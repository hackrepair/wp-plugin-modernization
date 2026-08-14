#!/usr/bin/env python3
# Copyright (C) 2026 Jim Walker
# SPDX-License-Identifier: GPL-2.0-or-later
"""Create a read-only local review report for a WordPress plugin folder or ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Iterable

from . import __version__


HEADER_FIELDS = ("Plugin Name", "Version", "Requires at least", "Requires PHP", "Text Domain")
MAX_ZIP_MEMBERS = 20_000
MAX_ZIP_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
EXCLUDED_DIRECTORY_NAMES = frozenset({
    ".claude", ".codex", ".git", ".hg", ".svn", "__pycache__", "node_modules", "vendor",
})
REQUEST_PATTERN = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\b")
WPDB_CALL_PATTERN = re.compile(r"\$wpdb\s*->\s*(?:query|get_(?:var|row|results|col))\s*\(")
OUTPUT_PATTERN = re.compile(r"\b(?:echo|print)\b")
RISKY_FUNCTION_PATTERN = re.compile(r"\b(?:eval|base64_decode|gzinflate|system|shell_exec|exec|passthru|proc_open)\s*\(")
UNSERIALIZE_PATTERN = re.compile(r"\bunserialize\s*\(")
NONCE_PATTERN = re.compile(r"\b(?:check_admin_referer|check_ajax_referer|wp_verify_nonce|wp_nonce_field)\s*\(")
CAPABILITY_PATTERN = re.compile(r"\b(?:current_user_can|user_can)\s*\(")
AUTHORIZATION_WRAPPER_PATTERN = re.compile(r"\b(?:assert|require)_[A-Za-z0-9_]*(?:access|capability|permission)[A-Za-z0-9_]*\s*\(")
UNSLASH_PATTERN = re.compile(r"\bwp_unslash\s*\(")
SANITIZER_PATTERN = re.compile(r"\b(?:absint|intval|map_deep|rest_sanitize_boolean|sanitize_[A-Za-z0-9_]+)\b")
ESCAPING_PATTERN = re.compile(r"\b(?:esc_html|esc_attr|esc_url|esc_js|esc_textarea|wp_kses(?:_post)?|wp_json_encode)\s*\(")
FUNCTION_PATTERN = re.compile(r"\bfunction\s*(?:&\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(")


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    confidence: str
    title: str
    path: str
    line: int
    note: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_directory(path: Path) -> str:
    """Create a reproducible fingerprint without changing the selected source."""
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if not item.is_file() or item.is_symlink():
            continue
        relative = item.relative_to(path).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with item.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def is_safe_zip_member(member: zipfile.ZipInfo) -> bool:
    normalized = member.filename.replace("\\", "/")
    name = PurePosixPath(normalized)
    unix_mode = member.external_attr >> 16
    return (
        "\x00" not in member.filename
        and not name.is_absolute()
        and ".." not in name.parts
        and not re.match(r"^[A-Za-z]:", normalized)
        and not stat.S_ISLNK(unix_mode)
    )


def extract_zip(archive: Path, target: Path) -> Path:
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise ValueError(f"ZIP contains too many entries ({len(members)} > {MAX_ZIP_MEMBERS}).")
        expanded_size = sum(item.file_size for item in members)
        if expanded_size > MAX_ZIP_UNCOMPRESSED_BYTES:
            raise ValueError("ZIP expands beyond the 1 GiB local review limit.")
        unsafe = [item.filename for item in members if not is_safe_zip_member(item)]
        if unsafe:
            raise ValueError(f"ZIP contains unsafe path(s): {', '.join(unsafe[:3])}")
        target.mkdir(parents=True, exist_ok=False)
        target_root = target.resolve()
        for member in members:
            normalized = PurePosixPath(member.filename.replace("\\", "/"))
            destination = target.joinpath(*normalized.parts)
            resolved_destination = destination.resolve()
            if not resolved_destination.is_relative_to(target_root):
                raise ValueError(f"ZIP member escapes the review directory: {member.filename}")
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)

    children = [item for item in target.iterdir() if item.name != "__MACOSX"]
    return children[0] if len(children) == 1 and children[0].is_dir() else target


def iter_php_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.php")):
        relative_parts = path.relative_to(root).parts
        if not path.is_symlink() and not any(part.lower() in EXCLUDED_DIRECTORY_NAMES for part in relative_parts):
            yield path


def parse_headers(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")[:8192]
    headers = {}
    for field in HEADER_FIELDS:
        match = re.search(rf"^\s*\*?\s*{re.escape(field)}:\s*(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)
        if match:
            headers[field] = match.group(1).strip()
    return headers


def lint_php(path: Path) -> tuple[bool | None, str]:
    php = shutil.which("php")
    if not php:
        return None, "PHP is not available locally; syntax was not checked."
    result = subprocess.run([php, "-l", str(path)], capture_output=True, text=True, check=False)
    if result.returncode == 0:
        return True, ""
    return False, (result.stdout + result.stderr).strip()


def php_runtime_version() -> str | None:
    php = shutil.which("php")
    if not php:
        return None
    result = subprocess.run([php, "-r", "echo PHP_VERSION;"], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else "available, version unknown"


def function_scopes(lines: list[str]) -> list[tuple[int, int]]:
    """Return approximate PHP function/method line ranges for local evidence checks."""
    scopes: list[tuple[int, int]] = []
    start = None
    depth = 0
    saw_open_brace = False
    for index, line in enumerate(lines):
        if start is None and FUNCTION_PATTERN.search(line):
            start = index
        if start is None:
            continue
        depth += line.count("{") - line.count("}")
        saw_open_brace = saw_open_brace or "{" in line
        if saw_open_brace and depth <= 0:
            scopes.append((start, index))
            start = None
            depth = 0
            saw_open_brace = False
    return scopes


def scope_for_line(line_index: int, lines: list[str], scopes: list[tuple[int, int]]) -> str:
    for start, end in scopes:
        if start <= line_index <= end:
            return "\n".join(lines[start:end + 1])
    return "\n".join(lines)


def is_dynamic_sql(query_arguments: str) -> bool:
    """Recognize only obvious dynamic query construction; do not flag static SQL."""
    return bool(re.search(r"(?:\.\s*\$|\$(?!wpdb\b)[A-Za-z_][A-Za-z0-9_]*|\{\$(?!wpdb\b)|sprintf\s*\()", query_arguments))


def has_constrained_unserialize(lines: list[str], line_index: int) -> bool:
    local_text = "\n".join(lines[line_index:min(len(lines), line_index + 5)])
    return "allowed_classes" in local_text and bool(re.search(r"\bis_(?:array|object)\s*\(", local_text))


def analyze_file(path: Path, root: Path) -> tuple[list[Finding], bool, bool]:
    findings: list[Finding] = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    text = "\n".join(lines)
    relative = str(path.relative_to(root))
    has_nonce = bool(NONCE_PATTERN.search(text))
    has_capability = bool(CAPABILITY_PATTERN.search(text))
    scopes = function_scopes(lines)

    for line_number, line in enumerate(lines, start=1):
        context = scope_for_line(line_number - 1, lines, scopes)
        if REQUEST_PATTERN.search(line):
            guarded = all((NONCE_PATTERN.search(context), (CAPABILITY_PATTERN.search(context) or AUTHORIZATION_WRAPPER_PATTERN.search(context)), UNSLASH_PATTERN.search(context), SANITIZER_PATTERN.search(context)))
            if guarded:
                findings.append(Finding("input", "info", "observed", "Request input has local controls", relative, line_number, "A capability check, nonce check, unslashing, and sanitizer occur in this function/method. Verify the data flow before treating it as safe."))
            else:
                findings.append(Finding("input", "review", "review", "Request input needs context review", relative, line_number, "Trace validation, unslashing, sanitization, authorization, and nonce pairing in the same entrypoint."))
        wpdb_call = WPDB_CALL_PATTERN.search(line)
        if wpdb_call and is_dynamic_sql(line[wpdb_call.end():]) and "$wpdb->prepare" not in line:
            findings.append(Finding("database", "review", "review", "Dynamic database query needs parameterization review", relative, line_number, "Confirm dynamic values reach this query through $wpdb->prepare(); leave table/column identifiers inline unless the WordPress version supports a safe identifier placeholder."))
        if OUTPUT_PATTERN.search(line) and "$" in line and not ESCAPING_PATTERN.search(line):
            prior_line = lines[line_number - 2] if line_number > 1 else ""
            if "phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped" in prior_line:
                findings.append(Finding("output", "info", "observed", "Documented unescaped output observed", relative, line_number, "The preceding PHPCS suppression documents this output path. Verify that the stated source remains valid."))
            else:
                findings.append(Finding("output", "review", "review", "Dynamic output needs escaping-context review", relative, line_number, "Review the output context and escaping. This cue alone is not an XSS finding."))
        if UNSERIALIZE_PATTERN.search(line):
            if has_constrained_unserialize(lines, line_number - 1):
                findings.append(Finding("deserialization", "info", "observed", "Constrained deserialization observed", relative, line_number, "The local call disables classes and follows with an array/object guard. Review provenance if untrusted data can reach it."))
            else:
                findings.append(Finding("dangerous-function", "review", "review", "Deserialization needs provenance review", relative, line_number, "Establish whether untrusted data can reach this call and avoid object construction."))
        elif RISKY_FUNCTION_PATTERN.search(line):
            findings.append(Finding("dangerous-function", "review", "review", "High-risk PHP function needs provenance review", relative, line_number, "Establish data provenance and intended use before judging this call."))
    return findings, has_nonce, has_capability


def markdown_report(report: dict) -> str:
    lines = [
        "# WP Plugin Modernization Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Analyzer: `{report['tool']['name']} {report['tool']['version']}`",
        f"Input: `{report['input']['name']}`",
        f"Input SHA-256: `{report['input']['sha256']}`",
        "",
        "## Scope and limits",
        "",
        "This is a local static review. Review cues are not confirmed vulnerabilities, and a completed scan is not a security, compatibility, or malware verdict.",
        "",
        "## Inventory",
        "",
        f"- PHP files scanned: {report['inventory']['php_files']}",
        f"- PHP lint: {report['inventory']['lint_summary']}",
        f"- PHP runtime: {report['checks']['php_lint']['runtime']}",
        f"- WordPress plugin headers found: {len(report['plugin_headers'])}",
        f"- Nonce markers: {report['markers']['nonce_files']}",
        f"- Capability markers: {report['markers']['capability_files']}",
        "",
        "## Actionable review cues",
        "",
    ]
    actionable = [finding for finding in report["findings"] if finding["severity"] != "info"]
    observations = [finding for finding in report["findings"] if finding["severity"] == "info"]
    if not actionable:
        lines.append("No configured review cues matched.")
    else:
        for finding in actionable:
            lines.append(f"- **{finding['title']}** — `{finding['path']}:{finding['line']}`. {finding['note']}")
    lines.extend(["", "## Mitigated observations", ""])
    if not observations:
        lines.append("No mitigated patterns were recorded.")
    else:
        for finding in observations:
            lines.append(f"- **{finding['title']}** — `{finding['path']}:{finding['line']}`. {finding['note']}")
    lines.extend(["", "## Next review steps", "", "1. Resolve PHP syntax failures before deeper analysis.", "2. Review each request-input and database cue along the full request/data flow.", "3. Confirm capability and nonce checks at the actual privileged entrypoint.", "4. Run staging smoke tests before installing a modified candidate.", ""])
    return "\n".join(lines)


def build_report(input_path: Path) -> dict:
    source_hash = sha256_file(input_path) if input_path.is_file() else sha256_directory(input_path)
    with tempfile.TemporaryDirectory(prefix="wp-plugin-modernization-") as temporary:
        workspace = Path(temporary)
        if input_path.is_file():
            if input_path.suffix.lower() != ".zip":
                raise ValueError("Input file must be a ZIP archive; use a directory for unpacked plugins.")
            root = extract_zip(input_path, workspace / "plugin")
        elif input_path.is_dir():
            root = input_path
        else:
            raise ValueError("Input does not exist.")

        php_files = list(iter_php_files(root))
        findings: list[Finding] = []
        headers: list[dict[str, object]] = []
        lint_failures: list[dict[str, str]] = []
        lint_unavailable = False
        nonce_files = 0
        capability_files = 0
        for php_file in php_files:
            ok, detail = lint_php(php_file)
            relative = str(php_file.relative_to(root))
            if ok is False:
                detail = detail.replace(str(php_file), relative)
                lint_failures.append({"path": relative, "detail": detail})
                findings.append(Finding("syntax", "high", "observed", "PHP syntax error", relative, 0, detail))
            elif ok is None:
                lint_unavailable = True

            file_headers = parse_headers(php_file)
            if "Plugin Name" in file_headers:
                headers.append({"path": relative, "headers": file_headers})
            file_findings, has_nonce, has_capability = analyze_file(php_file, root)
            findings.extend(file_findings)
            nonce_files += int(has_nonce)
            capability_files += int(has_capability)

    lint_summary = "unavailable" if lint_unavailable else f"{len(php_files) - len(lint_failures)} passed, {len(lint_failures)} failed"
    return {
        "schema_version": 3,
        "tool": {"name": "wp-plugin-modernization", "version": __version__},
        "generated_at": datetime.now(UTC).isoformat(),
        "input": {"name": input_path.name, "kind": "zip" if input_path.is_file() else "directory", "sha256": source_hash},
        "checks": {
            "php_lint": {
                "available": not lint_unavailable,
                "runtime": php_runtime_version() or "unavailable",
                "command": "php -l <relative-file>",
            },
        },
        "inventory": {"php_files": len(php_files), "lint_summary": lint_summary, "lint_failures": lint_failures, "excluded_directory_names": sorted(EXCLUDED_DIRECTORY_NAMES)},
        "plugin_headers": headers,
        "markers": {"nonce_files": nonce_files, "capability_files": capability_files},
        "findings": [asdict(item) for item in findings],
        "limitations": ["WPCS, PHPStan, PHP compatibility, WordPress.org metadata, and runtime testing are not part of this dependency-free foundation."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a read-only local WordPress plugin review report.")
    parser.add_argument("--version", action="version", version=f"wp-plugin-modernization {__version__}")
    parser.add_argument("input", help="Plugin directory or ZIP archive")
    parser.add_argument("--output", required=True, help="New, empty directory for the generated report")
    args = parser.parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()
    if output.exists():
        parser.error("--output must not already exist; prior reports are never overwritten.")
    if input_path == output or input_path in output.parents:
        parser.error("--output must be outside the input path.")
    try:
        report = build_report(input_path)
        output.mkdir(parents=True)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (output / "report.md").write_text(markdown_report(report), encoding="utf-8")
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
