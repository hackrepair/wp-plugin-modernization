# WP Plugin Modernization

## Project identity

| Field | Value |
| --- | --- |
| Product | WP Plugin Modernization |
| Author | Jim Walker, The Hack Repair Guy |
| Website | https://hackrepair.com/ |
| Repository | https://github.com/hackrepair/wp-plugin-modernization |
| License | GPL-2.0-or-later |
| Development status | Early development |
| Publication status | Public-ready locally; GitHub repository exists but publication is pending. |

## Purpose

WP Plugin Modernization is a local-only application for reviewing WordPress plugin folders and ZIP archives before they are changed, shipped, or installed. It produces evidence-led findings and reviewable modernization candidates; it does not certify a plugin as secure, compatible, or production-ready.

## Product boundary

- Run on the operator's machine against a selected plugin folder or ZIP.
- Keep the source input read-only. Extract ZIPs and create all reports/candidates in a new run directory.
- Start with deterministic local evidence: file inventory, PHP syntax, plugin metadata, and pattern-based review findings.
- Describe unavailable checks and unknown/custom/premium plugin metadata explicitly. Do not infer a failure or clean result.
- Make network lookups, staging execution, dependency installation, and code rewrites opt-in future capabilities.
- Never access a live WordPress site, Docker container, or browser session as part of a normal scan.

## Non-goals for v0.1

- Replacing Wordfence, Site Cleaner, or a runtime malware/integrity scanner.
- Automatic edits to a plugin.
- A security guarantee, a compatibility guarantee, or a malware verdict.
- Uploading source, telemetry, licensing, or account-based features.

## Users and decisions supported

| User question | Evidence supplied |
| --- | --- |
| Can this plugin parse under the local PHP runtime? | Per-file `php -l` result and tool availability. |
| Is this recognizably a WordPress plugin? | Header fields, entry-file candidates, and declared requirements. |
| What deserves a code review first? | File/line findings for direct input, database calls, output, nonce/capability markers, and risky functions. |
| Can I safely modernize it? | A staged follow-up checklist; no automatic recommendation to deploy. |

## Architecture

1. **Core analyzer**: a dependency-free Python CLI that accepts a folder or ZIP, copies/extracts it into an isolated run folder, inventories PHP files, runs safe local checks, and writes JSON plus Markdown.
2. **Local interface**: a later thin localhost UI over the same core output. It must never make live-site calls by default.
3. **Optional adapters**: WPCS, PHPStan, PHP compatibility, WordPress.org metadata, and staging smoke tests. Each reports availability and command/result provenance.

## Evidence model

Every finding has a category, severity, confidence, source path, line when available, and a human review note.

- **Observed**: direct local evidence, such as a PHP lint error or a `$wpdb` call.
- **Review cue**: a pattern that needs context, such as an `echo` or `$_POST` reference.
- **Unavailable**: a desired check could not run because its local tool or required input was absent.

The app must never promote a review cue into a confirmed vulnerability without additional evidence.

## Implementation status

### Completed foundation

- Read-only folder and ZIP input with SHA-256 input fingerprinting.
- ZIP path-traversal rejection and mandatory new output directories.
- First-party PHP inventory with PHP syntax checks when available.
- JSON schema version 2 plus a human-readable Markdown report.
- Separate actionable review cues and mitigated observations.
- Context recognition for capability/authorization wrappers, nonces, unslashing, sanitizers, escaping, prepared SQL patterns, constrained deserialization, and documented output exceptions.
- Exclusions for `.claude`, `.codex`, `.git`, `.hg`, `.svn`, `vendor`, `node_modules`, and bytecode/cache directories.
- Seven fixture tests covering the source-preservation and classification boundaries above.
- Real scan against THRG WP Site Cleaner: 22 first-party PHP files, 18 actionable review cues, and 39 mitigated observations after noise reduction. This is validation of report behavior, not a security verdict on the plugin.

## Roadmap

### M0 - Foundation (complete)

- [x] Define product boundary and report schema.
- [x] Implement isolated folder/ZIP intake and a read-only local report.
- [x] Add fixture-based tests for folder, ZIP, unsafe paths, non-overwrite behavior, and contextual classification.

### M1 - Static analysis adapters (next)

- [ ] Detect and run locally installed WPCS/PHPCS, PHPStan, and PHP compatibility tooling without installing anything automatically.
- [ ] Normalize adapter results into the evidence model with tool version and command provenance.
- [ ] Add severity, confidence, category, and path filters.
- [ ] Add a self-contained HTML report while retaining JSON and Markdown.

### M2 - Reviewed modernization candidates

- [ ] Generate a separate candidate copy only after explicit user selection.
- [ ] Limit default transformations to low-risk mechanical changes.
- [ ] Require diff review, syntax checks, and staging smoke-test acknowledgement before handoff.

### M3 - Local UI and exports

- [ ] Add a localhost UI for selecting inputs and reading reports.
- [ ] Keep JSON and Markdown as stable, scriptable artifacts.
- [ ] Provide an offline export bundle with no source uploads.

## Public repository checklist

- [x] Public-facing README with honest scope, privacy, usage, development, and Jim Walker attribution.
- [x] Project status and implementation roadmap reconciled with the code.
- [x] Contribution and private security-reporting guidance.
- [x] GPL-2.0-or-later license file.
- [ ] Add repository description, homepage, and topics on GitHub.
- [ ] Make the GitHub repository public when Jim approves publication.
- [ ] Create the initial commit and push `main`.
- [ ] Verify the rendered GitHub README and repository links.

## Definition of done for a release

- Input source remains byte-identical after every supported scan.
- ZIP extraction rejects traversal paths and preserves the original archive.
- Reports state tool availability and scan limitations.
- Tests cover the no-write guarantee and malformed inputs.
- Lint, unit tests, `git diff --check`, and a manual local UI run pass.
- Packaged artifacts are verified before release and existing versioned archives are retained.
