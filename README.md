<h1 align="center">WP Plugin Modernization</h1>

<p align="center">
  Local WordPress plugin review, without uploading your source code.
</p>

<p align="center">
  <a href="https://github.com/hackrepair/wp-plugin-modernization"><img alt="Development status" src="https://img.shields.io/badge/status-early%20development-f4931e?style=for-the-badge"></a>
  <img alt="Python 3.11 or newer" src="https://img.shields.io/badge/python-3.11%2B-3776ab?style=for-the-badge">
  <a href="LICENSE"><img alt="GPL-2.0-or-later license" src="https://img.shields.io/badge/license-GPL--2.0--or--later-222222?style=for-the-badge"></a>
</p>

---

## Review WordPress Plugin Code Without False Certainty

WP Plugin Modernization is a local, read-only review tool for WordPress plugin folders and ZIP archives. It inventories PHP files, checks PHP syntax when a local PHP runtime is available, and produces focused review cues for request input, database access, output handling, and higher-risk PHP functions.

The application separates actionable review cues from mitigated observations. It does not call a plugin secure, compatible, malware-free, or ready for production based on pattern matching alone.

Developed by [Jim Walker, The Hack Repair Guy](https://hackrepair.com/), this project applies an evidence-first WordPress repair mindset to plugin code review: show what was observed, explain the limits, and keep final decisions in human hands.

## What It Does Today

| Capability | Why It Matters |
| --- | --- |
| Local folder and ZIP intake | Review custom, premium, archived, or public plugins without uploading source. |
| Read-only source handling | Reports are written to a new output directory; the selected plugin is not modified. |
| Safe ZIP extraction | Archive paths are checked before extraction to reject path traversal. |
| PHP syntax checks | Every first-party PHP file is checked with `php -l` when PHP is available. |
| Context-aware review cues | Request input, output, deserialization, and dynamic database patterns are interpreted with nearby controls. |
| Mitigation recognition | Nonces, capability wrappers, sanitization, escaping, constrained deserialization, and documented exceptions reduce noise. |
| JSON and Markdown reports | Keep a machine-readable artifact and a practical human review report from the same scan. |
| Tooling exclusions | `.git`, `.claude`, `.codex`, `vendor`, `node_modules`, and similar non-plugin trees are skipped. |

## Requirements

- Python 3.11 or newer
- PHP available on `PATH` for syntax checks

The foundation analyzer has no third-party Python dependencies.

## Quick Start

```sh
git clone https://github.com/hackrepair/wp-plugin-modernization.git
cd wp-plugin-modernization

python3 app/analyze_plugin.py /path/to/plugin-or-plugin.zip \
  --output /path/to/new-report-directory
```

The output directory must not already exist. A successful run creates:

```text
new-report-directory/
├── report.json
└── report.md
```

## Understanding the Report

**Actionable review cues** identify code that still needs contextual review. A cue is not proof of a vulnerability.

**Mitigated observations** record patterns where nearby controls were detected, such as capability and nonce checks, appropriate escaping, or `unserialize()` with object construction disabled and a type guard.

**Unavailable checks** explain when evidence could not be collected, for example when PHP is not installed locally.

## Honest Scope

WP Plugin Modernization is not a malware scanner, runtime debugger, penetration test, WordPress integrity checker, or automatic code-rewriting service.

The current foundation does not run WPCS, PHPStan, PHP compatibility rules, WordPress Plugin Check, live-site tests, or staging activation tests. These are planned as explicit adapters, with availability and provenance recorded in the report.

Do not deploy changes solely because a report is quiet. Mature plugins still require code review, staging activation, representative workflow tests, and production-specific judgment.

## Privacy

Plugin source remains on the local machine. The foundation analyzer does not upload files, send telemetry, require an account, contact a private scanning service, or access a WordPress site.

Future network-backed adapters must remain opt-in and disclose exactly what data leaves the machine.

## Development

Run the test suite:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Current coverage includes source preservation, folder and ZIP intake, unsafe ZIP rejection, non-overwriting reports, embedded-worktree exclusion, guarded-input recognition, constrained deserialization, structured WordPress database calls, and documented stream output.

See [PROJECT.md](PROJECT.md) for the evidence model, architecture, implementation status, roadmap, and release requirements.

## Contributing and Security Reports

Contributions are welcome while the project is taking shape. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

For a vulnerability in WP Plugin Modernization itself, follow [SECURITY.md](SECURITY.md). Do not attach private or customer plugin source to a public issue.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

## Credits

Developed by [Jim Walker, The Hack Repair Guy](https://hackrepair.com/).

Repository: [hackrepair/wp-plugin-modernization](https://github.com/hackrepair/wp-plugin-modernization)
