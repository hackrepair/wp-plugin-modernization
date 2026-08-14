# Contributing to WP Plugin Modernization

Thank you for helping improve WP Plugin Modernization.

## Before opening a change

- Keep scanning local and read-only by default.
- Treat pattern matches as review evidence, not confirmed vulnerabilities.
- Preserve unavailable and partial checks explicitly.
- Do not add source uploads, telemetry, live-site access, dependency installation, or code rewriting without an approved project milestone.
- Never include customer, premium, private, or otherwise non-public plugin source in an issue, fixture, commit, or pull request.

## Development workflow

1. Create a focused branch.
2. Create a virtual environment and install the package in editable mode:

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --editable .
   ```

3. Add or update fixture tests for classification or input-handling changes.
4. Run:

   ```sh
   PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
   git diff --check
   ```

5. Verify the installed interface with `wp-plugin-modernization --version` and `wp-plugin-modernization --help`.
6. Describe the evidence boundary, false-positive tradeoffs, and validation performed in the pull request.

Small, reviewable changes are preferred. A lower finding count is not automatically an improvement; changes should make the report more accurate and more useful without hiding meaningful uncertainty.

## Bug reports and feature requests

Open a GitHub issue with a minimal synthetic example whenever possible. Remove credentials, personal data, customer information, proprietary source, and real filesystem paths.

Security issues in this application should follow [SECURITY.md](SECURITY.md), not a public issue.

By contributing, you agree that your contribution is licensed under GPL-2.0-or-later.
