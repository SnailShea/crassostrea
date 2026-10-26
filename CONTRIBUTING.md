# Contributing to Crassostrea

Thank you for improving Crassostrea. The developer documentation (design,
development environment, tests) is in the separate documentation project
(`crassostrea-docs`, section "Developer guide"); please read it before larger
changes.

## Pull requests

1. Base your branch on the current development branch and name it after the
   kind and content of the change, e.g. `fix/digest-links` or
   `feat/api-recipients`.
2. Keep a pull request to one topic. Describe what changes for users and
   administrators, and how you tested it.
3. Run the tests before you submit:
   - web interface and API: `cd data/web && python -m pytest`
   - shell scripts: `bash -n` on the changed scripts, and a dry-run render
     (`SF_DRYRUN=y SF_ROOT=... system/configure.sh`) for configuration changes
   - cluster changes: the system tests in `tests/system/`
4. Changes to the web UI or the API go through the service layer
   (`data/web/crassostrea/services/`), so both enforce the same rules; new API
   routes must be documented in `api/spec.py` (a test checks this).
5. A single gateway (empty `HA_NODES`) must render exactly as before unless
   the change is meant for it.

## Issues

- Use the issue tracker for bugs and feature requests, not for support
  questions.
- Include the version (git commit), the EL10 distribution, whether the gateway
  is part of a cluster, and the relevant logs (`journalctl -u <unit>`).
  Remove passwords, keys and personal data from logs first.
- Report security problems privately, see [SECURITY.md](SECURITY.md).
