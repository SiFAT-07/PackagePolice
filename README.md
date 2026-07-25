# PackagePolice

Repository scaffold for PackagePolice — a safe collector and triage system

Usage (from the repo root):

```bash
python3 scripts/safe_collect.py requests flask some-suspicious-package
```

This project intentionally avoids fetching or executing package code; it
only scores package names with heuristic signals and stores metadata locally.

See `requirements.txt` for runtime dependencies.
