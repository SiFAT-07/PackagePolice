# PackagePolice Safe Sandbox

This workspace is set up for download-only package collection.

## Safety rule

Never run `npm install`, `pip install`, `python setup.py install`, `import`, `exec`, or `eval` on package contents. The collector only downloads archives and reads files as plain text.

## Current layout

- `scripts/` contains the safe collector.
- `quarantine/` stores raw archives and extracted source trees.
- `dataset/dataset.csv` stores the extracted features.
- `packages_to_collect.csv` stores the package list.
- Malicious npm samples are pulled from the public DataDog dataset repo, not the live registry.

## Run

```bash
cd /home/sifat/packagepolice/scripts
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export GITHUB_TOKEN=your_token_here
python3 safe_collect.py --list ../packages_to_collect.csv --workspace-root /home/sifat/packagepolice
```

## Output

- Raw downloads stay in `quarantine/`.
- Errors are appended to `logs/safe_collect_errors.log`.
- Rows are appended to `dataset/dataset.csv` as each package finishes.