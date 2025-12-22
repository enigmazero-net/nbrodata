# nbrodata

## Local run
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/nbro_fetch.py fetch --har har/nbro.har --out data/latest.json
```

## VS Code
Use the task `NBRO: Fetch latest data (HAR)` from the Command Palette (Run Task).
