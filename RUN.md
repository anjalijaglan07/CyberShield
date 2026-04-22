# Run Instructions

## 1. Go to the Project Folder

```bash
cd /home/infsec1/Desktop/codex/CyberShied
```

## 2. Create and Activate a Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install Requirements

```bash
pip install -r requirements.txt
```

## 4. Configure VirusTotal (Optional)

Create a `.env` file and add your API key:

```bash
echo "VIRUSTOTAL_API_KEY=YOUR_KEY" > .env
```

## 5. Ensure Malware Model Artifacts Are Available

The malware analysis endpoint expects:

```
artifacts/model.joblib
artifacts/feature_schema.json
```

If you don’t have these yet, train a model using a manifest CSV:

```bash
python3 train_pe_model.py --manifest /path/to/manifest.csv --base-dir /path/to/samples --out-dir artifacts
```

The manifest CSV must contain `path` and `label` columns, where `label` is `1` for malware and `0` for benign.

## 6. Run the Application

```bash
python3 app.py
```

Then open:
`http://localhost:5000`
