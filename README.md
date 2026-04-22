# CyberShied ( https://cybershied.onrender.com )👈 👈 Click For Demo.
A web-based AI-powered malware detection system integrating PE header analysis for .exe files, URL threat checks, file hash lookups, and extension verification. Designed for fast, reliable detection to support cybersecurity analysis and threat mitigation.


# 🔒 Advanced Malware Detection System

A web-based AI-powered malware detection platform that integrates multiple analysis techniques to identify malicious files and URLs. Built for cybersecurity enthusiasts, students, and analysts, this system enables intelligent threat detection through an interactive and unified interface.

---

## 🚀 Features

- **PE Header-Based `.exe` File Analysis**  
  Detects malicious Windows executable files using machine learning on PE header features.

- **URL Safety Checker**  
  Analyzes URLs for phishing, malware, or suspicious behavior using trained models and threat intelligence.

- **File Hash Analysis**  
  Checks file hashes against known malware databases (like VirusTotal).

- **File Extension Verification**  
  Identifies spoofed or mismatched file extensions to catch hidden threats.

---

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript  
- **Backend:** Python, Flask  
- **Machine Learning:** Scikit-learn, XGBoost  
- **Libraries/Tools:** PEfile, hashlib, requests, joblib

---

## 📦 Installation & Usage

### 1. Go to the Project Folder

```bash
cd /home/infsec1/Desktop/codex/CyberShied
```

### 2. Create and Activate a Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Requirements

```bash
pip install -r requirements.txt
```

### 4. Configure VirusTotal (Optional)

Create a `.env` file and add your API key:

```bash
echo "VIRUSTOTAL_API_KEY=YOUR_KEY" > .env
```

### 5. Ensure Malware Model Artifacts Are Available

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

### 6. Run the Application

```bash
python3 app.py
```

Then open:
`http://localhost:5000`

---

## 📁 Project Structure

```
Advanced-Malware-Detection-System/
│
├── app/                    # Backend logic & ML code
│   ├── main.py
│   ├── model.pkl
│   └── ...
├── frontend/               # HTML/CSS/JS files
├── static/
├── templates/
├── utils/                  # Helper scripts
├── dataset/                # Sample data (if any)
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 📄 Project Report

feel free to contact me via email.(anjalijaglan07@gmail.com)

---

## ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**. Do not use it in production or for malicious activities.

---

## 📬 Contact

For questions or collaborations, feel free to contact me via GitHub or email.

---
