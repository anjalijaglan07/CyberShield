from flask import Flask, render_template, request
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import urlparse
import zipfile

import joblib
import pefile
import requests
from dotenv import load_dotenv

from pe_features import DEFAULT_FEATURES, extract_pe_features, features_to_vector
load_dotenv()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB

# Replace with your actual VirusTotal API key in .env
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
MALICIOUS_LABEL = int(os.getenv("MALICIOUS_LABEL", "1"))

ARTIFACTS_DIR = Path(__file__).parent / "artifacts"
MODEL_PATH = ARTIFACTS_DIR / "model.joblib"
SCHEMA_PATH = ARTIFACTS_DIR / "feature_schema.json"


def load_model_and_schema():
    model = None
    features = DEFAULT_FEATURES
    if MODEL_PATH.exists():
        model = joblib.load(MODEL_PATH)
    if SCHEMA_PATH.exists():
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            features = data.get("features", features)
    return model, features


MODEL, FEATURE_ORDER = load_model_and_schema()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")



@app.route("/malware_analysis", methods=["GET", "POST"])
def malware_analysis():
    summary = None
    detailed = None
    confidence = None
    risk_level = None
    signals = None
    if request.method == "POST":
        # Ensure the file is uploaded via an input with the name "file"
        if "file" in request.files:
            file = request.files["file"]
            filename = file.filename

            # Proceed only if the file is an EXE
            if filename.lower().endswith(".exe"):
                try:
                    if MODEL is None:
                        summary = "Model not available"
                        detailed = {"error": "Model artifact not found. Train and save artifacts/model.joblib."}
                        return render_template(
                            "malware_analysis.html",
                            summary=summary,
                            detailed=detailed,
                            confidence=confidence,
                            risk_level=risk_level,
                            signals=signals,
                        )

                    # Reset the file pointer and read content for PE parsing
                    file.seek(0)
                    file_bytes = file.read()
                    pe_analysis = extract_pe_features(file_bytes)
                    feature_vector = features_to_vector(pe_analysis.features, FEATURE_ORDER)

                    proba = None
                    if hasattr(MODEL, "predict_proba"):
                        proba_all = MODEL.predict_proba([feature_vector])[0]
                        if hasattr(MODEL, "classes_") and MALICIOUS_LABEL in MODEL.classes_:
                            idx = list(MODEL.classes_).index(MALICIOUS_LABEL)
                            proba = float(proba_all[idx])
                        else:
                            proba = float(proba_all[1]) if len(proba_all) > 1 else float(proba_all[0])
                        confidence = round(proba * 100, 2)
                    else:
                        confidence = None

                    prediction = MODEL.predict([feature_vector])[0]

                    if proba is not None:
                        if proba >= 0.7:
                            risk_level = "High"
                        elif proba >= 0.3:
                            risk_level = "Medium"
                        else:
                            risk_level = "Low"
                    else:
                        risk_level = "Unknown"

                    signals = pe_analysis.signals
                    detailed = {
                        "file_type": "exe",
                        "file": filename,
                        "features": pe_analysis.features,
                        "imphash": pe_analysis.imphash,
                        "prediction": int(prediction),
                        "confidence": confidence,
                        "risk_level": risk_level,
                        "signals": signals,
                    }

                    summary = "File is malicious" if int(prediction) == MALICIOUS_LABEL else "File is safe"
                
                except pefile.PEFormatError as e:
                    detailed = {"error": str(e)}
                    summary = "Invalid or corrupted PE file"
                except Exception as e:
                    detailed = {"error": str(e)}
                    summary = "Error during PE analysis"
            else:
                summary = "The uploaded file is not an EXE."
    
    return render_template(
        "malware_analysis.html",
        summary=summary,
        detailed=detailed,
        confidence=confidence,
        risk_level=risk_level,
        signals=signals,
    )

@app.route("/url_detection", methods=["GET", "POST"])
def url_detection():
    summary = None
    detailed = None
    if request.method == "POST":
        if "url" in request.form:
            url = request.form["url"].strip()
            headers = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}
            try:
                parsed = urlparse(url)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    detailed = {"safe": None, "error": "Invalid URL. Use http(s)://host/path."}
                elif not VIRUSTOTAL_API_KEY:
                    detailed = {"safe": None, "error": "VirusTotal API key missing."}
                else:
                    # Submit the URL for scanning
                    url_scan = requests.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url},
                        timeout=10,
                    )
                    vt_response = url_scan.json() if url_scan.status_code == 200 else None
                    if vt_response and vt_response.get("data", {}).get("id"):
                        analysis_id = vt_response["data"]["id"]
                        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        analysis_data = None
                        status = None
                        for _ in range(5):
                            analysis_response = requests.get(analysis_url, headers=headers, timeout=10)
                            analysis_data = (
                                analysis_response.json() if analysis_response.status_code == 200 else None
                            )
                            status = (
                                analysis_data.get("data", {})
                                .get("attributes", {})
                                .get("status")
                                if analysis_data
                                else None
                            )
                            if status == "completed":
                                break
                            time.sleep(1)
                        if status == "completed" and analysis_data:
                            malicious = (
                                analysis_data.get("data", {})
                                .get("attributes", {})
                                .get("stats", {})
                                .get("malicious", 0)
                            )
                            is_safe = malicious == 0
                            detailed = {
                                "safe": is_safe,
                                "status": status,
                                "virustotal_report": analysis_data,
                            }
                        else:
                            detailed = {
                                "safe": None,
                                "status": status or "pending",
                                "virustotal_report": analysis_data or vt_response,
                            }
                    else:
                        detailed = {"safe": None, "virustotal_report": vt_response}
            except requests.exceptions.RequestException as e:
                detailed = {"safe": False, "error": str(e)}
            
            if detailed.get("safe") is True:
                summary = "URL is safe"
            elif detailed.get("safe") is False:
                summary = "URL is not safe"
            else:
                if detailed.get("error"):
                    summary = "URL scan error"
                elif detailed.get("status") in {"pending", "queued"}:
                    summary = "URL scan pending"
                else:
                    summary = "URL scan result unavailable"
    return render_template("url_detection.html", summary=summary, detailed=detailed)

@app.route("/hash_file", methods=["GET", "POST"])
def hash_file():
    summary = None
    detailed = None
    if request.method == "POST":
        if "file" in request.files:
            file = request.files["file"]
            file_hash = calculate_hash(file)
            headers = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}
            try:
                vt_report = None
                if VIRUSTOTAL_API_KEY:
                    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                    response = requests.get(vt_url, headers=headers, timeout=10)
                    vt_report = response.json() if response.status_code == 200 else None
                detailed = {"hash": file_hash, "virustotal_report": vt_report}
            except requests.exceptions.RequestException as e:
                detailed = {"hash": file_hash, "error": str(e)}
            summary = f"File hash is: {file_hash}"
    return render_template("hash_file.html", summary=summary, detailed=detailed)

@app.route("/extension_validation", methods=["GET", "POST"])
def extension_validation():
    summary = None
    detailed = None
    if request.method == "POST":
        if "file_ext" in request.files:
            file = request.files["file_ext"]
            original_filename = file.filename
            file_extension = os.path.splitext(original_filename)[1].lower().lstrip(".")
            detected_type = detect_file_type(file)
            if detected_type is None:
                detailed = {
                    "is_valid": None,
                    "detected_type": None,
                    "extension": file_extension or None,
                }
                summary = "Extension unknown"
            else:
                is_valid = detected_type == file_extension
                detailed = {
                    "is_valid": is_valid,
                    "detected_type": detected_type,
                    "extension": file_extension or None,
                }
                summary = "Extension is valid" if is_valid else "Extension is not valid"
    return render_template("extension_validation.html", summary=summary, detailed=detailed)

def calculate_hash(file):
    hasher = hashlib.sha256()
    file.seek(0)
    while True:
        chunk = file.read(4096)
        if not chunk:
            break
        hasher.update(chunk)
    file.seek(0)
    return hasher.hexdigest()

def detect_file_type(file):
    file.seek(0)
    header = file.read(16)
    file.seek(0)
    signatures = [
        (b"MZ", "exe"),
        (b"%PDF-", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpg"),
        (b"GIF87a", "gif"),
        (b"GIF89a", "gif"),
        (b"\x1f\x8b\x08", "gz"),
        (b"Rar!\x1a\x07\x00", "rar"),
        (b"OggS", "ogg"),
        (b"ID3", "mp3"),
        (b"\x00\x00\x00\x18ftyp", "mp4"),
        (b"\x00\x00\x00\x14ftyp", "mp4"),
    ]
    for sig, ext in signatures:
        if header.startswith(sig):
            return ext
    if header.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(file) as zf:
                names = zf.namelist()
            if any(name.startswith("word/") for name in names):
                return "docx"
            if any(name.startswith("xl/") for name in names):
                return "xlsx"
            if any(name.startswith("ppt/") for name in names):
                return "pptx"
        except Exception:
            pass
        finally:
            file.seek(0)
        return "zip"
    return None

if __name__ == "__main__":
    app.run(debug=True, host="192.168.119.113", port=6789)
