# CyberShied Malware Analysis Upgrade for Real‑World EXE Detection

**Project Path:** `/home/infsec1/Desktop/codex/CyberShied`

## Summary
- Replace the 7‑feature PE header model with a richer PE feature extractor and retrain on a public dataset to improve real‑world generalization.
- Add a hybrid signal layer (simple heuristics + ML probabilities) and calibrated scoring for clearer, more trustworthy results.
- Improve the malware analysis UX to show confidence, key flags, and transparent errors.

## Public APIs/Interfaces
- No route changes. `POST /malware_analysis` remains the same.
- Response UI gains new fields: `confidence`, `risk_level`, and `signals` list (non‑breaking additions).

## Key Changes
- Data + training pipeline
  - Add a training script that ingests open PE datasets (e.g., EMBER or similar), enforces a clean train/val/test split, and outputs a versioned model artifact with feature schema metadata.
  - Evaluate with ROC‑AUC, PR‑AUC, F1, and confusion matrix; record metrics in a simple report file.
- Feature extraction
  - Implement a dedicated PE feature extractor with richer signals: sections count/sizes, entropy stats, import counts, export presence, TLS presence, debug/relo info, timestamp age, string counts, and optional imphash.
  - Validate PE structure robustly and reject malformed files early with clear errors.
- Modeling
  - Train multiple models (RandomForest + XGBoost) and select the best based on validation PR‑AUC and balanced error.
  - Calibrate probabilities (Platt/Isotonic) and define a risk‑level mapping for UI (Low/Med/High).
- Hybrid signals
  - Add lightweight heuristics (e.g., high section entropy + suspicious imports) that contribute to a “signals” list shown to users alongside ML score.
- Runtime + UX
  - Load the trained model once at startup, not on every request.
  - Update `templates/malware_analysis.html` to show summary, confidence, and key signals in a compact result card with a collapsible JSON detail panel.
  - Add file size limits and ensure only valid PE executables are processed in `app.py`.

## Test Plan
- Unit tests for feature extractor on:
  - Valid PE with expected fields.
  - Corrupted/invalid PE.
  - Edge cases (no imports, zero sections, unusual headers).
- Integration tests for `/malware_analysis`:
  - Valid EXE → returns summary + confidence.
  - Non‑EXE and invalid PE → returns clean error state.
- Model evaluation run with metrics report captured and reviewed.

## Assumptions
- You want “do all of the above,” meaning feature expansion, hybrid signals, and a model swap/selection step.
- Open datasets can be downloaded and used for training.
- Balanced performance is preferred over prioritizing only false negatives or false positives.
