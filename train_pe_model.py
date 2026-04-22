import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

from pe_features import DEFAULT_FEATURES, extract_pe_features, features_to_vector


def load_manifest(manifest_path: Path):
    df = pd.read_csv(manifest_path)
    if "path" not in df.columns or "label" not in df.columns:
        raise ValueError("Manifest must contain 'path' and 'label' columns.")
    return df


def build_feature_rows(df, base_dir: Path):
    rows = []
    labels = []
    for _, row in df.iterrows():
        file_path = base_dir / row["path"]
        label = int(row["label"])
        if not file_path.exists():
            continue
        with open(file_path, "rb") as f:
            analysis = extract_pe_features(f.read())
        rows.append(analysis.features)
        labels.append(label)
    return rows, labels


def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    base_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    base_model.fit(X_train, y_train)

    calibrated = CalibratedClassifierCV(base_model, method="isotonic", cv=3)
    calibrated.fit(X_train, y_train)

    y_proba = calibrated.predict_proba(X_test)[:, 1]
    y_pred = calibrated.predict(X_test)

    report = {
        "roc_auc": roc_auc_score(y_test, y_proba),
        "pr_auc": average_precision_score(y_test, y_proba),
        "classification_report": classification_report(y_test, y_pred, output_dict=True),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    return calibrated, report


def train_from_feature_csv(csv_path: Path):
    df = pd.read_csv(csv_path)
    if "legitimate" not in df.columns:
        raise ValueError("Feature CSV must contain 'legitimate' column.")

    feature_order = [c for c in DEFAULT_FEATURES if c in df.columns]
    if not feature_order:
        raise ValueError("No matching feature columns found in CSV.")

    X = df[feature_order].values.tolist()
    # Convert to malicious=1, benign=0
    y = (1 - df["legitimate"].astype(int)).tolist()
    return X, y, feature_order


def main():
    parser = argparse.ArgumentParser(description="Train PE malware detector.")
    parser.add_argument("--manifest", help="CSV with path,label columns")
    parser.add_argument(
        "--features-csv",
        help="CSV with PE feature columns and 'legitimate' label column",
    )
    parser.add_argument("--base-dir", default=".", help="Base directory for manifest paths")
    parser.add_argument("--out-dir", default="artifacts", help="Output directory")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.features_csv:
        X, labels, feature_order = train_from_feature_csv(Path(args.features_csv))
    else:
        if not args.manifest:
            raise ValueError("Provide either --manifest or --features-csv.")
        manifest = Path(args.manifest)
        base_dir = Path(args.base_dir)
        df = load_manifest(manifest)
        rows, labels = build_feature_rows(df, base_dir)
        if not rows:
            raise RuntimeError("No feature rows created. Check manifest paths.")
        feature_order = DEFAULT_FEATURES
        X = [features_to_vector(r, feature_order) for r in rows]

    model, report = train_model(X, labels)

    joblib.dump(model, out_dir / "model.joblib")
    with open(out_dir / "feature_schema.json", "w", encoding="utf-8") as f:
        json.dump({"features": feature_order}, f, indent=2)
    with open(out_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("Model saved to:", out_dir / "model.joblib")


if __name__ == "__main__":
    main()
