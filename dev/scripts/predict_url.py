# predict_url.py
import argparse, sys
import joblib, numpy as np, pandas as pd
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from dev.scripts.extract_features import extract_features

def load_artifact(pkl):
    obj = joblib.load(pkl)
    if isinstance(obj, dict) and "model" in obj:
        return obj["model"], obj.get("feature_columns"), obj.get("imputer")
    return obj, None, None  # fallback: bare estimator

def enforce_schema(feat_dict, feature_columns):
    df = pd.DataFrame([feat_dict]).apply(pd.to_numeric, errors="coerce")
    if feature_columns:
        for c in feature_columns:
            if c not in df.columns: df[c] = np.nan
        df = df[feature_columns]
    return df

def predict_one(url, model_path, threshold=0.5):
    model, cols, imputer = load_artifact(model_path)
    X = enforce_schema(extract_features(url), cols)
    Xv = imputer.transform(X) if imputer is not None else X.fillna(0).values
    pred = int(model.predict(Xv)[0])
    prob = float(model.predict_proba(Xv)[0,1]) if hasattr(model,"predict_proba") else (1.0 if pred==1 else 0.0)
    label = "Phishing" if prob >= threshold else "Legitimate"
    return label, prob

def threshold_level(thr: float) -> str:
    if thr < 0.30: return "Very low"
    if thr < 0.50: return "Low"
    if thr < 0.60: return "Medium"
    if thr < 0.80: return "High"
    return "Very high"

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Predict phishing for one URL")
    ap.add_argument("-u","--url", required=False)
    ap.add_argument("-m","--model", default="phishing_model.pkl")
    ap.add_argument("-t","--threshold", type=float, default=0.5)
    a = ap.parse_args()
    url = a.url or input("Enter URL: ").strip()
    try:
        label, prob = predict_one(url, a.model, a.threshold)
        lvl = threshold_level(a.threshold)
        print(f"\nThreshold: {a.threshold:.2f} ({lvl})")
        print(f"Result: {label} (phishing prob: {prob:.3f})")
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr); sys.exit(1)
