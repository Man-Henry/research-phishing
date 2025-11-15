# train_model.py
import argparse, glob, os, sys
import joblib, numpy as np, pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score
from sklearn.ensemble import RandomForestClassifier

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from src.utils.schema import FEATURE_COLUMNS, NON_NUMERIC_COLUMNS, normalize_labels, resolve_label_column

def load_dataset(path=None):
    cands = []
    if path: cands.append(path)
    if os.environ.get("TRAIN_DATA_PATH"): cands.append(os.environ["TRAIN_DATA_PATH"])
    cands += ["dataset_full.csv","url_features.csv","PhiUSIIL_Phishing_URL_Dataset.csv"]
    for f in glob.glob("*.csv"):
        if "phish" in f.lower() and f not in cands: cands.insert(0, f)
    for p in cands:
        if p and os.path.exists(p):
            df = pd.read_csv(p)
            print(f"Loaded {p}, shape={df.shape}")
            return df
    raise FileNotFoundError("Không tìm thấy CSV. Truyền --data hoặc đặt TRAIN_DATA_PATH.")

def prepare_X_y(df: pd.DataFrame):
    # chuẩn hoá cột nhãn -> Label
    label_col = "Label" if "Label" in df.columns else resolve_label_column(df)
    if label_col != "Label":
        df = df.rename(columns={label_col:"Label"})

    # nếu Label là chuỗi, chuẩn hoá 0/1
    if not np.issubdtype(df["Label"].dtype, np.number):
        df["Label"] = normalize_labels(df["Label"])

    # chỉ giữ những feature numeric có trong file (theo schema)
    present = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"Thiếu {len(missing)} cột (sẽ được thêm khi suy luận): {', '.join(missing[:12])}{' ...' if len(missing)>12 else ''}")

    X = df[present].apply(pd.to_numeric, errors="coerce")
    y = df["Label"].astype(int)

    print("\nLabel counts:\n", y.value_counts().sort_index())
    print("\nFeature snapshot:\n", X.describe().T[['mean','std','min','max']].round(3).head(10))
    return X, y, present

def train_and_save(X, y, features, out_path):
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    imputer = SimpleImputer(strategy="median")
    X_tr_imp = imputer.fit_transform(X_tr)
    X_te_imp = imputer.transform(X_te)

    model = RandomForestClassifier(
        n_estimators=500, max_depth=30, min_samples_split=10, min_samples_leaf=5,
        max_features='sqrt', class_weight='balanced_subsample', n_jobs=-1, random_state=42
    )
    model.fit(X_tr_imp, y_tr)

    y_pred = model.predict(X_te_imp)
    print("\n=== Evaluation ===")
    print(classification_report(y_te, y_pred, digits=4))
    cm = confusion_matrix(y_te, y_pred)
    print("Confusion [[TN,FP],[FN,TP]]:", cm.tolist())
    if hasattr(model,"predict_proba"):
        proba = model.predict_proba(X_te_imp)[:,1]
        print("ROC AUC:", roc_auc_score(y_te, proba))
        print("Average Precision (PR AUC):", average_precision_score(y_te, proba))

    artifact = {
        "model": model,
        "imputer": imputer,
        "feature_columns": features,
        "metadata": {
            "sklearn_version": __import__("sklearn").__version__,
            "n_samples": int(len(X)), "n_features": int(len(features))
        }
    }
    joblib.dump(artifact, out_path, compress=3)
    print(f"Saved model to {out_path}")

def main(data_path=None, out_path="phishing_model.pkl"):
    if data_path is None:
        # cho phép gọi từ GUI truyền None
        pass
    df = load_dataset(data_path)
    X, y, feats = prepare_X_y(df)
    if len(feats)==0:
        raise ValueError("Không tìm thấy feature numeric nào.")
    train_and_save(X, y, feats, out_path)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train phishing URL model")
    ap.add_argument("-d","--data", default=None, help="CSV path (mặc định auto-detect)")
    ap.add_argument("-o","--out", default="phishing_model.pkl", help="Đường dẫn lưu model")
    args = ap.parse_args()
    main(args.data, args.out)
