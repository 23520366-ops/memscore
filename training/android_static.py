"""Fit the Android benign/malware baseline on anonymized static features.

Read the original Parquet in column blocks for a balanced sample of 80,000 apps.
The published columns are anonymous, so this workflow cannot score a new APK.
Run with `python training/android_static.py`.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from common import MODELS, RESULTS, SEED, open_parquet, plot_importance, run_models, save_json

OUT = RESULTS / "android_static"
OUT.mkdir(parents=True, exist_ok=True)
SAMPLES_PER_CLASS = 40_000

with open_parquet("cicandmal2020-static.parquet") as pf:
    meta = pf.read(columns=["F0", "Label"]).to_pandas()
    meta["is_malware"] = (meta["Label"] != "Benign").astype(int)
    print("Total rows:", len(meta))
    print(meta["Label"].value_counts().to_string())

    rng = np.random.default_rng(SEED)
    ben = np.flatnonzero(meta["is_malware"].values == 0)
    mal = np.flatnonzero(meta["is_malware"].values == 1)
    idx = np.sort(np.concatenate([rng.choice(ben, SAMPLES_PER_CLASS, replace=False), rng.choice(mal, SAMPLES_PER_CLASS, replace=False)]))
    sub = meta.iloc[idx].reset_index(drop=True)

    # Read 500 columns at a time and retain the sampled rows.
    feat_names = [n for n in pf.schema_arrow.names if n not in ("F0", "Label")]
    blocks = []
    for i in range(0, len(feat_names), 500):
        cols = feat_names[i:i + 500]
        part = pf.read(columns=cols).to_pandas().iloc[idx].reset_index(drop=True)
        blocks.append(part.fillna(0).astype("float32"))
        print(f"  Read {min(i + 500, len(feat_names))}/{len(feat_names)} columns", flush=True)
X = pd.concat(blocks, axis=1)
del blocks
keep = X.columns[X.nunique() > 1]
print(f"Dropped {X.shape[1] - len(keep)} constant columns. {len(keep)} features remain.")
X = X[keep]

save_json({
    "tong_so_dong_file_goc": len(meta),
    "so_mau_moi_loai_file_goc": meta["Label"].value_counts().to_dict(),
    "so_mau_lay": {"sach": SAMPLES_PER_CLASS, "doc": SAMPLES_PER_CLASS},
    "so_dac_trung_con_lai": len(keep),
    "ghi_chu": "Anonymized static features F1 through F9503",
}, OUT / "eda.json")

y = sub["is_malware"].values
tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, groups=sub["F0"]))
scores, best, model, tree, tree_name = run_models(X.values[tr], y[tr], X.values[te], y[te],
                                                  ["Benign", "Malware"], "S1_sach_doc_static", OUT)
scores.to_csv(OUT / "bang_diem.csv", index=False, encoding="utf-8-sig")
print(scores.to_string(index=False))

# Measure recall for each malware class in the test split.
pred = model.predict(X.values[te])
t = sub.iloc[te].assign(prediction=pred)
by_type = t[t["is_malware"] == 1].groupby("Label")["prediction"].agg(["count", "mean"]).rename(
    columns={"count": "so_mau_test", "mean": "ti_le_phat_hien"}).sort_values("ti_le_phat_hien")
by_type.round(4).to_csv(OUT / "phat_hien_theo_loai.csv", encoding="utf-8-sig")
print(by_type.round(4).to_string())
print("Benign false positive rate:", round(t.loc[t["is_malware"] == 0, "prediction"].mean(), 4))

plot_importance(tree, list(keep), f"Top 20 static features ({tree_name})", OUT / "importance.png")
# The two scores differ by about 0.03 percentage points. The Random Forest artifact is nearly 40 MB.
# Save the smaller XGBoost artifact for the demo.
from common import make_models  # noqa: E402
xgb_model = make_models(2)["XGBoost"].fit(X.values[tr], y[tr])
joblib.dump({"model": xgb_model, "features": list(keep), "labels": ["Benign", "Malware"], "name": "XGBoost"},
            MODELS / "android_sach_doc_static.joblib", compress=3)
print("Finished.")
