"""Evaluate Windows memory classification on CIC-MalMem-2022.

Each row contains 55 features previously extracted from a memory image
with Volatility. Run with `python training/windows_malmem.py`.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupShuffleSplit

from common import DATA, MODELS, RESULTS, SEED, plot_importance, run_models, save_json

OUT = RESULTS / "windows"
OUT.mkdir(parents=True, exist_ok=True)
MODELS.mkdir(exist_ok=True)

# Load and prepare the dataset.
df = pd.read_csv(DATA / "CIC-MalMem-2022.csv")
print("Original dataset shape:", df.shape)

# Category encodes class, family, sample hash, and capture index.
parts = df["Category"].str.split("-")
df["type"] = parts.str[0]                                  # Benign / Trojan / Spyware / Ransomware
df["family"] = np.where(df["Class"] == "Malware", parts.str[1], "Benign")
# Keep all captures from a sample hash in the same split.
df["group"] = np.where(df["Class"] == "Malware", parts.str[2], "benign_" + df.index.astype(str))

features = [c for c in df.columns if c not in ("Category", "Class", "type", "family", "group")]
const = [c for c in features if df[c].nunique() <= 1]
features = [c for c in features if c not in const]
print(f"Dropped {len(const)} constant columns: {const}")
print(f"Training features: {len(features)}")

eda = {
    "so_mau": len(df),
    "so_dac_trung": len(features),
    "cot_bi_bo": const,
    "dong_trung_lap": int(df.duplicated(subset=features + ["Class"]).sum()),
    "phan_bo_sach_doc": df["Class"].value_counts().to_dict(),
    "phan_bo_loai": df["type"].value_counts().to_dict(),
    "phan_bo_ho": df["family"].value_counts().to_dict(),
}
save_json(eda, OUT / "eda.json")

X = df[features].astype("float32").values
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
tr, te = next(gss.split(X, groups=df["group"]))
print(f"Train rows: {len(tr)}. Test rows: {len(te)}.")

all_scores = []

# W1: benign versus malware.
print("\n== W1: benign versus malware ==")
y_bin = (df["Class"] == "Malware").astype(int).values
scores, best_bin, model_bin, _, _ = run_models(
    X[tr], y_bin[tr], X[te], y_bin[te], ["Benign", "Malware"], "W1_sach_doc", OUT)
all_scores.append(scores)

# W2: four-way Windows classification.
print("\n== W2: Benign / Trojan / Spyware / Ransomware ==")
type_labels = ["Benign", "Trojan", "Spyware", "Ransomware"]
y_type = df["type"].map({k: i for i, k in enumerate(type_labels)}).values
scores, best_type, model_type, tree_type, _ = run_models(
    X[tr], y_type[tr], X[te], y_type[te], type_labels, "W2_loai", OUT)
all_scores.append(scores)

pd.concat(all_scores).to_csv(OUT / "bang_diem.csv", index=False, encoding="utf-8-sig")

# Plot feature importance.
imp = plot_importance(tree_type, features, "Top 20 Windows memory features for four-way classification",
                      OUT / "importance_W2.png")
imp.rename("importance").to_csv(OUT / "importance_W2.csv", encoding="utf-8-sig")

# Compare Volatility plugins individually.
# Feature prefixes identify the Volatility plugin that produced them.
print("\n== Four-way classification by individual Volatility plugin ==")
plugin_rows = []
for plugin in sorted({f.split(".")[0] for f in features}):
    cols = [i for i, f in enumerate(features) if f.startswith(plugin + ".")]
    rf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1, class_weight="balanced")
    rf.fit(X[tr][:, cols], y_type[tr])
    f1 = f1_score(y_type[te], rf.predict(X[te][:, cols]), average="macro")
    plugin_rows.append({"plugin": plugin, "so_dac_trung": len(cols), "f1_macro": round(f1, 4)})
    print(f"  {plugin:12s} ({len(cols):2d} columns)  F1={f1:.4f}")
pd.DataFrame(plugin_rows).sort_values("f1_macro", ascending=False).to_csv(
    OUT / "theo_plugin.csv", index=False, encoding="utf-8-sig")

# Evaluate generalization to unseen families.
# Hold out one entire family at a time and measure binary detection.
print("\n== Leave-one-family-out detection ==")
fam_rows = []
benign_idx = np.where(df["Class"] == "Benign")[0]
rng = np.random.default_rng(SEED)
benign_test = rng.choice(benign_idx, size=len(benign_idx) // 5, replace=False)
benign_train = np.setdiff1d(benign_idx, benign_test)
for fam in sorted(df.loc[df["Class"] == "Malware", "family"].unique()):
    fam_idx = np.where(df["family"] == fam)[0]
    other_mal = np.where((df["Class"] == "Malware") & (df["family"] != fam))[0]
    train_idx = np.concatenate([benign_train, other_mal])
    rf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1)
    rf.fit(X[train_idx], y_bin[train_idx])
    detect = rf.predict(X[fam_idx]).mean()
    false_alarm = rf.predict(X[benign_test]).mean()
    fam_rows.append({"ho_ma_doc": fam, "loai": df.loc[fam_idx[0], "type"], "so_mau": len(fam_idx),
                     "ti_le_phat_hien": round(detect, 4), "bao_dong_nham_tren_mau_sach": round(false_alarm, 4)})
    print(f"  {fam:14s} detected {detect:6.2%}   false positives {false_alarm:.2%}")
pd.DataFrame(fam_rows).to_csv(OUT / "ho_chua_tung_thay.csv", index=False, encoding="utf-8-sig")

# Save models and test presets.
joblib.dump({"model": model_bin, "features": features, "labels": ["Benign", "Malware"], "name": best_bin},
            MODELS / "windows_sach_doc.joblib")
joblib.dump({"model": model_type, "features": features, "labels": type_labels, "name": best_type},
            MODELS / "windows_loai.joblib")
# Retain a small set of test rows for demonstration.
demo = df.iloc[te].groupby("type").sample(n=25, random_state=SEED)
demo[["Category", "Class", "type", "family"] + features].to_csv(
    DATA / "demo_windows.csv", index=False, encoding="utf-8-sig")
print("\nFinished. See results/windows and models/.")
