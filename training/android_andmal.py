"""Compare RAM features with all dynamic features on CCCS-CIC-AndMal-2020.

A1 uses the 21 nonconstant RAM features. A2 uses all dynamic features.
Both experiments group measurements from the same APK when splitting the data.
Run with `python training/android_andmal.py`.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight

from common import MODELS, RESULTS, SEED, load_parquet, plot_importance, run_models, save_json

OUT = RESULTS / "android"
OUT.mkdir(parents=True, exist_ok=True)
MODELS.mkdir(exist_ok=True)


# Load and prepare the dataset.
df = load_parquet("cicandmal2020-dynamic.parquet")
print("Dataset shape:", df.shape)

# Split the original label into malware class and reboot phase.
label = df["Label"].astype(str)
df["malware_class"] = label.str.replace(r"_(before|after)_reboot_Cat$", "", regex=True)
df["after_reboot"] = label.str.contains("after_reboot").astype(int)

# Exclude identifiers and other text columns from the feature matrix.
text_cols = [c for c in df.columns if not pd.api.types.is_numeric_dtype(df[c])]
id_like = [c for c in text_cols if c not in ("Label", "malware_class")]
hash_col = next((c for c in df.columns if c.lower() in ("hash", "sha256", "md5")), None)
# Group both reboot phases of each APK by hash.
df["group"] = df[hash_col].astype(str) if hash_col else df.index.astype(str)

numeric = [c for c in df.columns if c not in text_cols + ["malware_class", "after_reboot", "group", "Label"]
           and pd.api.types.is_numeric_dtype(df[c])]
const = [c for c in numeric if df[c].nunique() <= 1]
numeric = [c for c in numeric if c not in const]
mem_cols = [c for c in numeric if c.startswith("Memory_")]
print(f"Excluded text columns: {id_like}")
print(f"Dropped {len(const)} constant columns")
print(f"Remaining features: {len(numeric)} ({len(mem_cols)} RAM)")

groups = {}
for c in numeric:
    prefix = c.split("_")[0]
    groups[prefix] = groups.get(prefix, 0) + 1

classes = df["malware_class"].value_counts()
labels = classes.index.tolist()          # Ordered by descending sample count.
y = df["malware_class"].map({k: i for i, k in enumerate(labels)}).values

save_json({
    "so_dong": len(df),
    "so_cot_ban_dau": int(df.shape[1]),
    "cot_chu_bi_bo": id_like,
    "cot_hang_so_bi_bo": const,
    "so_dac_trung": len(numeric),
    "so_cot_theo_nhom": groups,
    "cot_ram": mem_cols,
    "so_mau_moi_loai": classes.to_dict(),
    "dong_trung_lap": int(df.duplicated(subset=numeric + ["malware_class"]).sum()),
    "co_cot_ma_bam": hash_col,
    "so_app_khac_nhau": int(df["group"].nunique()),
}, OUT / "eda.json")

# Plot the class distribution.
import matplotlib.pyplot as plt  # noqa: E402
fig, ax = plt.subplots(figsize=(8, 4.5))
classes[::-1].plot.barh(ax=ax, color="#3b6ea8")
ax.set_xlabel("Sample count")
ax.set_title("AndMal2020 dynamic samples by malware class", fontsize=10)
for i, v in enumerate(classes[::-1].values):
    ax.text(v, i, f" {v:,}", va="center", fontsize=7)
fig.tight_layout()
fig.savefig(OUT / "phan_bo_loai.png", dpi=150)
plt.close(fig)

# Split the dataset and fit each model.
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
tr, te = next(gss.split(df, groups=df["group"]))
print(f"Train rows: {len(tr)}. Test rows: {len(te)}.")
# Weight less common classes more heavily.
w_tr = compute_sample_weight("balanced", y[tr])

all_scores, saved = [], {}
for tag, cols, title in [("A1_chi_RAM", mem_cols, "RAM features only"),
                         ("A2_tat_ca", numeric, "all dynamic features")]:
    print(f"\n== {tag}: {title} ==")
    X = df[cols].astype("float32").values
    scores, best, model, tree, tree_name = run_models(X[tr], y[tr], X[te], y[te], labels, tag, OUT,
                                                      sample_weight=w_tr)
    all_scores.append(scores)
    imp = plot_importance(tree, cols, f"Top 20 features ({title}, {tree_name})",
                          OUT / f"importance_{tag}.png")
    imp.rename("importance").to_csv(OUT / f"importance_{tag}.csv", encoding="utf-8-sig")
    saved[tag] = {"model": model, "features": cols, "labels": labels, "name": best}

table = pd.concat(all_scores)
table.to_csv(OUT / "bang_diem.csv", index=False, encoding="utf-8-sig")
print("\n", table.to_string(index=False))

# Compare feature groups.
# Fit each feature group independently.
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import f1_score  # noqa: E402
rows = []
for prefix in sorted(groups):
    cols = [c for c in numeric if c.split("_")[0] == prefix]
    rf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1, class_weight="balanced")
    X = df[cols].astype("float32").values
    rf.fit(X[tr], y[tr])
    f1 = f1_score(y[te], rf.predict(X[te]), average="macro")
    rows.append({"nhom_dac_trung": prefix, "so_cot": len(cols), "f1_macro": round(f1, 4)})
    print(f"  {prefix:10s} ({len(cols):3d} columns) F1={f1:.4f}")
pd.DataFrame(rows).sort_values("f1_macro", ascending=False).to_csv(
    OUT / "theo_nhom_dac_trung.csv", index=False, encoding="utf-8-sig")

# Save the trained models.
joblib.dump(saved["A1_chi_RAM"], MODELS / "android_loai_chi_RAM.joblib")
joblib.dump(saved["A2_tat_ca"], MODELS / "android_loai_tat_ca.joblib")
print("\nFinished. See results/android and models/.")
