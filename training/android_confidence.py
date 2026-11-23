"""Evaluate confidence thresholds, top-k accuracy, and coarser Android labels.

Run with `python training/android_confidence.py`.
"""
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from common import RESULTS, SEED, load_parquet, plot_confusion

OUT = RESULTS / "android"

# Group samples by broad behavior.
BEHAVIOR_GROUPS = {
    "Trojan": "General Trojan", "Trojan_Spy": "Information theft", "Trojan_SMS": "Information theft",
    "Trojan_Banker": "Information theft", "Trojan_Dropper": "General Trojan", "Backdoor": "General Trojan",
    "Ransomware": "Extortion and scareware", "Scareware": "Extortion and scareware",
    "Adware": "Advertising and unwanted software", "PUA": "Advertising and unwanted software", "Riskware": "Advertising and unwanted software",
    "FileInfector": "General Trojan", "Zero_Day": "Unclassified", "No_Category": "Unclassified",
}


def model():
    return XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.9, colsample_bytree=0.8,
                         tree_method="hist", objective="multi:softprob", random_state=SEED, n_jobs=-1)


def run(X, y_lab, tr, te, tag):
    labels = pd.Series(y_lab[np.concatenate([tr, te])]).value_counts().index.tolist()
    y = pd.Series(y_lab).map({k: i for i, k in enumerate(labels)}).fillna(-1).astype(int).values
    m = model()
    m.fit(X[tr], y[tr], sample_weight=compute_sample_weight("balanced", y[tr]))
    p = m.predict_proba(X[te])
    pred = p.argmax(1)
    acc, f1 = accuracy_score(y[te], pred), f1_score(y[te], pred, average="macro")
    plot_confusion(y[te], pred, labels, tag, OUT / f"confusion_{tag}.png")
    return labels, y[te], p, acc, f1


df = load_parquet("cicandmal2020-dynamic.parquet")
df["malware_class"] = df["Label"].str.replace(r"_(before|after)_reboot_Cat$", "", regex=True)
num = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c]) and df[c].nunique() > 1]
mem = [c for c in num if c.startswith("Memory_")]
tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(df, groups=df["Hash"]))

rows, conf_rows = [], []
for feat_name, cols in [("RAM only", mem), ("All features", num)]:
    X = df[cols].astype("float32").values

    # Measure confidence and top-k accuracy across all 14 classes.
    labels, yt, p, acc, f1 = run(X, df["malware_class"].values, tr, te, f"14loai_{'RAM' if cols is mem else 'tatca'}")
    rank = np.argsort(-p, axis=1)
    top2 = np.mean([yt[i] in rank[i, :2] for i in range(len(yt))])
    top3 = np.mean([yt[i] in rank[i, :3] for i in range(len(yt))])
    rows.append({"bai_toan": "14 classes", "dac_trung": feat_name, "accuracy": acc, "f1_macro": f1,
                 "dung_trong_top2": top2, "dung_trong_top3": top3})
    conf = p.max(1)
    correct = p.argmax(1) == yt
    for th in [0.0, 0.5, 0.6, 0.7, 0.8, 0.9]:
        sel = conf >= th
        conf_rows.append({"dac_trung": feat_name, "nguong_tin_cay": th, "ti_le_mau_duoc_tra_loi": sel.mean(),
                          "accuracy_tren_mau_do": correct[sel].mean()})

    # Exclude the two ambiguous classes.
    keep = ~df["malware_class"].isin(["Zero_Day", "No_Category"]).values
    idx = np.where(keep)[0]
    tr2, te2 = np.intersect1d(tr, idx), np.intersect1d(te, idx)
    _, _, _, acc, f1 = run(X, df["malware_class"].where(keep, "").values, tr2, te2,
                           f"12loai_{'RAM' if cols is mem else 'tatca'}")
    rows.append({"bai_toan": "12 classes (excluding Zero_Day and No_Category)", "dac_trung": feat_name,
                 "accuracy": acc, "f1_macro": f1})

    # Evaluate the four grouped behaviors among classified samples.
    g = df["malware_class"].map(BEHAVIOR_GROUPS)
    keep = (g != "Unclassified").values
    idx = np.where(keep)[0]
    tr3, te3 = np.intersect1d(tr, idx), np.intersect1d(te, idx)
    _, _, _, acc, f1 = run(X, g.where(keep, "").values, tr3, te3, f"4nhom_{'RAM' if cols is mem else 'tatca'}")
    rows.append({"bai_toan": "4 behavior groups", "dac_trung": feat_name, "accuracy": acc, "f1_macro": f1})
    print(pd.DataFrame(rows).tail(3).round(4).to_string(index=False), flush=True)

pd.DataFrame(rows).round(4).to_csv(OUT / "bang_diem_bien_the.csv", index=False, encoding="utf-8-sig")
pd.DataFrame(conf_rows).round(4).to_csv(OUT / "do_tin_cay.csv", index=False, encoding="utf-8-sig")
print(pd.DataFrame(conf_rows).round(3).to_string(index=False))
