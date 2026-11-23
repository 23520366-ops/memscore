"""Regenerate serving datasets from existing trusted training artifacts.

The output includes presets, hash lookup tables, held-out IDs, and reference
statistics. Keep the persisted field names compatible with the app.
Run with `python training/prepare_demo.py`.
"""
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from common import DATA, MODELS, ROOT, SEED, load_parquet, open_parquet

OUT = ROOT / "app" / "data"
OUT.mkdir(parents=True, exist_ok=True)
rng = np.random.default_rng(SEED)


def split(df, groups):
    return next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(df, groups=groups))


def ref_stats(frame, cols):
    q1, med, q3 = frame[cols].quantile(0.25), frame[cols].median(), frame[cols].quantile(0.75)
    return {c: {"median": float(med[c]), "iqr": float(max(q3[c] - q1[c], 1e-9)),
                "p95": float(frame[c].quantile(0.95))} for c in cols}


def pick_with_hard(pool, proba, labels_true, n_easy, n_hard):
    """Select confident correct predictions and difficult examples where available."""
    pred = proba.argmax(1)
    conf = proba.max(1)
    easy = np.flatnonzero((pred == labels_true) & (conf >= 0.8))
    hard = np.flatnonzero((pred != labels_true) | (conf < 0.6))
    e = rng.choice(easy, min(n_easy, len(easy)), replace=False) if len(easy) else []
    h = rng.choice(hard, min(n_hard, len(hard)), replace=False) if len(hard) else []
    return [pool[i] for i in list(e) + list(h)]


stats, test_sets = {}, {}

# ------------------------------------------------------------------ Windows
win = pd.read_csv(DATA / "CIC-MalMem-2022.csv")
parts = win["Category"].str.split("-")
win["loai"] = parts.str[0]
win["ho"] = np.where(win["Class"] == "Malware", parts.str[1], "")
win["ma_bam"] = np.where(win["Class"] == "Malware", parts.str[2], "")
group = np.where(win["Class"] == "Malware", win["ma_bam"], "benign_" + win.index.astype(str))
tr, te = split(win, group)
gb = joblib.load(MODELS / "windows_sach_doc.joblib")
gt = joblib.load(MODELS / "windows_loai.joblib")
feats = gb["features"]
test = win.iloc[te].copy()
p_type = gt["model"].predict_proba(test[feats].values)
lab_idx = test["loai"].map({k: i for i, k in enumerate(gt["labels"])}).values
chosen = []
for i, lab in enumerate(gt["labels"]):
    rows = np.flatnonzero(lab_idx == i)
    chosen += [test.index[rows[j]] for j in pick_with_hard(list(range(len(rows))), p_type[rows], lab_idx[rows],
                                                             8, 2)]
wm = win.loc[chosen, ["Category", "Class", "loai", "ho", "ma_bam"] + feats].reset_index(drop=True)
wm.insert(0, "id", [f"W{i + 1:02d}" for i in range(len(wm))])
wm.to_csv(OUT / "windows_mau.csv", index=False, encoding="utf-8")
stats["windows"] = ref_stats(win.iloc[tr][win.iloc[tr]["Class"] == "Benign"], feats)
test_sets["windows"] = sorted(set(win.iloc[te]["ma_bam"]) - {""})
print("Windows:", len(wm), "presets")

# Android RAM classification
dyn = load_parquet("cicandmal2020-dynamic.parquet")
dyn["loai"] = dyn["Label"].str.replace(r"_(before|after)_reboot_Cat$", "", regex=True)
dyn["sau_reboot"] = dyn["Label"].str.contains("after_reboot").astype(int)
tr, te = split(dyn, dyn["Hash"])
ga = joblib.load(MODELS / "android_loai_chi_RAM.joblib")
mem = ga["features"]
test = dyn.iloc[te].copy()
p = ga["model"].predict_proba(test[mem].values)
lab_idx = test["loai"].map({k: i for i, k in enumerate(ga["labels"])}).values
chosen = []
for i, lab in enumerate(ga["labels"]):
    rows = np.flatnonzero(lab_idx == i)
    n_easy, n_hard = (3, 1) if i < 6 else (2, 0)
    chosen += [test.index[rows[j]] for j in pick_with_hard(list(range(len(rows))), p[rows], lab_idx[rows],
                                                             n_easy, n_hard)]
am = dyn.loc[chosen, ["Hash", "Family", "loai", "sau_reboot"] + mem].reset_index(drop=True)
am.insert(0, "id", [f"A{i + 1:02d}" for i in range(len(am))])
am.to_csv(OUT / "android_ram_mau.csv", index=False, encoding="utf-8")
stats["android_ram"] = ref_stats(dyn.iloc[tr], mem)
test_sets["android_ram"] = sorted(set(dyn.iloc[te]["Hash"].str.lower()))
# Store only the columns needed for hash lookup.
dyn[["Hash", "Family", "loai", "sau_reboot"] + mem].to_parquet(OUT / "android_ram_tra_cuu.parquet", index=False)
print("Android RAM:", len(am), "presets")

# Android static benign/malware classification
gs = joblib.load(MODELS / "android_sach_doc_static.joblib")
sfeats = gs["features"]
static_name = "cicandmal2020-static.parquet"
with open_parquet(static_name) as pf:
    meta = pf.read(columns=["F0", "Label"]).to_pandas()
meta["doc"] = (meta["Label"] != "Benign").astype(int)
# Reproduce the training subset from android_static.py.
r2 = np.random.default_rng(SEED)
ben = np.flatnonzero(meta["doc"].values == 0)
mal = np.flatnonzero(meta["doc"].values == 1)
idx = np.sort(np.concatenate([r2.choice(ben, 40_000, replace=False), r2.choice(mal, 40_000, replace=False)]))
sub = meta.iloc[idx].reset_index(drop=True)
trs, _ = split(sub, sub["F0"])
train_hashes = set(sub.iloc[trs]["F0"])
meta["trong_tap_train"] = meta["F0"].isin(train_hashes).astype(int)

# Score the entire static dataset in batches and read features in column blocks.
print("Scoring the static dataset...")
probs = np.zeros(len(meta), dtype="float32")
step = 60_000
with open_parquet(static_name) as pf:
    for start in range(0, len(meta), step):
        stop = min(start + step, len(meta))
        block = []
        for j in range(0, len(sfeats), 600):
            cols = sfeats[j:j + 600]
            t = pf.read(columns=cols)
            block.append(t.slice(start, stop - start).to_pandas().fillna(0).astype("float32"))
            del t
        X = pd.concat(block, axis=1)[sfeats].values
        probs[start:stop] = gs["model"].predict_proba(X)[:, 1]
        print(f"  {stop}/{len(meta)}", flush=True)
meta["xac_suat_doc"] = probs
meta.rename(columns={"F0": "ma_bam", "Label": "nhan"})[["ma_bam", "nhan", "xac_suat_doc", "trong_tap_train"]] \
    .to_csv(OUT / "android_static_tra_cuu.csv.gz", index=False, compression="gzip")

# Select up to 15 unseen presets per class, including difficult cases.
unseen = meta[meta["trong_tap_train"] == 0]
pick = []
for d, n in [(0, 15), (1, 15)]:
    g = unseen[unseen["doc"] == d]
    pred_right = (g["xac_suat_doc"] >= 0.5).astype(int) == d
    sure = g[pred_right & ((g["xac_suat_doc"] - 0.5).abs() > 0.4)]
    hard = g[~pred_right | ((g["xac_suat_doc"] - 0.5).abs() < 0.2)]
    pick += list(sure.sample(min(n - 2, len(sure)), random_state=SEED).index)
    pick += list(hard.sample(min(2, len(hard)), random_state=SEED).index)
pick = sorted(pick)
rows = []
with open_parquet(static_name) as pf:
    for j in range(0, len(sfeats), 600):
        cols = sfeats[j:j + 600]
        rows.append(pf.read(columns=cols).take(pick).to_pandas().fillna(0).astype("float32"))
sm = pd.concat(rows, axis=1)[sfeats]
sm.insert(0, "nhan", meta.loc[pick, "Label"].values)
sm.insert(0, "ma_bam", meta.loc[pick, "F0"].values)
sm.insert(0, "id", [f"S{i + 1:02d}" for i in range(len(sm))])
sm.to_parquet(OUT / "android_static_mau.parquet", index=False)
print("Android static:", len(sm), "presets")

(OUT / "thong_ke_tham_chieu.json").write_text(json.dumps(stats, ensure_ascii=False), encoding="utf-8")
(OUT / "tap_test.json").write_text(json.dumps(test_sets), encoding="utf-8")
print("Finished.")
