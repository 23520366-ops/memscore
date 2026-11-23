"""Evaluate tuning, RAM ratios, model ensembles, and aggregation by APK.

Use the original grouped split and seed for a comparable held-out evaluation.
Run with `python training/android_tuning.py`.
"""
import time

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from common import RESULTS, SEED, load_parquet, plot_confusion, save_json

OUT = RESULTS / "android"


def prepare():
    df = load_parquet("cicandmal2020-dynamic.parquet")
    df["malware_class"] = df["Label"].str.replace(r"_(before|after)_reboot_Cat$", "", regex=True)
    df["after_reboot"] = df["Label"].str.contains("after_reboot").astype(int)
    num = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c]) and c != "after_reboot"]
    num = [c for c in num if df[c].nunique() > 1]
    return df, num


def add_ratios(d):
    """Add ratios that describe the composition of memory use."""
    eps = 1.0
    r = pd.DataFrame(index=d.index)
    r["R_heap_used"] = d["Memory_HeapAlloc"] / (d["Memory_HeapSize"] + eps)
    r["R_private_over_total"] = (d["Memory_PrivateDirty"] + d["Memory_PrivateClean"]) / (d["Memory_PssTotal"] + eps)
    r["R_shared_dirty"] = d["Memory_SharedDirty"] / (d["Memory_PssTotal"] + eps)
    r["R_clean_over_total"] = d["Memory_PssClean"] / (d["Memory_PssTotal"] + eps)
    r["R_views_per_activity"] = d["Memory_Views"] / (d["Memory_Activities"] + eps)
    r["R_proxy_over_local_binder"] = d["Memory_ProxyBinders"] / (d["Memory_LocalBinders"] + eps)
    r["R_kb_per_parcel"] = d["Memory_ParcelMemory"] / (d["Memory_ParcelCount"] + eps)
    r["R_death_over_proxy"] = d["Memory_DeathRecipients"] / (d["Memory_ProxyBinders"] + eps)
    r["R_total_objects"] = d[["Memory_Views", "Memory_AppContexts", "Memory_Activities", "Memory_Assets",
                               "Memory_LocalBinders", "Memory_ProxyBinders", "Memory_WebViews"]].sum(axis=1)
    return r


def lgbm(n_classes):
    return lgb.LGBMClassifier(n_estimators=3000, learning_rate=0.03, num_leaves=127, min_child_samples=10,
                              subsample=0.8, subsample_freq=1, colsample_bytree=0.6, reg_lambda=1.0,
                              objective="multiclass", num_class=n_classes, random_state=SEED,
                              n_jobs=-1, verbose=-1)


def xgb(n_classes):
    return XGBClassifier(n_estimators=3000, learning_rate=0.05, max_depth=10, min_child_weight=1,
                         subsample=0.8, colsample_bytree=0.6, tree_method="hist", objective="multi:softprob",
                         eval_metric="mlogloss", early_stopping_rounds=100, random_state=SEED, n_jobs=-1)


def fit_predict(X_tr, y_tr, X_te, groups_tr, n_classes, which=("lgbm", "xgb")):
    """Use 10% of the training apps for early stopping and return test probabilities."""
    inner = GroupShuffleSplit(n_splits=1, test_size=0.1, random_state=SEED)
    a, b = next(inner.split(X_tr, groups=groups_tr))
    w = compute_sample_weight("balanced", y_tr[a])
    probs = {}
    if "lgbm" in which:
        m = lgbm(n_classes)
        m.fit(X_tr[a], y_tr[a], sample_weight=w, eval_set=[(X_tr[b], y_tr[b])],
              callbacks=[lgb.early_stopping(100, verbose=False)])
        probs["LightGBM"] = m.predict_proba(X_te)
    if "xgb" in which:
        m = xgb(n_classes)
        m.fit(X_tr[a], y_tr[a], sample_weight=w, eval_set=[(X_tr[b], y_tr[b])], verbose=False)
        probs["XGBoost"] = m.predict_proba(X_te)
    if len(probs) > 1:
        probs["LightGBM + XGBoost"] = np.mean(list(probs.values()), axis=0)
    return probs


def score(y, p):
    pred = p.argmax(1)
    return accuracy_score(y, pred), f1_score(y, pred, average="macro"), pred


def per_app(df, cols):
    """Combine both reboot phases of each app and calculate their difference."""
    keep = df[["Hash", "malware_class", "after_reboot"] + cols].copy()
    # Average repeated measurements within each phase.
    keep = keep.groupby(["Hash", "malware_class", "after_reboot"], as_index=False)[cols].mean()
    wide = keep.pivot(index=["Hash", "malware_class"], columns="after_reboot", values=cols)
    wide = wide.reindex(columns=pd.MultiIndex.from_product([cols, [0, 1]]))
    wide.columns = [f"{c}__{'after' if s else 'before'}" for c, s in wide.columns]
    for c in cols:
        t, s = f"{c}__before", f"{c}__after"
        wide[f"{c}__delta"] = wide[s] - wide[t]
    wide["has_both_phases"] = wide[[f"{cols[0]}__before", f"{cols[0]}__after"]].notna().all(axis=1).astype(int)
    return wide.reset_index()


def main():
    df, num = prepare()
    mem = [c for c in num if c.startswith("Memory_")]
    labels = df["malware_class"].value_counts().index.tolist()
    lab_id = {k: i for i, k in enumerate(labels)}
    y = df["malware_class"].map(lab_id).values
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(df, groups=df["Hash"]))
    test_hashes = set(df["Hash"].iloc[te])
    rows = []

    def log(exp, feat, model, acc, f1, unit, secs):
        rows.append({"cach": exp, "dac_trung": feat, "mo_hinh": model, "accuracy": round(acc, 4),
                     "f1_macro": round(f1, 4), "don_vi_cham": unit, "giay": round(secs, 1)})
        print(f"  {exp:30s} {feat:12s} {model:20s} acc={acc:.4f} f1={f1:.4f} ({secs:.0f}s)", flush=True)

    feature_sets = {
        "RAM only": (df[mem], mem),
        "RAM + ratios": (pd.concat([df[mem], add_ratios(df)], axis=1), None),
        "All features": (pd.concat([df[num], add_ratios(df)], axis=1), None),
    }

    # C1, C2, and C4 score each measurement independently.
    print("\n== Scoring by measurement ==")
    for name, (X, _) in feature_sets.items():
        Xv = X.astype("float32").values
        t0 = time.time()
        probs = fit_predict(Xv[tr], y[tr], Xv[te], df["Hash"].values[tr], len(labels))
        for model, p in probs.items():
            acc, f1, _ = score(y[te], p)
            log("C1/C2/C4 per measurement", name, model, acc, f1, "measurement", time.time() - t0)

    # C3 scores aggregated app measurements.
    print("\n== Scoring by app with both reboot phases ==")
    best = None
    for name, cols in [("RAM only", mem), ("RAM + ratios", None)]:
        base = df.copy()
        if cols is None:
            ratios = add_ratios(df)
            base = pd.concat([base, ratios], axis=1)
            cols = mem + list(ratios.columns) if name == "RAM + ratios" else num + list(ratios.columns)
        wide = per_app(base, cols)
        is_te = wide["Hash"].isin(test_hashes).values
        Xw = wide.drop(columns=["Hash", "malware_class"]).astype("float32").values
        yw = wide["malware_class"].map(lab_id).values
        t0 = time.time()
        probs = fit_predict(Xw[~is_te], yw[~is_te], Xw[is_te], wide["Hash"].values[~is_te], len(labels))
        for model, p in probs.items():
            acc, f1, pred = score(yw[is_te], p)
            log("C3 per app", name, model, acc, f1, "app", time.time() - t0)
            if name == "RAM only" and (best is None or f1 > best[0]):
                best = (f1, model, yw[is_te], pred)

    f1b, model_b, y_true, y_pred = best
    plot_confusion(y_true, y_pred, labels, f"RAM only, grouped by app - {model_b}",
                   OUT / "confusion_cai_thien_chi_RAM.png")

    pd.DataFrame(rows).to_csv(OUT / "bang_diem_cai_thien.csv", index=False, encoding="utf-8-sig")
    save_json({"mo_hinh_tot_nhat_chi_RAM": model_b, "f1": round(f1b, 4)}, OUT / "cai_thien_tom_tat.json")
    print("\nFinished.")


if __name__ == "__main__":
    main()
