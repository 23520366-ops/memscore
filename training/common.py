"""Shared dataset, model, evaluation, and plotting utilities."""
import json
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
RESULTS = ROOT / "results"
MODELS = ROOT / "models"
SEED = 42


@contextmanager
def open_parquet(name: str):
    """Open a Parquet file directly or stream it from a ZIP archive."""
    path = DATA / name
    if path.is_file():
        with pq.ParquetFile(path) as parquet:
            yield parquet
        return
    path = next((p for p in sorted(DATA.glob(f"*{name}*.zip")) if p.is_file()), None)
    if path is None:
        raise FileNotFoundError(f"Could not find {name} in {DATA}.")
    with zipfile.ZipFile(path) as archive:
        members = [m for m in archive.namelist() if m.endswith(".parquet")]
        if not members:
            raise ValueError(f"No Parquet member in {path.name}.")
        inner = next((m for m in members if m.rsplit("/", 1)[-1] == name), members[0])
        with archive.open(inner) as stream, pq.ParquetFile(stream) as parquet:
            yield parquet


def load_parquet(name: str) -> pd.DataFrame:
    with open_parquet(name) as parquet:
        return parquet.read().to_pandas()


def make_models(n_classes: int):
    """Return the four estimators compared in the experiments."""
    return {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Decision Tree": DecisionTreeClassifier(random_state=SEED, class_weight="balanced"),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, random_state=SEED, n_jobs=-1, class_weight="balanced"),
        "XGBoost": XGBClassifier(
            n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.9,
            colsample_bytree=0.8, tree_method="hist", random_state=SEED, n_jobs=-1,
            objective="binary:logistic" if n_classes == 2 else "multi:softprob",
            eval_metric="logloss" if n_classes == 2 else "mlogloss"),
    }


def evaluate(y_true, y_pred, average="macro"):
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, average=average, zero_division=0),
        "recall": recall_score(y_true, y_pred, average=average, zero_division=0),
        "f1": f1_score(y_true, y_pred, average=average, zero_division=0),
    }


def run_models(X_tr, y_tr, X_te, y_te, labels, tag, out_dir: Path, sample_weight=None):
    """Fit and compare the four models and return the highest-scoring estimator."""
    rows, fitted = [], {}
    for name, model in make_models(len(labels)).items():
        t0 = time.time()
        if name == "XGBoost" and sample_weight is not None:
            model.fit(X_tr, y_tr, sample_weight=sample_weight)
        else:
            model.fit(X_tr, y_tr)
        train_s = time.time() - t0
        t0 = time.time()
        pred = model.predict(X_te)
        pred_ms = (time.time() - t0) / len(X_te) * 1000
        m = evaluate(y_te, pred)
        m.update(model=name, experiment=tag, train_seconds=round(train_s, 2),
                 ms_per_sample=round(pred_ms, 4))
        rows.append(m)
        fitted[name] = (model, pred)
        print(f"  [{tag}] {name:20s} acc={m['accuracy']:.4f} f1={m['f1']:.4f} ({train_s:.1f}s)")
    df = pd.DataFrame(rows)[["experiment", "model", "accuracy", "precision", "recall", "f1",
                             "train_seconds", "ms_per_sample"]]
    best = df.sort_values("f1", ascending=False).iloc[0]["model"]
    model, pred = fitted[best]
    report = classification_report(y_te, pred, labels=range(len(labels)), target_names=labels,
                                   digits=4, zero_division=0)
    (out_dir / f"report_{tag}.txt").write_text(f"Best model: {best}\n\n{report}", encoding="utf-8")
    plot_confusion(y_te, pred, labels, f"{tag} - {best}", out_dir / f"confusion_{tag}.png")
    # Use the best tree model for feature importance.
    best_tree = df[df.model.isin(["Random Forest", "XGBoost"])].sort_values("f1", ascending=False).iloc[0]["model"]
    return df, best, model, fitted[best_tree][0], best_tree


def plot_confusion(y_true, y_pred, labels, title, path):
    cm = confusion_matrix(y_true, y_pred, labels=range(len(labels)))
    cm_norm = cm / cm.sum(axis=1, keepdims=True).clip(min=1)
    size = max(5, 0.55 * len(labels) + 2)
    fig, ax = plt.subplots(figsize=(size, size * 0.85))
    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(labels)), labels, fontsize=8)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if cm[i, j]:
                ax.text(j, i, f"{cm_norm[i, j]:.2f}", ha="center", va="center", fontsize=7,
                        color="white" if cm_norm[i, j] > 0.5 else "black")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title, fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_importance(model, feature_names, title, path, top=20):
    est = model[-1] if hasattr(model, "steps") else model
    imp = pd.Series(est.feature_importances_, index=feature_names).sort_values(ascending=False)
    head = imp.head(top)[::-1]
    fig, ax = plt.subplots(figsize=(8, 0.32 * len(head) + 1.2))
    ax.barh(head.index, head.values, color="#3b6ea8")
    ax.set_xlabel("Feature importance")
    ax.set_title(title, fontsize=10)
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return imp


def save_json(obj, path):
    Path(path).write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
