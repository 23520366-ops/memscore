"""Serve the MemScope demo, dataset lookups, and isolated live measurements."""
import gzip
import hashlib
import json
import os
import shutil
import tempfile
import unicodedata
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path, PureWindowsPath
from queue import Full
from zipfile import is_zipfile

from xgboost import XGBClassifier
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sklearn.model_selection import GroupShuffleSplit
from starlette.datastructures import Headers
from starlette.formparsers import MultiPartException
from starlette.middleware.trustedhost import TrustedHostMiddleware

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = HERE / "data"
if __package__:
    from .android_runner import MAX_APK, AndroidJobs
    from .windows_features import FEATURE_NOTES
    from .sample_policy import SampleNotAllowed, require_allowed_sample
    from .windows_runner import BUILTIN_SAMPLES, MAX_EXE, WindowsJobs
else:
    from android_runner import MAX_APK, AndroidJobs
    from windows_features import FEATURE_NOTES
    from sample_policy import SampleNotAllowed, require_allowed_sample
    from windows_runner import BUILTIN_SAMPLES, MAX_EXE, WindowsJobs

CONFIDENCE_THRESHOLD = 0.70

# Load the model artifacts and dataset records.
MODELS = HERE / "models"


def load_model(name: str) -> dict:
    """Load gzip-compressed native XGBoost artifacts for portable inference."""
    meta = json.loads((MODELS / f"{name}.json").read_text(encoding="utf-8"))
    clf = XGBClassifier()
    clf.load_model(bytearray(gzip.decompress((MODELS / f"{name}.ubj.gz").read_bytes())))
    meta["model"] = clf
    return meta


INFERENCE_MODELS = {k: load_model(k) for k in
     ["windows_sach_doc", "windows_loai", "android_loai_chi_RAM", "android_sach_doc_static"]}
try:
    STATS = json.loads((DATA / "thong_ke_tham_chieu.json").read_text(encoding="utf-8"))
except FileNotFoundError:
    STATS = {}
TEST = {k: set(v) for k, v in json.loads((DATA / "tap_test.json").read_text(encoding="utf-8")).items()}

WINDOWS_PRESETS = pd.read_csv(DATA / "windows_mau.csv")
ANDROID_RAM_PRESETS = pd.read_csv(DATA / "android_ram_mau.csv")
ANDROID_STATIC_PRESETS = pd.read_parquet(DATA / "android_static_mau.parquet")

WINDOWS_DATA = pd.read_csv(ROOT / "data" / "CIC-MalMem-2022.csv")
windows_category_parts = WINDOWS_DATA["Category"].str.split("-")
WINDOWS_DATA["loai"], WINDOWS_DATA["ho"] = windows_category_parts.str[0], np.where(WINDOWS_DATA["Class"] == "Malware", windows_category_parts.str[1], "")
WINDOWS_DATA["ma_bam"] = np.where(WINDOWS_DATA["Class"] == "Malware", windows_category_parts.str[2].str.lower(), "")
ANDROID_RAM_DATA = pd.read_parquet(DATA / "android_ram_tra_cuu.parquet")
ANDROID_RAM_DATA["hash_l"] = ANDROID_RAM_DATA["Hash"].str.lower()
ANDROID_STATIC_DATA = pd.read_csv(DATA / "android_static_tra_cuu.csv.gz")
ANDROID_STATIC_DATA["hash_l"] = ANDROID_STATIC_DATA["ma_bam"].str.lower()

# Vietnamese labels and descriptions displayed in the web UI.
WINDOWS_GROUPS = {
    "pslist": ("Tiến trình", "Danh sách tiến trình đang chạy, số luồng, số handle trung bình"),
    "dlllist": ("DLL", "Số thư viện được nạp vào các tiến trình"),
    "handles": ("Handle", "Số đối tượng đang mở: file, registry, mutex, sự kiện, luồng..."),
    "ldrmodules": ("DLL bị giấu", "DLL có trong bộ nhớ nhưng không có trong danh sách nạp chính thức"),
    "malfind": ("Tiêm mã", "Vùng nhớ vừa ghi được vừa chạy được, dấu hiệu mã bị chèn vào tiến trình khác"),
    "psxview": ("Tiến trình ẩn", "Tiến trình thấy được bằng cách quét nhưng không có trong danh sách thường"),
    "modules": ("Module nhân", "Số driver/module đang nạp trong nhân Windows"),
    "svcscan": ("Dịch vụ", "Số dịch vụ Windows, driver nhân, driver hệ thống file"),
    "callbacks": ("Callback", "Các hàm được đăng ký để nhân gọi khi có sự kiện"),
}
ANDROID_GROUPS = {
    "Heap": (["Memory_HeapSize", "Memory_HeapAlloc", "Memory_HeapFree"], "Bộ nhớ heap Java và heap native của tiến trình"),
    "RAM riêng": (["Memory_PrivateDirty", "Memory_PrivateClean"], "RAM chỉ app này dùng"),
    "RAM chia sẻ": (["Memory_PssTotal", "Memory_PssClean", "Memory_SharedDirty", "Memory_SharedClean"],
                       "RAM tính cả phần dùng chung với app khác"),
    "Giao diện": (["Memory_Views", "Memory_ViewRootImpl", "Memory_Activities"], "Số màn hình và thành phần giao diện"),
    "Tài nguyên": (["Memory_AppContexts", "Memory_Assets"], "Ngữ cảnh app và file tài nguyên đang mở"),
    "Binder": (["Memory_LocalBinders", "Memory_ProxyBinders", "Memory_DeathRecipients",
                                    "Memory_ParcelMemory", "Memory_ParcelCount"],
                                   "Binder là kênh app liên lạc với dịch vụ hệ thống và app khác: số kết nối, dữ liệu gửi qua"),
    "Kết nối mã hóa": (["Memory_OpenSSLSockets"], "Số kết nối mạng mã hóa đang mở"),
    "WebView": (["Memory_WebViews"], "Khung trình duyệt nhúng trong app, adware hay dùng để hiện quảng cáo"),
}
CLASS_NAMES = {
    "Benign": "Sạch", "Trojan": "Trojan", "Spyware": "Phần mềm gián điệp", "Ransomware": "Mã độc tống tiền",
    "Riskware": "Riskware", "Adware": "Adware", "Zero_Day": "Zero-day (mới, chưa rõ loại)",
    "Trojan_Spy": "Trojan gián điệp", "Trojan_SMS": "Trojan SMS", "No_Category": "Chưa phân loại",
    "Trojan_Dropper": "Trojan dropper", "PUA": "Ứng dụng không mong muốn (PUA)", "Backdoor": "Backdoor",
    "Scareware": "Scareware", "FileInfector": "File infector", "Trojan_Banker": "Trojan ngân hàng",
}


def class_name(label: str) -> str:
    return CLASS_NAMES.get(label, label)


def measure_deviation(stats, row, cols):
    """Return reference deviations and a normalized score between zero and one."""
    items = []
    for c in cols:
        if pd.isna(row.get(c)):
            continue
        value = float(row[c])
        s = stats.get(c)
        median = z = None
        if s is not None:
            median = s["median"]
            # Floor the reference spread to avoid division by zero.
            scale = max(s["iqr"], (s["p95"] - median) / 1.65, 1.0)
            z = round(abs(value - median) / scale, 2)
        items.append({"ten": c, "gia_tri": value, "trung_vi": median, "do_lech": z})
    score = max((i["do_lech"] for i in items if i["do_lech"] is not None), default=None)
    items.sort(key=lambda i: i["do_lech"] if i["do_lech"] is not None else -1, reverse=True)
    return (min(score / 6, 1.0) if score is not None else None), items


def top_classes(model_pack: dict, X: np.ndarray, k: int = 3) -> list[dict]:
    p = model_pack["model"].predict_proba(X)[0]
    order = np.argsort(-p)[:k]
    return [{"ma": model_pack["labels"][i], "ten": class_name(model_pack["labels"][i]), "p": round(float(p[i]), 4)}
            for i in order]


def predict_windows(row, source, *, live=False):
    binary, multi = INFERENCE_MODELS["windows_sach_doc"], INFERENCE_MODELS["windows_loai"]
    X = row[binary["features"]].values.reshape(1, -1).astype("float32")
    malware_probability = float(binary["model"].predict_proba(X)[0][1])
    X_type = row[multi["features"]].values.reshape(1, -1).astype("float32")
    class_predictions = top_classes(multi, X_type, 4)
    malware_classes = [l for l in class_predictions if l["ma"] != "Benign"][:3]
    groups = []
    features = WINDOWS_FEATURES if live else binary["features"]
    for plugin, (label, description) in WINDOWS_GROUPS.items():
        cols = [c for c in features if c.startswith(plugin + ".")]
        score, items = measure_deviation(STATS.get("windows", {}), row, cols)
        groups.append({"ma": plugin, "ten": label, "mo_ta": description,
                     "muc": round(score, 3) if score is not None else None, "chi_so": items if live else items[:4]})
    ground_truth = row.get("loai", None)
    family = row.get("ho")
    family = family if isinstance(family, str) and family else None
    is_malware = bool(malware_probability >= 0.5)
    return {
        "nen_tang": "windows", "nguon": source,
        "sach_doc": {"co": True, "doc": is_malware, "tin_cay": round(malware_probability if is_malware else 1 - malware_probability, 4)},
        "loai": class_predictions if live else malware_classes if is_malware else [],
        "xac_suat_doc": malware_probability,
        "nhan_that": class_name(ground_truth) if ground_truth else None,
        "ho": family,
        "dung": bool(is_malware == (ground_truth != "Benign")) if ground_truth else None,
        "khoi": groups,
        "chua_thay": True,
    }


WINDOWS_FEATURES = [c for c in WINDOWS_DATA.columns if "." in c]


@lru_cache(maxsize=1)
def windows_training_ranges():
    # Reproduce the grouped split in training/windows_malmem.py.
    groups = np.where(WINDOWS_DATA["Class"].eq("Malware"), windows_category_parts.str[2],
                      "benign_" + WINDOWS_DATA.index.astype(str))
    split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, _ = next(split.split(WINDOWS_DATA, groups=groups))
    train = WINDOWS_DATA.iloc[train_idx][WINDOWS_FEATURES]
    return train.min(), train.max(), len(train)


def score_windows(features: dict[str, float | None], sha: str | None, filename: str,
                  true_label: str | None = None) -> dict:
    if set(features) != set(WINDOWS_FEATURES):
        raise ValueError("Volatility output does not match the 55 CIC-MalMem-2022 columns.")
    values = {c: features[c] for c in WINDOWS_FEATURES}
    row = pd.Series(values, dtype="float64")
    if true_label:
        # Only label the run when its content is known independently (built-in or allowlisted clean sample).
        row["loai"] = true_label
    r = predict_windows(row, "Đo trực tiếp RAM trên máy ảo Windows bằng Volatility 3",
                        live=True)
    lower, upper, size = windows_training_ranges()
    ranges = {}
    outside = []
    measured = 0
    for c, value in values.items():
        mn, mx = float(lower[c]), float(upper[c])
        ranges[c] = {"min": mn, "max": mx}
        if value is not None:
            measured += 1
            if not mn <= value <= mx:
                outside.append(c)
    r.update(ma_bam=sha, ten=filename, chua_thay=None, so_do_windows=values,
             ghi_chu_dac_trung=FEATURE_NOTES,
             khoang_huan_luyen={"so_dong": size, "so_da_do": measured,
                               "ngoai_khoang": outside, "cac_khoang": ranges},
             ghi_chu="Điểm mô hình trên Windows 11 và Volatility 3 dùng để đối chiếu với dữ liệu gốc. "
                     "Các ô chưa đo được được truyền vào XGBoost dưới dạng giá trị thiếu.")
    return r


def predict_android_ram(row, source, ground_truth=None, family=None, held_out=True, *, live=False):
    features = INFERENCE_MODELS["android_loai_chi_RAM"]["features"]
    missing = np.nan if live else 0
    X = np.array([[row[c] if row.get(c) is not None else missing for c in features]], dtype="float32")
    class_predictions = top_classes(INFERENCE_MODELS["android_loai_chi_RAM"], X, 3)
    groups = []
    for label, (cols, description) in ANDROID_GROUPS.items():
        cols = [c for c in cols if c in features]
        score, items = measure_deviation(STATS.get("android_ram", {}), row, cols)
        groups.append({"ma": label, "ten": label, "mo_ta": description, "muc": round(score, 3) if score is not None else None,
                     "chi_so": items if live else items[:4]})
    return {
        "nen_tang": "android_ram", "nguon": source,
        "sach_doc": {"co": False, "ly_do": "Bộ dữ liệu RAM Android hiện chỉ có mã độc, nên phần này chỉ đoán loại."},
        "loai": class_predictions, "chac_chan": bool(class_predictions[0]["p"] >= CONFIDENCE_THRESHOLD),
        "nhan_that": class_name(ground_truth) if ground_truth else None, "ho": family,
        "dung": bool(class_predictions[0]["ten"] == class_name(ground_truth)) if ground_truth else None,
        "khoi": groups, "chua_thay": bool(held_out),
    }


def score_apk(measurements: dict[str, int | None], sha: str, filename: str, package: str) -> dict:
    r = predict_android_ram(measurements, f"Đo trực tiếp trên máy ảo Android ({package})", live=True)
    metrics = [i for group in r["khoi"] for i in group["chi_so"] if i["do_lech"] is not None]
    largest_deviation = max(metrics, key=lambda i: i["do_lech"], default=None)
    deviation_profile = None
    if largest_deviation is not None:
        deviation_profile = {"diem": round(min(largest_deviation["do_lech"] / 6, 1.0), 3),
                   "so_chi_so": len(metrics), "chi_so_lon_nhat": largest_deviation["ten"]}
    r["sach_doc"]["ly_do"] = ("Mô hình RAM Android học từ tập dữ liệu chỉ có mã độc và dự đoán loại mã độc. "
                             "Với app sạch, loại dự đoán và độ tin cậy chỉ mang tính tham khảo.")
    r.update(ma_bam=sha, ten=filename, goi=package, so_do_ram=measurements, do_lech_ho_so=deviation_profile, chua_thay=None)
    return r


def predict_android_static(malware_probability, source, ground_truth=None, held_out=True):
    is_malware = bool(malware_probability >= 0.5)
    return {
        "nen_tang": "android_static", "nguon": source,
        "sach_doc": {"co": True, "doc": is_malware, "tin_cay": round(malware_probability if is_malware else 1 - malware_probability, 4)},
        "loai": [], "nhan_that": ("Sạch" if ground_truth == "Benign" else f"Mã độc ({ground_truth})") if ground_truth else None,
        "dung": bool(is_malware == (ground_truth != "Benign")) if ground_truth else None,
        "khoi": [], "chua_thay": bool(held_out),
        "ghi_chu": "Đặc trưng tĩnh lấy từ file cài đặt; tác giả bộ dữ liệu không công bố tên nên không giải thích được từng đặc trưng.",
    }


# Local API. Payload and dataset keys support the existing evidence format.
MAX_LOOKUP = 1024 * 1024 * 1024  # hash lookup only; the file is never executed
UPLOAD_LIMITS = {"/api/lookup": MAX_LOOKUP, "/api/analyze/android": MAX_APK,
                  "/api/analyze/windows": MAX_EXE}
MULTIPART_OVERHEAD = 64 * 1024


def size_error(limit):
    return f"The file exceeds {limit // (1024 * 1024)} MiB."


class UploadGuard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if origin is not None and origin != f"http://{headers.get('host')}":
            return await JSONResponse({"detail": "Requests must come from the local demo page."}, 403)(scope, receive, send)
        limit = UPLOAD_LIMITS.get(scope["path"].rstrip("/"))
        if limit is None:
            return await self.app(scope, receive, send)
        max_body = limit + MULTIPART_OVERHEAD
        try:
            length = int(headers.get("content-length", "0"))
            if length < 0:
                raise ValueError
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length."}, 400)(scope, receive, send)
        if length > max_body:
            return await JSONResponse({"detail": size_error(limit)}, 413)(scope, receive, send)

        received = 0
        too_large = False

        async def read_limited():
            nonlocal received, too_large
            message = await receive()
            received += len(message.get("body", b""))
            if received > max_body:
                too_large = True
                # Starlette closes partial multipart files after this exception.
                raise MultiPartException(size_error(limit))
            return message

        async def send_response(message):
            if not too_large:
                await send(message)
            elif message["type"] == "http.response.start":
                await JSONResponse({"detail": size_error(limit)}, 413)(scope, receive, send)

        await self.app(scope, read_limited, send_response)


app = FastAPI(title="MemScope")
app.add_middleware(UploadGuard)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


@app.exception_handler(Full)
async def queue_full(request, exc):
    return JSONResponse({"detail": "The VM queue is full. Try again later."}, 503)


def safe_filename(filename: str | None) -> str:
    name = (filename or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join("_" if c in '<>:"|?*' else c for c in name
                   if unicodedata.category(c) not in {"Cc", "Cf"}).strip(" .")
    name = name or "file"
    if PureWindowsPath(name).is_reserved():
        name = "_" + name
    suffix = Path(name).suffix[:16]
    if len(name) > 180:
        name = name[:180 - len(suffix)] + suffix
    return name


def check_file_size(file: UploadFile, limit: int) -> None:
    size = file.size
    if size is None:
        position = file.file.tell()
        size = file.file.seek(0, os.SEEK_END)
        file.file.seek(position)
    if size > limit:
        raise HTTPException(413, size_error(limit))


@contextmanager
def temporary_upload(file, suffix):
    path = None
    try:
        file.file.seek(0)
        with tempfile.NamedTemporaryFile(prefix="ie105-", suffix=suffix, delete=False) as tmp:
            path = Path(tmp.name)
            shutil.copyfileobj(file.file, tmp)
        yield path
    except BaseException:
        if path is not None:
            path.unlink(missing_ok=True)
        raise


def find_hard_presets():
    """Flag preset misclassifications and low-confidence predictions at startup."""
    hard = {}
    X = WINDOWS_PRESETS[INFERENCE_MODELS["windows_sach_doc"]["features"]].values.astype("float32")
    p = INFERENCE_MODELS["windows_sach_doc"]["model"].predict_proba(X)[:, 1]
    X_type = WINDOWS_PRESETS[INFERENCE_MODELS["windows_loai"]["features"]].values.astype("float32")
    type_scores = INFERENCE_MODELS["windows_loai"]["model"].predict_proba(X_type)
    for r, malware_score, type_score in zip(WINDOWS_PRESETS.itertuples(), p, type_scores):
        incorrect = (malware_score >= 0.5) != (r.loai != "Benign") or INFERENCE_MODELS["windows_loai"]["labels"][type_score.argmax()] != r.loai
        hard[("windows", r.id)] = bool(incorrect or max(malware_score, 1 - malware_score) < 0.6 or type_score.max() < 0.6)
    X = ANDROID_RAM_PRESETS[INFERENCE_MODELS["android_loai_chi_RAM"]["features"]].values.astype("float32")
    for r, pr in zip(ANDROID_RAM_PRESETS.itertuples(), INFERENCE_MODELS["android_loai_chi_RAM"]["model"].predict_proba(X)):
        hard[("android_ram", r.id)] = bool(INFERENCE_MODELS["android_loai_chi_RAM"]["labels"][pr.argmax()] != r.loai or pr.max() < 0.6)
    X = ANDROID_STATIC_PRESETS[INFERENCE_MODELS["android_sach_doc_static"]["features"]].values.astype("float32")
    for r, pr in zip(ANDROID_STATIC_PRESETS.itertuples(), INFERENCE_MODELS["android_sach_doc_static"]["model"].predict_proba(X)[:, 1]):
        hard[("android_static", r.id)] = bool((pr >= 0.5) != (r.nhan != "Benign") or max(pr, 1 - pr) < 0.6)
    return hard


HARD_PRESETS = find_hard_presets()


@app.get("/api/samples/{platform}")
def list_samples(platform: str):
    return [dict(m, kho=HARD_PRESETS.get((platform, m["id"]), False)) for m in sample_list(platform)]


def sample_list(platform: str):
    if platform == "windows":
        return [{"id": r.id, "ten": f"{class_name(r.loai)}" + (f" ({r.ho})" if isinstance(r.ho, str) and r.ho else ""),
                 "nhan": class_name(r.loai)} for r in WINDOWS_PRESETS.itertuples()]
    if platform == "android_ram":
        return [{"id": r.id, "ten": f"{class_name(r.loai)} ({r.Family})", "nhan": class_name(r.loai)} for r in ANDROID_RAM_PRESETS.itertuples()]
    if platform == "android_static":
        return [{"id": r.id, "ten": "App sạch" if r.nhan == "Benign" else f"Mã độc ({r.nhan})",
                 "nhan": "Sạch" if r.nhan == "Benign" else "Mã độc"} for r in ANDROID_STATIC_PRESETS.itertuples()]
    raise HTTPException(404, "Unknown platform.")


@app.get("/api/samples/{platform}/{sample_id}")
def analyze_preset(platform: str, sample_id: str):
    if platform == "windows":
        r = WINDOWS_PRESETS[WINDOWS_PRESETS.id == sample_id]
        if r.empty:
            raise HTTPException(404, "Sample not found.")
        row = r.iloc[0]
        out = predict_windows(row, "Mẫu soạn sẵn trong tập test")
        family = f" ({row['ho']})" if isinstance(row["ho"], str) and row["ho"] else ""
        out.update(id=sample_id, ma_bam=row["ma_bam"] if isinstance(row["ma_bam"], str) else "",
                   ten=("Máy Windows sạch" if row["loai"] == "Benign" else class_name(row["loai"]) + family),
                   nguon=("Bản chụp RAM máy sạch trong tập test, mô hình chưa thấy" if row["loai"] == "Benign" else
                          f"Lần chụp RAM thứ {row['Category'].rsplit('-', 1)[-1].replace('.raw', '')} của mẫu này, "
                          "trong tập test, mô hình chưa thấy"))
        return out
    if platform == "android_ram":
        r = ANDROID_RAM_PRESETS[ANDROID_RAM_PRESETS.id == sample_id]
        if r.empty:
            raise HTTPException(404, "Sample not found.")
        row = r.iloc[0]
        out = predict_android_ram(row, "Mẫu soạn sẵn trong tập test", row["loai"], row["Family"])
        out.update(id=sample_id, ma_bam=row["Hash"], ten=f"{row['Family']} ({'sau' if row['sau_reboot'] else 'trước'} khởi động lại)")
        return out
    if platform == "android_static":
        r = ANDROID_STATIC_PRESETS[ANDROID_STATIC_PRESETS.id == sample_id]
        if r.empty:
            raise HTTPException(404, "Sample not found.")
        row = r.iloc[0]
        X = row[INFERENCE_MODELS["android_sach_doc_static"]["features"]].values.reshape(1, -1).astype("float32")
        p = float(INFERENCE_MODELS["android_sach_doc_static"]["model"].predict_proba(X)[0][1])
        out = predict_android_static(p, "Mẫu soạn sẵn, mô hình chưa thấy", row["nhan"])
        out.update(id=sample_id, ma_bam=row["ma_bam"], ten="Ứng dụng Android")
        return out
    raise HTTPException(404, "Unknown platform.")


def file_hashes(file: UploadFile) -> tuple[str, str, int]:
    file.file.seek(0)
    sha, md5_sum = hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    size = 0
    while chunk := file.file.read(1024 * 1024):
        size += len(chunk)
        sha.update(chunk)
        md5_sum.update(chunk)
    return sha.hexdigest(), md5_sum.hexdigest(), size


@app.post("/api/lookup")
def lookup(file: UploadFile = File(...)):
    """Hash an upload and look up its dataset records without executing it."""
    check_file_size(file, MAX_LOOKUP)
    filename = safe_filename(file.filename)
    sha256, md5, size = file_hashes(file)
    found = []
    w = WINDOWS_DATA[WINDOWS_DATA["ma_bam"].isin([sha256, md5])]
    if not w.empty:
        row = w.iloc[0]
        r = predict_windows(row, f"Có trong bộ MalMem-2022 ({len(w)} bản chụp RAM của mẫu này)")
        r["chua_thay"] = bool(row["ma_bam"] in TEST["windows"])
        r.update(ma_bam=row["ma_bam"], ten=filename)
        found.append(r)
    a = ANDROID_RAM_DATA[ANDROID_RAM_DATA["hash_l"] == sha256]
    if not a.empty:
        row = a.iloc[0]
        r = predict_android_ram(row, f"Có trong bộ AndMal2020, phần số đo RAM ({len(a)} lần đo)", row["loai"],
                                row["Family"], sha256 in TEST["android_ram"])
        r.update(ma_bam=sha256, ten=filename)
        found.append(r)
    s = ANDROID_STATIC_DATA[ANDROID_STATIC_DATA["hash_l"] == sha256]
    if not s.empty:
        row = s.iloc[0]
        r = predict_android_static(float(row["xac_suat_doc"]), "Có trong bộ AndMal2020, phần đặc trưng tĩnh",
                                   row["nhan"], not bool(row["trong_tap_train"]))
        r.update(ma_bam=sha256, ten=filename)
        found.append(r)
    return {"ten_file": filename, "kich_thuoc": size, "sha256": sha256, "md5": md5, "ket_qua": found}


def validate_live_sample(platform: str, sha256: str, md5: str = "") -> dict:
    if (WINDOWS_DATA["ma_bam"].isin({sha256, md5} - {""}).any()
            or ANDROID_RAM_DATA["hash_l"].eq(sha256).any()
            or ANDROID_STATIC_DATA.loc[ANDROID_STATIC_DATA["nhan"].ne("Benign"), "hash_l"].eq(sha256).any()):
        raise SampleNotAllowed("The file matches a known malware dataset record.")
    return require_allowed_sample(platform, sha256)


def validate_upload(platform: str, file: UploadFile) -> tuple[str, dict]:
    sha, md5, _ = file_hashes(file)
    try:
        return sha, validate_live_sample(platform, sha, md5)
    except SampleNotAllowed as exc:
        raise HTTPException(422, str(exc)) from exc


ANDROID_JOBS = AndroidJobs(HERE / "results", score_apk, validate_live_sample)
WINDOWS_JOBS = WindowsJobs(HERE / "results", score_windows, validate_live_sample)


@app.post("/api/analyze/android", status_code=202)
def analyze_android(file: UploadFile = File(...), duration: int = Query(40, ge=30, le=45)):
    filename = safe_filename(file.filename)
    if Path(filename).suffix.lower() != ".apk":
        raise HTTPException(400, "Select an Android .apk file.")
    check_file_size(file, MAX_APK)
    validate_upload("android", file)
    if not is_zipfile(file.file):
        raise HTTPException(400, "The file does not have a valid APK structure.")
    with temporary_upload(file, ".apk") as path:
        job_id = ANDROID_JOBS.submit(path, filename, duration)
    return {"job_id": job_id}


@app.post("/api/analyze/windows", status_code=202)
def analyze_windows(file: UploadFile | None = File(None), sample: str | None = Query(None)):
    if file is None:
        if sample not in BUILTIN_SAMPLES:
            raise HTTPException(400, "Select a clean .exe, Notepad, or the Windows baseline.")
        return {"job_id": WINDOWS_JOBS.submit(BUILTIN_SAMPLES[sample], builtin=sample)}
    filename = safe_filename(file.filename)
    if sample is not None or Path(filename).suffix.lower() != ".exe":
        raise HTTPException(400, "Select one Windows .exe file.")
    check_file_size(file, MAX_EXE)
    sha, sample_info = validate_upload("windows", file)
    with temporary_upload(file, ".upload") as path:
        job_id = WINDOWS_JOBS.submit(sample_info.get("filename", filename), path=path, sha=sha)
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = ANDROID_JOBS.get(job_id) or WINDOWS_JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "Analysis job not found.")
    return job


app.mount("/static", StaticFiles(directory=HERE / "web"), name="static")


@app.get("/")
def index():
    return FileResponse(HERE / "web" / "index.html")


if __name__ == "__main__":
    if __package__:
        from .launch import main
    else:
        from launch import main
    raise SystemExit(main(app))
