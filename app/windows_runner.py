"""Measure Windows guest memory using VMware Workstation and Volatility 3."""

import hashlib
import json
import locale
import logging
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
from pathlib import Path, PureWindowsPath
from queue import Full
from threading import Lock
from uuid import uuid4

if __package__:
    from .windows_features import PLUGINS, extract_features
else:
    from windows_features import PLUGINS, extract_features


VMX = Path(os.environ.get("MEMSCOPE_VMX", r"D:\MayAo\Win11-IE105\Win11-IE105.vmx")).resolve()
VMRUN = Path(os.environ.get("MEMSCOPE_VMRUN") or shutil.which("vmrun") or
             r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")
VOL = Path(__file__).resolve().parents[1] / ".venv-vol"
VOL_PYTHON = VOL / "Scripts" / "python.exe"
SNAPSHOT = "sach"
MEASUREMENT_DELAY = 60
MAX_EXE = 64 * 1024 * 1024
SAFE_GUEST_NAME = re.compile(r"[A-Za-z0-9._-]{1,100}\.exe", re.IGNORECASE)
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
BUILTIN_SAMPLES = {"baseline": "Clean Windows baseline", "notepad": "Guest Notepad"}
STEPS = {
    "khoi_phuc": "Restore the clean snapshot",
    "khoi_dong": "Boot and wait for VMware Tools",
    "chep": "Copy the file to the guest",
    "chay": "Run the sample and wait 60 seconds",
    "chup_ram": "Suspend the guest and locate its memory image",
    "volatility": "Extract features with Volatility 3",
    "cham_diem": "Run the Windows models",
    "don": "Restore the clean snapshot",
    "luu": "Save evidence",
}
LOGGER = logging.getLogger(__name__)


class WindowsError(RuntimeError):
    pass


def run_command(command, *, timeout, env=None):
    try:
        proc = subprocess.run(
            [str(part) for part in command], timeout=timeout, env=env, capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for name in ("stdout", "stderr"):
            data = getattr(proc, name)
            try:
                value = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                value = data.decode(locale.getencoding(), errors="replace")
            setattr(proc, name, value)
        return proc
    except FileNotFoundError:
        raise WindowsError(f"Could not find {Path(command[0]).name}.") from None
    except subprocess.TimeoutExpired:
        raise WindowsError(f"{Path(command[0]).name} timed out after {timeout} seconds.") from None


def output_tail(proc):
    return (proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}")[-1000:]


class WindowsVM:
    def vmrun(self, command, *arguments, guest=False, timeout=90):
        auth = ("-gu", "test", "-gp", os.environ.get("MEMSCOPE_WINDOWS_PASSWORD", os.environ.get("IE105_WINDOWS_PASSWORD", "ie105test"))) if guest else ()
        proc = run_command([VMRUN, "-T", "ws", *auth, command, VMX, *arguments], timeout=timeout)
        if proc.returncode:
            raise WindowsError(f"VMware could not run {command}. {output_tail(proc)}")
        return proc.stdout.strip()

    def is_running(self):
        proc = run_command([VMRUN, "-T", "ws", "list"], timeout=20)
        if proc.returncode:
            raise WindowsError(f"Could not connect to VMware. {output_tail(proc)}")
        return any(os.path.normcase(path.strip().strip('"')) == os.path.normcase(str(VMX))
                   for path in proc.stdout.splitlines()[1:])

    def check(self):
        if not VMRUN.is_file():
            raise WindowsError("VMware Workstation vmrun.exe was not found.")
        if not VMX.is_file():
            raise WindowsError("The Windows VMX file was not found.")
        if self.is_running():
            raise WindowsError("Power off Win11-IE105 before measuring memory.")
        if SNAPSHOT not in {line.strip() for line in self.vmrun("listSnapshots").splitlines()[1:]}:
            raise WindowsError("Win11-IE105 has no clean snapshot named sach.")
        if not VOL_PYTHON.is_file() or not (VOL / "Lib/site-packages/volatility3").is_dir():
            raise WindowsError("Install Volatility 3 in .venv-vol first.")
        self.check_isolation()

    def check_isolation(self):
        text = VMX.read_text(encoding="utf-8-sig", errors="replace")
        cfg = dict(re.findall(r'^\s*([\w.:]+)\s*=\s*"([^"]*)"', text, re.MULTILINE))
        cfg = {key.lower(): value.lower() for key, value in cfg.items()}
        for key, value in cfg.items():
            if re.fullmatch(r"ethernet\d+\.present", key) and value == "true":
                if cfg.get(key.replace(".present", ".startconnected")) != "false":
                    raise WindowsError("Disconnect the guest network adapters before measuring memory.")
            if re.fullmatch(r"sharedfolder\d+\.enabled", key) and value == "true":
                raise WindowsError("Disable guest shared folders before measuring memory.")

    def wait_for_tools(self):
        deadline = time.monotonic() + 240
        last_error = ""
        while time.monotonic() < deadline:
            try:
                state = self.vmrun("checkToolsState", timeout=15)
                # Some vmrun releases report "installed" while Tools are running. Verify guest processes.
                if state.strip().lower() in ("running", "installed"):
                    processes = self.vmrun("listProcessesInGuest", guest=True, timeout=15)
                    if "explorer.exe" in processes.lower():
                        return
            except WindowsError as exc:
                # VMware Tools can briefly disconnect while Windows signs in.
                last_error = str(exc)
            time.sleep(4)
        raise WindowsError(("VMware Tools or the guest sign-in session was unavailable after 240 seconds. "
                          + last_error).strip())

    def memory_images(self):
        ram = {}
        for path in VMX.parent.glob("*.vmem"):
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            if stat.st_size:
                ram[path] = (stat.st_size, stat.st_mtime_ns)
        return ram

    def capture_memory(self, previous_images):
        self.vmrun("suspend", "hard", timeout=180)
        ram = self.memory_images()
        candidates = [p for p, stat in ram.items() if previous_images.get(p) != stat]
        paired = [p for p in candidates if p.with_suffix(".vmss").is_file()]
        candidates = paired or candidates
        if len(candidates) != 1:
            raise WindowsError(f"Expected one new suspend memory image, found {len(candidates)}.")
        return candidates[0]

    def restore(self, previous_images):
        if self.is_running():
            self.vmrun("stop", "hard", timeout=120)
        self.vmrun("revertToSnapshot", SNAPSHOT, timeout=180)
        # VMware owns snapshot memory and suspend files. Let it clean them up.
        if any(previous_images.get(path) != stat for path, stat in self.memory_images().items()):
            raise WindowsError("VMware left a memory image behind after restoring the snapshot.")


@contextmanager
def lock_vm():
    if os.name != "nt" or not VMX.is_file():
        raise WindowsError("The Windows guest VMX was not found on the Windows host.")
    import msvcrt

    with (VMX.parent / "ie105-do-ram.lock").open("a+b") as lock:
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise WindowsError("Another process is using the Windows guest.") from None
        yield


def read_volatility(path, report_progress):
    env = dict(os.environ, APPDATA=str(VOL), PYTHONUTF8="1")
    # Keep Microsoft symbols and cache inside the Volatility environment.
    entry = "import sys; sys.argv[0]='vol'; from volatility3.cli import main; main()"
    rows = {}
    plugin_log = {}
    for key, plugin in PLUGINS.items():
        report_progress(f"Running {plugin}.")
        start = time.perf_counter()
        try:
            proc = run_command([VOL_PYTHON, "-c", entry, "-q", "-r", "json", "-f", path, plugin],
                        timeout=600, env=env)
            if proc.returncode:
                raise WindowsError(output_tail(proc))
            rows[key] = json.loads(proc.stdout)
            if not isinstance(rows[key], list):
                raise WindowsError("The plugin returned invalid JSON structure.")
            if key in ("pslist", "dlllist", "handles", "ldrmodules", "modules", "svcscan") and not rows[key]:
                raise WindowsError("The plugin found no memory records.")
            plugin_log[key] = {"so_dong": len(rows[key])}
        except (WindowsError, ValueError) as exc:
            if key != "psxview":
                raise WindowsError(f"{plugin} failed. {exc}") from exc
            rows[key] = None
            plugin_log[key] = {"loi": str(exc)}
        plugin_log[key]["thoi_gian"] = round(time.perf_counter() - start, 2)
    return extract_features(rows), plugin_log, {str(r["ImageFileName"]).lower() for r in rows["pslist"]}


class WindowsJobs:
    def __init__(self, results_dir, score, validate_sample):
        self.results_dir = results_dir
        self.score = score
        self.validate_sample = validate_sample
        self.jobs = {}
        self.lock = Lock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="windows")

    def submit(self, filename: str, path: Path | None = None, sha: str | None = None,
             builtin: str | None = None) -> str:
        job_id = uuid4().hex
        job = {
            "job_id": job_id, "ten_file": filename, "sha256": sha, "mau": builtin, "trang_thai": "cho",
            "buoc": [{"ma": step_id, "ten": label, "trang_thai": "cho", "thoi_gian": None, "ghi_chu": ""}
                     for step_id, label in STEPS.items()],
            "ket_qua": None, "loi": None, "tep_ket_qua": None, "thoi_gian": None,
        }
        with self.lock:
            if sum(j["trang_thai"] in {"cho", "dang_chay"} for j in self.jobs.values()) >= 4:
                raise Full
            self.jobs[job_id] = job
            try:
                self.pool.submit(self.run, job, path)
            except RuntimeError:
                del self.jobs[job_id]
                raise
            done = [key for key, old in self.jobs.items() if old["trang_thai"] in {"xong", "loi"}]
            for key in done[:-64]:
                del self.jobs[key]
        return job_id

    def get(self, job_id):
        with self.lock:
            job = deepcopy(self.jobs.get(job_id))
        if job:
            for step in job["buoc"]:
                started = step.pop("_bat_dau", None)
                if step["trang_thai"] == "dang_chay":
                    step["thoi_gian"] = round(time.perf_counter() - started, 2)
        return job

    @contextmanager
    def step(self, job, step_id):
        step = next(s for s in job["buoc"] if s["ma"] == step_id)
        start = time.perf_counter()

        def update(text):
            with self.lock:
                step["ghi_chu"] = text

        with self.lock:
            step.update(trang_thai="dang_chay", _bat_dau=start)
        try:
            yield update
        except Exception as exc:
            with self.lock:
                step.update(trang_thai="loi", ghi_chu=str(exc), thoi_gian=round(time.perf_counter() - start, 2))
            raise
        else:
            with self.lock:
                step.update(trang_thai="xong", thoi_gian=round(time.perf_counter() - start, 2))

    def measure_memory(self, job, vm, path, evidence):
        with self.step(job, "khoi_phuc") as note:
            vm.check()
            vm.vmrun("revertToSnapshot", SNAPSHOT, timeout=180)
            previous_images = vm.memory_images()
            note("Restored snapshot sach.")
        try:
            with self.step(job, "khoi_dong") as note:
                vm.check_isolation()
                vm.vmrun("start", "nogui", timeout=180)
                vm.wait_for_tools()
                note("VMware Tools are running.")
            args = ()
            target = r"C:\Windows\System32\notepad.exe" if job["mau"] == "notepad" else None
            true_label = None
            if path is not None:
                with self.step(job, "chep") as note:
                    with path.open("rb") as source:
                        sha = hashlib.file_digest(source, "sha256").hexdigest()
                    if sha != job["sha256"]:
                        raise WindowsError("The file SHA-256 changed after upload.")
                    sample_info = self.validate_sample("windows", sha)
                    name = PureWindowsPath(sample_info.get("filename", job["ten_file"])).name
                    if not SAFE_GUEST_NAME.fullmatch(name) or name.split(".")[0].upper() in RESERVED_NAMES:
                        raise WindowsError("The guest file name must be a plain .exe name (letters, digits, . _ -).")
                    true_label = "Benign" if sample_info.get("name") else None
                    args = tuple(sample_info.get("arguments", ()))
                    target = rf"C:\Users\test\{name}"
                    vm.vmrun("copyFileFromHostToGuest", path, target, guest=True)
                    note(f"Copied {name}.")
            else:
                with self.lock:
                    job["buoc"][2].update(trang_thai="bo_qua", ghi_chu="The sample is built into the guest or this is a baseline run.")
            with self.step(job, "chay") as note:
                if target:
                    vm.vmrun("runProgramInGuest", "-noWait", "-activeWindow", target, *args, guest=True)
                else:
                    note("Waiting 60 seconds after VMware Tools readiness for a baseline reading.")
                time.sleep(MEASUREMENT_DELAY)
            with self.step(job, "chup_ram") as note:
                ram = vm.capture_memory(previous_images)
                evidence["anh_ram"] = {"ten": ram.name, "kich_thuoc": ram.stat().st_size,
                                       "co_vmss": ram.with_suffix(".vmss").is_file()}
                note(f"Located {ram.name}.")
            with self.step(job, "volatility") as note:
                evidence["dac_trung"], evidence["plugins"], processes = read_volatility(ram, note)
                if target:
                    name = PureWindowsPath(target).name.lower()
                    evidence["tien_trinh_khi_chup"] = name in processes
                n_measured = sum(v is not None for v in evidence["dac_trung"].values())
                status = ""
                if target:
                    status = (" The sample process was present in memory." if evidence["tien_trinh_khi_chup"]
                              else " PsList did not find the sample process in the capture.")
                note(f"Measured {n_measured}/{len(evidence['dac_trung'])} features.{status}")
            with self.step(job, "cham_diem") as note:
                if job["mau"]:
                    true_label = "Benign"  # built-in baseline or Notepad run on the clean snapshot
                evidence["ket_qua"] = self.score(evidence["dac_trung"], job["sha256"], job["ten_file"], true_label)
                if target and not evidence.get("tien_trinh_khi_chup"):
                    evidence["ket_qua"]["canh_bao"] = ("PsList không thấy tiến trình của file trong ảnh RAM; "
                                                      "điểm này phản ánh trạng thái chung của máy ảo, chưa xác minh được là của file.")
                malware_probability = f"{evidence['ket_qua']['xac_suat_doc']:.2%}"
                note(f"Model malware probability: {malware_probability}.")
        finally:
            with self.step(job, "don") as note:
                vm.restore(previous_images)
                note("Restored the clean snapshot and checked for leftover memory images.")

    def run(self, job, path):
        start = time.perf_counter()
        when = datetime.now().astimezone()
        errors = []
        evidence = {"thoi_diem": when.isoformat(), "giay_cho": MEASUREMENT_DELAY, "ket_qua": None}
        with self.lock:
            job["trang_thai"] = "dang_chay"
        try:
            vm = WindowsVM()
            with lock_vm():
                self.measure_memory(job, vm, path, evidence)
        except Exception as exc:
            errors.append(str(exc))
            if not isinstance(exc, (WindowsError, OSError)):
                LOGGER.exception("Windows job %s failed", job["job_id"])
        if path is not None:
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                errors.append(f"Could not remove the temporary upload. {exc}")
        with self.lock:
            for step in job["buoc"][:-1]:
                if step["trang_thai"] == "cho":
                    step.update(trang_thai="bo_qua", ghi_chu="A preceding step did not complete.")

        dest = self.results_dir / f"windows_{when.date()}_{job['job_id']}.json"
        try:
            with self.step(job, "luu") as note:
                snapshot = self.get(job["job_id"])
                snapshot["buoc"][-1].update(trang_thai="xong", ghi_chu=dest.name)
                error_steps = [s["ghi_chu"] for s in snapshot["buoc"] if s["trang_thai"] == "loi"]
                errors = list(dict.fromkeys(error_steps + errors))
                self.results_dir.mkdir(parents=True, exist_ok=True)
                temp = dest.with_suffix(".tmp")
                try:
                    temp.write_text(json.dumps(
                        {**snapshot, **evidence, "trang_thai": "loi" if errors else "xong",
                         "tep_ket_qua": dest.name, "loi": "\n".join(errors) or None,
                         "thoi_gian": round(time.perf_counter() - start, 2)},
                        ensure_ascii=False, indent=2, allow_nan=False,
                    ), encoding="utf-8")
                    temp.replace(dest)
                finally:
                    temp.unlink(missing_ok=True)
                note(dest.name)
        except Exception as exc:
            errors.append(f"Could not save the evidence. {exc}")
            if not isinstance(exc, (OSError, ValueError)):
                LOGGER.exception("Could not save Windows job %s", job["job_id"])
        with self.lock:
            job.update(trang_thai="loi" if errors else "xong", ket_qua=evidence["ket_qua"],
                       tep_ket_qua=dest.name if dest.is_file() else None, loi="\n".join(errors) or None,
                       thoi_gian=round(time.perf_counter() - start, 2))
