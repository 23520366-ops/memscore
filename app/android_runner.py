"""Measure APK memory usage in Android Emulator and track its steps."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
from queue import Full
import re
import shutil
import subprocess
import tempfile
from threading import Lock
import time
from uuid import uuid4
from zipfile import BadZipFile, ZipFile

if not __package__:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collection.meminfo_parser import parse_meminfo, to_andmal_row
if __package__:
    from .sample_policy import SampleNotAllowed
else:
    from sample_policy import SampleNotAllowed


STEPS = {
    "sha256": "Compute SHA-256",
    "may_ao": "Prepare Android Emulator",
    "cai_dat": "Install the app and identify its package",
    "chay": "Launch the app and run Monkey",
    "doc_ram": "Read memory measurements",
    "cham_diem": "Run the model",
    "go_app": "Uninstall the app",
    "luu": "Save evidence",
}
PACKAGE_NAME = re.compile(r"[a-zA-Z][\w]*(?:\.[a-zA-Z][\w]*)+", re.ASCII)
MAX_APK = 64 * 1024 * 1024
HIDE_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LOGGER = logging.getLogger(__name__)


# Lab AVD names (scripts/setup_android_emulator.py creates "memscope"; "ie105" is the original lab AVD).
LAB_AVDS = ("memscope", "ie105")
CLEAN_SNAPSHOT = os.environ.get("MEMSCOPE_ANDROID_SNAPSHOT", "sach")


class AndroidError(RuntimeError):
    pass


class WrongAVD(AndroidError):
    """A running emulator differs from the configured lab AVD."""


def run_command(exe, *args, timeout=30):
    try:
        return subprocess.run(
            [str(exe), *args], capture_output=True, encoding="utf-8", errors="replace",
            timeout=timeout, creationflags=HIDE_WINDOW,
        )
    except FileNotFoundError:
        raise AndroidError(f"Could not find {Path(exe).name} in the Android SDK.") from None


def output_tail(proc):
    return "\n".join(s.strip() for s in (proc.stderr, proc.stdout) if s.strip())[-1200:]


def error_message(exc):
    if isinstance(exc, subprocess.TimeoutExpired):
        return f"{Path(exc.cmd[0]).name} timed out after {exc.timeout} seconds."
    return str(exc) or type(exc).__name__


def read_ini(path):
    if not path.is_file():
        return {}
    return dict((key.strip(), value.strip()) for key, _, value in (
        line.partition("=") for line in path.read_text(encoding="utf-8-sig").splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    ))


@contextmanager
def lock_emulator():
    with (Path(tempfile.gettempdir()) / "ie105-android.lock").open("a+b") as lock:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AndroidError("Another process is using the Android Emulator.") from None
        yield


class AndroidSDK:
    def __init__(self):
        local = os.environ.get("LOCALAPPDATA")
        roots = dict.fromkeys(filter(None, (
            os.environ.get("ANDROID_SDK_ROOT"), os.environ.get("ANDROID_HOME"), r"D:\Android\Sdk",
            str(Path(local) / "Android" / "Sdk") if local else None,
        )))
        adb_name = "adb.exe" if os.name == "nt" else "adb"
        emulator_name = "emulator.exe" if os.name == "nt" else "emulator"
        candidates = [Path(root) for root in roots if (Path(root) / "platform-tools" / adb_name).is_file()]
        self.root = next((root for root in candidates if (root / "emulator" / emulator_name).is_file()),
                         next(iter(candidates), None))
        self.adb = self.root / "platform-tools" / adb_name if self.root else shutil.which(adb_name)
        emulator = self.root / "emulator" / emulator_name if self.root else None
        self.emulator = emulator if emulator and emulator.is_file() else shutil.which(emulator_name)

    def devices(self):
        if not self.adb:
            raise AndroidError("adb was not found in the Android SDK.")
        p = run_command(self.adb, "devices", timeout=15)
        if p.returncode:
            raise AndroidError(f"Could not list adb devices. {output_tail(p)}")
        devices = {}
        for line in p.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"emulator-\d+", parts[0]):
                devices[parts[0]] = parts[1]
        return devices

    def list_avds(self):
        if not self.emulator or not Path(self.emulator).is_file():
            raise AndroidError("Android Emulator was not found in the SDK.")
        p = run_command(self.emulator, "-list-avds", timeout=15)
        if p.returncode:
            raise AndroidError(f"Could not list Android virtual devices. {output_tail(p)}")
        return [name.strip() for name in p.stdout.splitlines() if name.strip()]

    def lab_avd(self):
        names = self.list_avds()
        for name in LAB_AVDS:
            if name in names:
                return name
        raise AndroidError("Create the lab AVD with scripts/setup_android_emulator.py or set MEMSCOPE_ANDROID_AVD.")

    def verify_system_image(self, avd):
        if not self.root:
            return
        avd_home = os.environ.get("ANDROID_AVD_HOME")
        user_home = os.environ.get("ANDROID_USER_HOME")
        emulator_home = os.environ.get("ANDROID_EMULATOR_HOME")
        sdk_home = os.environ.get("ANDROID_SDK_HOME")
        directories = (
            Path(avd_home) if avd_home else None,
            Path(emulator_home) / "avd" if emulator_home else None,
            Path(user_home) / "avd" if user_home else None,
            Path(sdk_home) / ".android" / "avd" if sdk_home else None,
            Path.home() / ".android" / "avd",
        )
        for directory in filter(None, directories):
            ini = read_ini(directory / f"{avd}.ini")
            if not ini:
                continue
            avd_path = Path(ini["path"]) if ini.get("path") else directory / f"{avd}.avd"
            if not avd_path.is_dir() and ini.get("path.rel"):
                avd_path = directory.parent / ini["path.rel"]
            rel_image = read_ini(avd_path / "config.ini").get("image.sysdir.1")
            if rel_image:
                image = self.root / rel_image
                if not any((image / name).is_file() for name in ("system.img", "system-qemu.img")):
                    raise AndroidError(f"The {avd} AVD is missing its system image at {image}.")
            return

    def adb_command(self, serial, *args, timeout=30):
        if not self.adb:
            raise AndroidError("adb was not found in the Android SDK.")
        p = run_command(self.adb, "-s", serial, *args, timeout=timeout)
        if p.returncode:
            raise AndroidError(f"adb {args[0]} failed. {output_tail(p)}")
        return p.stdout

    def wait_for_boot(self, avd_name: str | None = None) -> tuple[str, str | None]:
        devices = self.devices()
        if len(devices) > 1:
            raise AndroidError("Open only one Android emulator before measuring memory.")
        preferred_avd = avd_name or os.environ.get("MEMSCOPE_ANDROID_AVD") or self.lab_avd()
        avd = None
        proc = None
        ready = False
        try:
            if not devices:
                names = self.list_avds()
                if not names:
                    raise AndroidError("Set up an Android virtual device first.")
                avd = preferred_avd or names[0]
                if avd not in names:
                    raise AndroidError(f"The Android virtual device {avd} does not exist.")
                self.verify_system_image(avd)
                env = os.environ.copy()
                if self.root:
                    env.update(ANDROID_SDK_ROOT=str(self.root), ANDROID_HOME=str(self.root))
                proc = subprocess.Popen(
                    [str(self.emulator), "-avd", avd, "-no-boot-anim", "-no-snapshot-save"],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, creationflags=HIDE_WINDOW,
                )
            deadline = time.monotonic() + 240
            while True:
                if proc is not None and proc.poll() is not None:
                    raise AndroidError(f"The {avd} AVD exited during boot (code {proc.returncode}).")
                if len(devices) > 1:
                    raise AndroidError("Multiple Android emulators are running. Open only one for memory measurement.")
                for serial, state in devices.items():
                    if state == "device":
                        try:
                            if avd or preferred_avd:
                                name = self.adb_command(serial, "emu", "avd", "name", timeout=8).splitlines()
                                if not name or name[0].strip() != (avd or preferred_avd):
                                    if proc is None and name and name[0] != "KO":
                                        raise WrongAVD(f"Close this emulator and start {preferred_avd}.")
                                    continue
                            if self.adb_command(serial, "shell", "getprop", "sys.boot_completed", timeout=8).strip() == "1":
                                ready = True
                                return serial, avd
                        except WrongAVD:
                            raise
                        except (AndroidError, subprocess.TimeoutExpired):
                            # adb may disconnect during the Android boot sequence.
                            pass
                if time.monotonic() >= deadline:
                    raise AndroidError("Android did not finish booting within 240 seconds.")
                time.sleep(2)
                devices = self.devices()
        finally:
            if not ready and proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    LOGGER.exception("Could not stop Android Emulator after a boot failure")

    def restore_clean_state(self, serial):
        """Load the clean snapshot and turn off guest networking before each web session."""
        output = self.adb_command(serial, "emu", "avd", "snapshot", "load", CLEAN_SNAPSHOT, timeout=120)
        if "OK" not in output.splitlines():
            raise AndroidError(f"Could not load the clean snapshot {CLEAN_SNAPSHOT}: {output.strip()}")
        # Services resume asynchronously after a snapshot load; wait until the package manager answers.
        time.sleep(10)
        serial, _ = self.wait_for_boot()
        deadline = time.monotonic() + 90
        while True:
            try:
                self.adb_command(serial, "shell", "service", "check", "activity", timeout=15)
                self.installed_packages(serial)
                break
            except AndroidError:
                if time.monotonic() >= deadline:
                    raise AndroidError("Android services did not come back after loading the clean snapshot.")
                time.sleep(3)
        for args in (("svc", "wifi", "disable"), ("svc", "data", "disable")):
            try:
                self.adb_command(serial, "shell", *args, timeout=15)
            except AndroidError:
                LOGGER.warning("Could not run %s in the emulator", " ".join(args))
        return serial

    def installed_packages(self, serial):
        raw = self.adb_command(serial, "shell", "pm", "list", "packages", "-u")
        packages = {line.removeprefix("package:").strip()
                    for line in raw.splitlines() if line.startswith("package:")}
        if not packages:
            raise AndroidError("Could not list packages in the emulator.")
        return packages

    def read_package_name(self, path):
        name = "aapt.exe" if os.name == "nt" else "aapt"
        build_tools = self.root / "build-tools" if self.root else None
        tools = sorted(build_tools.glob(f"*/{name}"), reverse=True) if build_tools else []
        exe = next(iter(tools), shutil.which(name))
        if not exe:
            raise AndroidError("Android Build-Tools (aapt) are required to identify this APK package.")
        p = run_command(exe, "dump", "badging", str(path))
        match = re.search(r"^package: name='([^']+)'", p.stdout, re.MULTILINE)
        if p.returncode or not match or not PACKAGE_NAME.fullmatch(match[1]):
            raise AndroidError(f"aapt could not read a valid package name. {output_tail(p)}")
        return match[1]


class AndroidJobs:
    def __init__(self, results_dir, score, validate_sample):
        self.results_dir = results_dir
        self.score = score
        self.validate_sample = validate_sample
        self.lock = Lock()
        self.jobs = {}
        # Serialize installation, measurement, and cleanup.
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="apk")

    def submit(self, path: Path, filename: str, duration: int) -> str:
        job_id = uuid4().hex
        job = {
            "job_id": job_id, "ten_file": filename, "trang_thai": "cho",
            "buoc": [{"ma": step_id, "ten": label, "trang_thai": "cho", "thoi_gian": None, "ghi_chu": ""}
                     for step_id, label in STEPS.items()],
            "ket_qua": None, "loi": None, "tep_ket_qua": None, "thoi_gian": None,
        }
        with self.lock:
            if sum(j["trang_thai"] in {"cho", "dang_chay"} for j in self.jobs.values()) >= 4:
                raise Full
            self.jobs[job_id] = job
            try:
                self.pool.submit(self.run, job, path, duration)
            except RuntimeError:
                del self.jobs[job_id]
                raise
            done = [key for key, old in self.jobs.items() if old["trang_thai"] in {"xong", "loi"}]
            for key in done[:-64]:
                del self.jobs[key]
        return job_id

    def get(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            snapshot = deepcopy(job)
        for step in snapshot["buoc"]:
            started = step.pop("_bat_dau", None)
            if step["trang_thai"] == "dang_chay":
                step["thoi_gian"] = round(time.perf_counter() - started, 2)
        return snapshot

    @contextmanager
    def step(self, job, step_id):
        step = next(step for step in job["buoc"] if step["ma"] == step_id)
        started = time.perf_counter()
        with self.lock:
            step.update(trang_thai="dang_chay", _bat_dau=started)
        note = {}
        try:
            yield note
        except Exception as exc:
            with self.lock:
                step.update(trang_thai="loi", ghi_chu=error_message(exc), thoi_gian=round(time.perf_counter() - started, 2))
            raise
        else:
            with self.lock:
                step.update(trang_thai="xong", ghi_chu=note.get("text", ""),
                            thoi_gian=round(time.perf_counter() - started, 2))

    def save_evidence(self, timestamp, sha, data):
        self.results_dir.mkdir(parents=True, exist_ok=True)
        path = self.results_dir / f"{timestamp}_{sha[:8]}_{data['job_id']}.json"
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.results_dir, suffix=".tmp", delete=False,
        ) as tmp:
            temp_path = Path(tmp.name)
            try:
                json.dump(data, tmp, ensure_ascii=False, indent=2, allow_nan=False)
                tmp.close()
                temp_path.replace(path)
            finally:
                tmp.close()
                temp_path.unlink(missing_ok=True)
        return path.name

    def run(self, job, path, duration):
        started = time.perf_counter()
        timestamp = datetime.now().astimezone()
        sha = serial = package = raw = measurements = result = evidence = None
        errors = []
        guard = ExitStack()
        with self.lock:
            job["trang_thai"] = "dang_chay"

        try:
            with self.step(job, "sha256") as note:
                with path.open("rb") as apk:
                    sha = hashlib.file_digest(apk, "sha256").hexdigest()
                sample_info = self.validate_sample("android", sha)
                try:
                    with ZipFile(path) as apk:
                        if apk.getinfo("AndroidManifest.xml").file_size == 0:
                            raise BadZipFile("Empty AndroidManifest.xml")
                except (BadZipFile, KeyError, UnicodeError):
                    raise AndroidError("The APK has no valid AndroidManifest.xml.") from None
                note["text"] = sha
            with self.step(job, "may_ao") as note:
                guard.enter_context(lock_emulator())
                sdk = AndroidSDK()
                serial, avd = sdk.wait_for_boot()
                serial = sdk.restore_clean_state(serial)
                origin = f"Started {avd}" if avd else "Using the running lab emulator"
                note["text"] = f"{origin} ({serial}), restored snapshot {CLEAN_SNAPSHOT}, network off."
            with self.step(job, "cai_dat") as note:
                before = sdk.installed_packages(serial)
                expected = sample_info.get("package") or sdk.read_package_name(path)
                if expected in before:
                    raise AndroidError(f"Package {expected} is already installed. Use a clean emulator.")
                # Track the package before installation so partial failures can be cleaned up.
                package = expected
                try:
                    output = sdk.adb_command(serial, "install", "-R", "-g", str(path), timeout=180)
                    if "Success" not in output.splitlines():
                        raise AndroidError(f"Could not install the APK. {output.strip()[-600:]}")
                except AndroidError as exc:
                    if "INSTALL_FAILED_ALREADY_EXISTS" in str(exc):
                        package = None
                    raise
                note["text"] = f"Installed {package}."
            with self.step(job, "chay") as note:
                launch = sdk.adb_command(serial, "shell", "monkey", "-p", package, "-c",
                                     "android.intent.category.LAUNCHER", "1")
                if not re.search(r"^Events injected: 1\s*$", launch, re.MULTILINE):
                    raise AndroidError(f"Monkey could not launch the app. {launch.strip()[-600:]}")
                # Monkey counts touch-down and touch-up separately and delays after each tap.
                taps = duration * 4
                events = 1 + 2 * taps
                output = sdk.adb_command(
                    serial, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER",
                    "-s", "42", "--throttle", "250", "--pct-touch", "100",
                    str(events), timeout=duration + 45,
                )
                if not re.search(rf"^Events injected: {events}\s*$", output, re.MULTILINE):
                    raise AndroidError(f"Monkey stopped before injecting {events} events. {output.strip()[-600:]}")
                note["text"] = f"Monkey injected {taps} random taps with a 250 ms interval."
            with self.step(job, "doc_ram") as note:
                raw = sdk.adb_command(serial, "shell", "dumpsys", "meminfo", "-a", package, timeout=60)
                measurements = to_andmal_row(parse_meminfo(raw, process_name=package))
                if measurements["Memory_PssTotal"] is None:
                    raise AndroidError(f"Could not read total PSS for {package}. Check the process and meminfo output.")
                note["text"] = f"Total PSS {measurements['Memory_PssTotal']} KB."
            with self.step(job, "cham_diem") as note:
                result = self.score(measurements, sha, job["ten_file"], package)
                top = result["loai"][0]
                confidence = f"{top['p']:.2%}"
                note["text"] = f"Top predicted class: {top['ma']} ({confidence})."
        except Exception as exc:
            errors.append(error_message(exc))
            if not isinstance(exc, (AndroidError, OSError, SampleNotAllowed, subprocess.TimeoutExpired)):
                LOGGER.exception("APK job %s failed", job["job_id"])

        if package:
            try:
                with self.step(job, "go_app") as note:
                    if package in sdk.installed_packages(serial):
                        output = sdk.adb_command(serial, "uninstall", package, timeout=60)
                        if "Success" not in output.splitlines():
                            raise AndroidError(f"Could not uninstall {package}. {output.strip()[-600:]}")
                    note["text"] = f"Package {package} was removed from the emulator."
            except Exception as exc:
                errors.append(error_message(exc))
        guard.close()
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"Could not remove the temporary APK. {error_message(exc)}")

        with self.lock:
            for step in job["buoc"]:
                if step["ma"] != "luu" and step["trang_thai"] == "cho":
                    step.update(trang_thai="bo_qua", ghi_chu="A preceding step did not complete.")

        if sha:
            try:
                with self.step(job, "luu") as note:
                    evidence = self.save_evidence(timestamp.date().isoformat(), sha, {
                        "thoi_diem": timestamp.isoformat(), "job_id": job["job_id"], "sha256": sha,
                        "ten_file": job["ten_file"], "goi": package, "may_ao": serial,
                        "giay_chay": duration, "buoc": self.get(job["job_id"])["buoc"][:-1],
                        "meminfo_tho": raw, "so_do_ram": measurements, "ket_qua": result,
                        "loi": "\n".join(errors) or None,
                    })
                    note["text"] = evidence
            except Exception as exc:
                errors.append(f"Could not save the evidence. {error_message(exc)}")
        else:
            with self.lock:
                job["buoc"][-1].update(trang_thai="bo_qua", ghi_chu="SHA-256 was unavailable.")
        with self.lock:
            job.update(trang_thai="loi" if errors else "xong", ket_qua=result, tep_ket_qua=evidence,
                       loi="\n".join(errors) or None, thoi_gian=round(time.perf_counter() - started, 2))
