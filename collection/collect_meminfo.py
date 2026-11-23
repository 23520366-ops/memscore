"""Record Android RAM measurements for explicitly allowlisted clean APKs."""
import argparse
import csv
import hashlib
import sys
import time
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.android_runner import AndroidError, AndroidSDK, lock_emulator
from app.sample_policy import ALLOWED_SAMPLES
from collection.meminfo_parser import ANDMAL_MEMORY_COLUMNS, parse_meminfo, to_andmal_row

HERE = Path(__file__).resolve().parent
FIELDS = ["sha256", "file", "label", "package", "measurement", "seconds_since_launch", "running"]


def measure(sdk: AndroidSDK, serial: str, path: Path, args: argparse.Namespace) -> list[dict]:
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    sample = ALLOWED_SAMPLES["android"].get(sha)
    if sample is None:
        raise AndroidError(f"{path.name} is absent from the verified clean allowlist.")

    snapshot = sdk.adb_command(serial, "emu", "avd", "snapshot", "load", args.snapshot, timeout=120)
    if "OK" not in snapshot.splitlines():
        raise AndroidError(f"Could not load snapshot {args.snapshot}: {snapshot.strip()}")
    sdk.wait_for_boot()
    package = sample.get("package") or sdk.read_package_name(path)
    if package in sdk.installed_packages(serial):
        raise AndroidError(f"Package {package} is already present in the clean snapshot.")

    measurements = []
    try:
        installed = sdk.adb_command(serial, "install", "-R", "-g", str(path), timeout=180)
        if "Success" not in installed.splitlines():
            raise AndroidError(f"Could not install {package}: {installed.strip()}")
        sdk.adb_command(serial, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
        started = time.monotonic()
        for index in range(1, args.repeats + 1):
            sdk.adb_command(serial, "shell", "monkey", "-p", package, "--throttle", "400",
                            "--pct-syskeys", "0", "40", timeout=90)
            time.sleep(max(0, args.interval - 15))
            raw = sdk.adb_command(serial, "shell", "dumpsys", "meminfo", "-a", package)
            (args.output / "raw" / f"{sha[:16]}_{index}.txt").write_text(raw, encoding="utf-8")
            row = to_andmal_row(parse_meminfo(raw, process_name=package))
            if row["Memory_PssTotal"] is None:
                continue
            try:
                running = bool(sdk.adb_command(serial, "shell", "pidof", package).strip())
            except AndroidError:
                running = False
            row.update(sha256=sha, file=path.name, label="Benign", package=package,
                       measurement=index, seconds_since_launch=int(time.monotonic() - started), running=int(running))
            measurements.append(row)
    finally:
        if package in sdk.installed_packages(serial):
            removed = sdk.adb_command(serial, "uninstall", package, timeout=60)
            if "Success" not in removed.splitlines():
                raise AndroidError(f"Could not remove {package}: {removed.strip()}")
    return measurements


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk-dir", type=Path, default=HERE / "apk" / "clean")
    parser.add_argument("--output", type=Path, default=HERE / "measurements")
    parser.add_argument("--snapshot", default="sach")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--interval", type=int, default=20)
    args = parser.parse_args()
    if args.repeats < 1 or args.interval < 0 or not args.snapshot:
        parser.error("Provide a snapshot, at least one repeat, and a non-negative interval.")

    paths = sorted(args.apk_dir.glob("*.apk"))
    if not paths:
        parser.error(f"No APKs found in {args.apk_dir}.")
    (args.output / "raw").mkdir(parents=True, exist_ok=True)
    output = args.output / "meminfo.csv"
    done = set()
    if output.exists():
        with output.open(encoding="utf-8", newline="") as stream:
            done = {row["file"] for row in csv.DictReader(stream)}

    sdk = AndroidSDK()
    with lock_emulator(), output.open("a", encoding="utf-8", newline="") as stream:
        serial, _ = sdk.wait_for_boot()
        writer = csv.DictWriter(stream, FIELDS + ANDMAL_MEMORY_COLUMNS)
        if stream.tell() == 0:
            writer.writeheader()
        for path in paths:
            if path.name in done:
                continue
            try:
                rows = measure(sdk, serial, path, args)
            except AndroidError as exc:
                print(f"{path.name}: {exc}", file=sys.stderr)
                continue
            writer.writerows(rows)
            stream.flush()
            print(f"{path.name}: {len(rows)}/{args.repeats} measurements saved.")
    print(f"Output: {output}")


if __name__ == "__main__":
    try:
        main()
    except (AndroidError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
