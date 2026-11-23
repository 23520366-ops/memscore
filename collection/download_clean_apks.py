"""Download clean F-Droid APK candidates and verify the index-provided SHA-256."""
import argparse
import csv
import hashlib
import random
import re
from pathlib import Path

import requests

REPO = "https://f-droid.org/repo/"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "apk" / "clean"


def supports_x86(version: dict) -> bool:
    native = version.get("nativecode") or []
    return not native or any(abi.startswith("x86") for abi in native)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=150)
    parser.add_argument("--max-mb", type=float, default=25)
    parser.add_argument("--api", type=int, default=34, help="The target Android API level.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.count < 1 or args.max_mb <= 0:
        parser.error("Use a positive sample count and size limit.")
    args.output.mkdir(parents=True, exist_ok=True)

    print("Downloading the F-Droid index...")
    index_response = requests.get(REPO + "index-v1.json", timeout=300)
    index_response.raise_for_status()
    index = index_response.json()
    categories = {app["packageName"]: (app.get("categories") or ["Other"])[0] for app in index["apps"]}
    candidates = []
    for package, versions in index["packages"].items():
        version = max(versions, key=lambda item: item.get("versionCode", 0))
        if version.get("size", 0) > args.max_mb * 1024 * 1024:
            continue
        if int(version.get("minSdkVersion", 1)) > args.api or not supports_x86(version):
            continue
        if re.fullmatch(r"[A-Za-z0-9_.-]+\.apk", version.get("apkName", "")) and re.fullmatch(
                r"[0-9a-f]{64}", version.get("hash", "").lower()):
            candidates.append((categories.get(package, "Other"), package, version))

    random.Random(42).shuffle(candidates)
    per_category = {}
    total = 0
    with (args.output / "sample_sources.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["package", "category", "filename", "sha256", "source_url"])
        for category, package, version in candidates:
            if per_category.get(category, 0) >= 12:
                continue
            name = version["apkName"]
            url = REPO + name
            path = args.output / name
            expected = version["hash"].lower()
            if path.exists():
                if digest(path) != expected:
                    raise ValueError(f"{path} exists with a different SHA-256.")
            else:
                response = requests.get(url, timeout=300)
                response.raise_for_status()
                if hashlib.sha256(response.content).hexdigest() != expected:
                    raise ValueError(f"The downloaded SHA-256 does not match for {name}.")
                path.write_bytes(response.content)
            writer.writerow([package, category, name, expected, url])
            per_category[category] = per_category.get(category, 0) + 1
            total += 1
            print(f"[{total}/{args.count}] {package} ({category})")
            if total >= args.count:
                break
    print(f"Saved {total} F-Droid candidates to {args.output}.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, requests.RequestException) as exc:
        raise SystemExit(str(exc)) from exc
