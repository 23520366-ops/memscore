"""Download the verified clean demo samples into ./samples and check their SHA-256.

The files come from their official release pages and match app/config/allowed_samples.json,
so MemScope will accept them for live RAM measurements.
"""
import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "samples"

SAMPLES = [
    # (file name, url, sha256 of the final file, member inside a zip or None)
    ("7zr.exe", "https://github.com/ip7z/7zip/releases/download/26.06/7zr.exe",
     "e80db2dad715a6c5adabe292d31ed54e11f4e9b99ca349827b50573b175891bc", None),
    ("notepad++.exe",
     "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.portable.x64.zip",
     "b34e96a8088644415dff0b4af6c7a444f4119d90c5a7d6bed78f5bc164dbb357", "notepad++.exe"),
    ("com.github.muellerma.coffee_47.apk", "https://f-droid.org/repo/com.github.muellerma.coffee_47.apk",
     "ae4688fe48e751517e7a1d56aed27bff10b87daac0d7e28993fb193a7dc8f223", None),
    ("org.woheller69.level_35.apk", "https://f-droid.org/repo/org.woheller69.level_35.apk",
     "fbe2fa19b05adc4d1335f7a2456c138b8483b643746c45dee6c6fb14ca7a6db8", None),
    ("org.secuso.privacyfriendlydicer_101.apk", "https://f-droid.org/repo/org.secuso.privacyfriendlydicer_101.apk",
     "f2b4d3f021c3a6207c3c9e75a75fa325b88847bd46b4f99e41e28dc3be8fae7f", None),
]


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "MemScope sample downloader"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def main() -> int:
    OUT.mkdir(exist_ok=True)
    failed = 0
    for name, url, expected, member in SAMPLES:
        target = OUT / name
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
            print(f"OK (cached)  {name}")
            continue
        try:
            data = fetch(url)
            if member:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    data = archive.read(member)
        except Exception as exc:  # network errors, missing release assets
            print(f"FAILED       {name}: {exc}", file=sys.stderr)
            failed += 1
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            print(f"HASH MISMATCH {name}: {digest}", file=sys.stderr)
            failed += 1
            continue
        target.write_bytes(data)
        print(f"OK           {name}")
    print(f"Samples are in {OUT}")
    return int(failed > 0)


if __name__ == "__main__":
    raise SystemExit(main())
