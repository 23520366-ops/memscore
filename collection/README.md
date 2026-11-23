# Collect clean Android RAM measurements

Set up the dedicated Android emulator using [SETUP.md](../docs/SETUP.md#2-set-up-android-emulator) and save its isolated state as `sach`. Use only verified clean APKs listed in [allowed_samples.json](../app/config/allowed_samples.json).

To discover clean candidates from F-Droid, install the optional downloader dependency and request a small batch. The downloader compares each file with its F-Droid index checksum and records its source.

```powershell
.\app\.venv\Scripts\python.exe -m pip install -r collection\requirements.txt
.\app\.venv\Scripts\python.exe .\collection\download_clean_apks.py --count 5
```

Review candidate provenance and add verified APKs through the [allowlist procedure](../docs/SAFETY.md#add-a-verified-clean-sample). Put local APKs in `collection/apk/clean/` or pass `--apk-dir`.

```powershell
.\app\.venv\Scripts\python.exe .\collection\collect_meminfo.py --snapshot sach
```

Collection reloads the clean snapshot before each app and records up to three meminfo readings by default. The CSV and raw meminfo text appear in `collection/measurements/`. Re-running the same collection skips APKs already present in the CSV. Share the measurements only after reviewing them for personal data.
