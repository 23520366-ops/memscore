# Safety

MemScope is a classroom classifier designed around published feature tables and controlled measurements of clean applications. Live malware can escape isolation, expose host data, or spread through a reachable network. The project uses pre-recorded malware feature rows for detection experiments and clean applications for live measurements. EICAR may be used as an inert file-handling or antivirus test. Never disable or bypass endpoint protection for the demo. [EICAR test file documentation](https://www.eicar.org/download-anti-malware-testfile/)

## Isolate the guests

- Use dedicated guest instances with disposable state and no personal accounts, credentials, or data.
- Keep the Windows guest powered off between runs, with network adapters disconnected and shared folders, shared clipboard, drag and drop, and USB passthrough disabled. Restore the powered-off `sach` snapshot after each measurement. The runner checks the network and shared-folder configuration before and after restoring the snapshot.
- Use one dedicated Android emulator with no signed-in account. Turn on airplane mode and verify Wi-Fi and mobile data are off before measuring. Keep physical Android devices disconnected. Live jobs uninstall the measured app. Restore a clean AVD snapshot when you need to reset the guest after an interrupted run.
- Keep the demo on `127.0.0.1`. The API limits upload size and rejects browser POSTs from other origins. Dataset lookup reads the upload as bytes and computes SHA-256 and MD5.

## Add a verified clean sample

1. Obtain a clean build from the project's official release or an official F-Droid listing. Match the release version and architecture.
2. Verify the publisher checksum or signature for that build, then record its SHA-256 in PowerShell with `Get-FileHash -Algorithm SHA256 -LiteralPath 'D:\Lab\clean sample.apk'`.
3. Add a lowercase SHA-256 key under `android` or `windows` in [allowed_samples.json](../app/config/allowed_samples.json). Each entry has a display `name` and `source_url`. An Android entry can include `package`. Android Build-Tools supply the package name when it is omitted. A Windows entry can include a guest `filename` and a list of `arguments`.
4. Restart the demo so it loads the updated config. Drop the file on the relevant model page. A matching dataset record is displayed immediately after lookup. An eligible hash miss starts a live measurement.

## Allowlist override

**Warning:** `MEMSCOPE_ALLOW_ANY_SAMPLE=1` disables the SHA-256 allowlist for web and API live runs. It makes otherwise unknown .exe and .apk files eligible for guest execution after the remaining checks. Dataset-known malware hashes remain blocked, and a hash miss provides no evidence that a file is clean. Use this override only for independently verified clean files in an isolated lab guest. The collection and smoke scripts still require an allowlisted sample.

To apply the override to one PowerShell session, set `$env:MEMSCOPE_ALLOW_ANY_SAMPLE = '1'` before starting the demo. Close the demo and run `Remove-Item Env:MEMSCOPE_ALLOW_ANY_SAMPLE` before restarting with the normal allowlist.
