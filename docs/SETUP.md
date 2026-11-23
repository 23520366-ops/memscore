# Set up MemScope on Windows 11

The preset demo needs Python and the repository's feature data and model files. Set up the Android or Windows guest only if you intend to take new RAM measurements. Run the commands from the repository root in Windows PowerShell unless otherwise noted.

## 1. Install Python and open the demo

1. Install 64-bit Python 3.12 with the Python launcher or add Python to PATH. [Python downloads](https://www.python.org/downloads/)
2. Clone the full repository, including `data/`, `app/data/` and `app/models/`; the demo loads them directly. If a derived table in `app/data/` is missing, rebuild it with `.\app\.venv\Scripts\python.exe .\training\prepare_demo.py` after restoring the source datasets listed in [data/README.md](../data/README.md).
3. Run [run_demo.bat](../run_demo.bat) by double-clicking it or by entering the command below. The first start may need internet access for Python packages.

```powershell
.\run_demo.bat
```

Wait for the browser to open at [the local demo](http://127.0.0.1:8000). Run `.\run_demo.bat --dry-run` to verify the app environment without starting the server. To stop the demo, press Ctrl+C in its console. Let active live jobs finish so guest cleanup can complete.

## 2. Set up Android Emulator

1. Enable hardware virtualization in UEFI if needed and verify the host can run Android Emulator with hardware acceleration. Install Android Studio, then open **Tools → SDK Manager → SDK Tools** and install **Android SDK Command-line Tools (latest)**. Note the Android SDK location. [Android Studio](https://developer.android.com/studio) · [SDK command-line tools](https://developer.android.com/tools)
2. Close other emulator instances and unplug any physical Android devices. Run the setup command. It installs Platform-Tools, Emulator, Build-Tools, and the API 34 Google APIs x86_64 image, creates the `memscope` AVD if needed, then boots it and saves a clean snapshot named `sach`.

```powershell
$env:ANDROID_HOME = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
.\app\.venv\Scripts\python.exe .\scripts\setup_android_emulator.py
```

Pass `--sdk` for a custom SDK location and `--java-home` for a custom Android Studio `jbr` directory. Set `ANDROID_HOME` to the same SDK before launching MemScope. Use `--no-start` to create the AVD without booting it.

3. Turn on airplane mode in the guest and verify Wi-Fi and mobile data are off. Leave it unsigned-in. With this emulator as the only connected Android device, save the offline clean state if you plan to restore from the snapshot.

```powershell
& (Join-Path $env:ANDROID_HOME 'platform-tools\adb.exe') emu avd snapshot save sach
```

4. MemScope uses the `memscope` AVD (or `ie105`) and loads its `sach` snapshot and turns off guest Wi-Fi and mobile data before every live run. Set `$env:MEMSCOPE_ANDROID_AVD` / `$env:MEMSCOPE_ANDROID_SNAPSHOT` to use other names. Run the demo, open **Android: loại mã độc (RAM)** and drop a verified clean APK. After a hash miss the app installs the sample, collects `dumpsys meminfo`, runs the model, uninstalls the app, and saves a JSON record in `app/results/`. Use the [allowlist instructions](SAFETY.md#add-a-verified-clean-sample) for new clean builds.

## 3. Prepare the VMware Windows guest

1. Install VMware Workstation Pro and check that `vmrun.exe -T ws list` works in your Windows session. Download the **Windows 11 Enterprise LTSC 2024 Evaluation** x64 ISO in English (United States). Copy its contents into a disposable, writable folder. This workflow expects `sources\install.wim` and `efi\microsoft\boot\efisys_noprompt.bin`. [VMware Workstation](https://knowledge.broadcom.com/external/article?articleNumber=387947) · [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)
2. Create a blank, disposable VMware VM with UEFI firmware, a single empty virtual disk on SATA 0:0, and about 4 GB of RAM. Choose **I will install the operating system later** and keep the VM powered off. The unattended lab setup expects a VMX without encryption or a virtual TPM. Disconnect guest networking and disable shared folders, clipboard, drag and drop, and USB passthrough.
3. Build the unattended ISO with the supplied answer file. It wipes **guest disk 0** and sets up the local lab account `test` with the disposable password `ie105test`. Use this ISO only with the dedicated blank VM. Adjust the sample paths below.

```powershell
$lab = 'D:\MayAo'
$env:MEMSCOPE_VMX = Join-Path $lab 'Win11-IE105\Win11-IE105.vmx'
$unattendedIso = Join-Path $lab 'win11-tu-cai.iso'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\build_windows_iso.ps1 `
  -ExtractedDirectory (Join-Path $lab 'LTSC extracted') -Iso $unattendedIso
```

4. From the same shell, run the preparation script. It attaches the Windows and VMware Tools ISOs, waits for VMware Tools and the `test` desktop session, shuts down the guest, detaches the media, and saves `sach`. If VMware Workstation is installed in a custom location, set `MEMSCOPE_VMRUN` to its full `vmrun.exe` path. Pass `-ToolsIso` if the VMware Tools ISO is separate from `vmrun.exe`. [VMware Tools](https://knowledge.broadcom.com/external/article/315639)

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\prepare_windows_vm.ps1 -IsoPath $unattendedIso
```

For an already installed, isolated lab guest with VMware Tools and the local `test` account, run `.\scripts\create_clean_snapshot.bat` or pass `-SnapshotOnly` to the PowerShell script. If you changed the disposable guest password, set `MEMSCOPE_WINDOWS_PASSWORD` before preparation and before running the demo. Leave the VM powered off and close its Workstation tab if it holds a lock.

## 4. Install Volatility for live Windows runs

```powershell
.\app\.venv\Scripts\python.exe -m venv .venv-vol
.\.venv-vol\Scripts\python.exe -m pip install volatility3==2.28.2
```

Volatility may fetch and cache Microsoft symbols on the host on the first run. Keep the Windows guest offline. [Volatility 3 installation and symbols](https://github.com/volatilityfoundation/volatility3#symbol-tables)

Start the demo from the shell that sets `MEMSCOPE_VMX`. Drop an allowlisted clean EXE onto **Windows (sạch/độc + loại)**. For a baseline or the guest's own Notepad, use the Windows smoke-run script with the web demo stopped.

```powershell
.\app\.venv\Scripts\python.exe .\scripts\try_exe.py --builtin baseline
.\app\.venv\Scripts\python.exe .\scripts\try_exe.py --builtin notepad
```

You can pass a verified clean file to `try_exe.py --file` or pass verified clean APK paths to `try_apk.py`. The scripts report progress and the resulting JSON filename.

## 5. Troubleshooting

| Symptom | Check |
| --- | --- |
| Python or dependency installation fails | Run `py -3.12 --version`, confirm network access for pip, and retry the launcher. |
| The local page does not open | Check `app/results/startup.txt` and stop any process already using port 8000. |
| Android emulator is missing or fails to boot | Confirm the selected SDK contains `adb.exe`, `emulator.exe`, and a complete system image. Start the AVD from Device Manager to inspect errors. |
| The API rejects a clean upload | Compare the actual SHA-256 with the correct platform entry in the allowlist. Restart after editing the config. APKs are limited to 64 MiB and EXEs to 32 MiB for live runs. |
| Windows reports a VMware connection or lock error | Verify `vmrun.exe -T ws list` in the current session, close the guest tab, and check the VMX path and powered-off snapshot. |
| VMware Tools reports `installed` | Preparation accepts either `installed` or `running` and waits for `listProcessesInGuest` to show `explorer.exe`. Check automatic sign-in and the guest password if it times out. |
| A live measurement fails | Open the reported JSON in `app/results/` and check the failed step. For Windows, make sure the clean snapshot was restored before retrying. |
| Android static lookup has no match | The downloaded dataset provides anonymized features. A new APK needs an existing hash record to display an Android static result. |
