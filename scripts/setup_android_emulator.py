"""Install Android SDK components and create a dedicated MemScope AVD on Windows."""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.android_runner import AndroidError, AndroidSDK


def run_sdk_tool(tool: Path, *args: str, env: dict, answer: str | None = None) -> None:
    if not tool.is_file():
        raise FileNotFoundError(f"Install Android SDK Command-line Tools (latest) in Android Studio: {tool}")
    cmd = [os.environ.get("ComSpec", "cmd.exe"), "/d", "/v:off", "/c", "call", str(tool), *args]
    subprocess.run(cmd, env=env, input=answer, text=True, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    default_sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    default_sdk = default_sdk or str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk")
    parser.add_argument("--sdk", type=Path, default=default_sdk)
    parser.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"))
    parser.add_argument("--avd", default="memscope")
    parser.add_argument("--api", type=int, default=34)
    parser.add_argument("--no-start", action="store_true", help="Create the AVD and exit before starting it.")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.avd):
        parser.error("Use letters, digits, dots, underscores, or hyphens in the AVD name.")

    sdk_root = args.sdk.resolve()
    java_home = args.java_home or Path(r"C:\Program Files\Android\Android Studio\jbr")
    if not (java_home / "bin" / "java.exe").is_file():
        parser.error("Set --java-home to the Android Studio jbr directory.")
    env = dict(os.environ, ANDROID_SDK_ROOT=str(sdk_root), ANDROID_HOME=str(sdk_root), JAVA_HOME=str(java_home))
    tools = sdk_root / "cmdline-tools" / "latest" / "bin"
    image = f"system-images;android-{args.api};google_apis;x86_64"

    print(f"Installing SDK components in {sdk_root}. Review the SDK license prompts.", flush=True)
    run_sdk_tool(tools / "sdkmanager.bat", "--sdk_root=" + str(sdk_root), "--licenses", env=env)
    run_sdk_tool(tools / "sdkmanager.bat", "--sdk_root=" + str(sdk_root),
                 "platform-tools", "emulator", "build-tools;34.0.0", image, env=env)
    os.environ.update(ANDROID_SDK_ROOT=str(sdk_root), ANDROID_HOME=str(sdk_root))
    sdk = AndroidSDK()
    if args.avd not in sdk.list_avds():
        run_sdk_tool(tools / "avdmanager.bat", "create", "avd", "--name", args.avd,
                     "--package", image, answer="no\n", env=env)
    else:
        print(f"Using existing AVD {args.avd}.")
    sdk.verify_system_image(args.avd)
    if args.no_start:
        print(f"AVD {args.avd} is ready to start in Android Studio Device Manager.")
        return
    if sdk.devices():
        raise AndroidError("Close any running emulator before provisioning the clean snapshot.")
    serial, _ = sdk.wait_for_boot(args.avd)
    output = sdk.adb_command(serial, "emu", "avd", "snapshot", "save", "sach", timeout=300)
    if "OK" not in output.splitlines():
        raise AndroidError(f"Could not save snapshot sach: {output.strip()}")
    print(f"AVD {args.avd} is running as {serial}. Saved snapshot sach.")


if __name__ == "__main__":
    try:
        main()
    except (AndroidError, OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from exc
