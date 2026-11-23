"""Run the Windows demo pipeline with a clean EXE or a built-in guest sample."""
import argparse
from pathlib import Path

from try_apk import require_verified, run_case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--file", type=Path, help="A verified clean .exe file.")
    inputs.add_argument("--builtin", choices=("baseline", "notepad"))
    args = parser.parse_args()
    if args.file:
        require_verified(args.file, "windows")

    from fastapi.testclient import TestClient
    from app.server import app

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        endpoint = "/api/analyze/windows"
        if args.file:
            results = [run_case(client, endpoint, args.file)]
        else:
            samples = [args.builtin] if args.builtin else ["baseline", "notepad"]
            results = [run_case(client, f"{endpoint}?sample={name}") for name in samples]
    return int(not all(results))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
