"""Run the Android demo pipeline with locally verified clean APKs."""
import argparse
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def run_case(client, endpoint: str, path: Path | None = None, *, timeout: int = 1800) -> bool:
    files = {"file": (path.name, path.read_bytes())} if path else None
    response = client.post(endpoint, files=files)
    if response.status_code != 202:
        print(f"Request failed ({response.status_code}): {response.text}", file=sys.stderr)
        return False

    job_id = response.json()["job_id"]
    deadline = time.monotonic() + timeout
    previous = None
    statuses = {"cho": "queued", "dang_chay": "running", "xong": "done", "loi": "failed", "bo_qua": "skipped"}
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        response.raise_for_status()
        job = response.json()
        current = [(step["ten"], step["trang_thai"]) for step in job["buoc"]]
        if previous != current:
            print(" | ".join(f"{name}: {statuses[status]}" for name, status in current), flush=True)
            previous = current
        if job["trang_thai"] in {"xong", "loi"}:
            if job["tep_ket_qua"]:
                print(f"Evidence: app/results/{job['tep_ket_qua']}")
            if job["loi"]:
                print(job["loi"], file=sys.stderr)
            return job["trang_thai"] == "xong"
        time.sleep(2)
    print(f"Timed out while waiting for job {job_id}.", file=sys.stderr)
    return False


def require_verified(path: Path, platform: str) -> None:
    from app.sample_policy import ALLOWED_SAMPLES

    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest not in ALLOWED_SAMPLES[platform]:
        raise ValueError(f"{path.name} is absent from the verified clean allowlist.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.apk:
        require_verified(path, "android")

    from fastapi.testclient import TestClient
    from app.server import app

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        results = [run_case(client, "/api/analyze/android", path, timeout=900) for path in args.apk]
    return int(not all(results))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
