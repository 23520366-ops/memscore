"""Load the local allowlist used before starting a sample in a guest."""
import json
import os
from pathlib import Path

ALLOWLIST_PATH = Path(__file__).resolve().parent / "config" / "allowed_samples.json"
ALLOWED_SAMPLES: dict[str, dict[str, dict]] = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))


class SampleNotAllowed(ValueError):
    """The uploaded file is ineligible for live measurement."""


def require_allowed_sample(platform: str, sha256: str) -> dict:
    sample = ALLOWED_SAMPLES[platform].get(sha256)
    if sample is not None:
        return sample
    if os.environ.get("MEMSCOPE_ALLOW_ANY_SAMPLE") == "1":
        return {}
    raise SampleNotAllowed("SHA-256 does not match a verified clean sample.")
