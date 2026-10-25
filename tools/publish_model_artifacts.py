"""Package trained artifacts reproducibly and upload them to Nexus."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path

import requests

from shift_lefter import experiment, trained_review

VAULT_URL = os.environ.get("SHIFT_LEFTER_VAULT_URL", "").rstrip("/")
NEXUS_ROOT = os.environ.get("SHIFT_LEFTER_NEXUS_REPOSITORY_URL", "").rstrip("/")
MODELS = ("lightgbm", "granite", "qwen")


def _vault_token() -> str:
    path = Path.home() / "documents" / "vault.creds"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("VAULT_ROOT_TOKEN="):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("Vault root token is unavailable")


def _nexus_auth() -> tuple[str, str]:
    response = requests.get(
        VAULT_URL,
        headers={"X-Vault-Token": _vault_token()},
        timeout=20,
    )
    response.raise_for_status()
    values = response.json()["data"]["data"]
    username = str(values["NEXUS_USERNAME"]).lower()
    password = str(values["NEXUS_PASSWORD"])
    if not username or not password:
        raise RuntimeError("Nexus credentials are incomplete")
    return username, password


def _model_root(name: str) -> Path:
    return experiment._research_root() / "models" / trained_review.DATASET_NAME / name


def _included_files(root: Path) -> list[Path]:
    names = ("adapter", "model.joblib", "training-manifest.json", "thresholds.json")
    files = []
    for name in names:
        path = root / name
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file()))
    if not any(path.name == "training-manifest.json" for path in files):
        raise RuntimeError(f"training manifest is missing from {root}")
    if not any(
        path.name in {"model.joblib", "adapter_model.safetensors"} for path in files
    ):
        raise RuntimeError(f"trained model artifact is missing from {root}")
    return sorted(files)


def _package(root: Path, destination: Path) -> None:
    with destination.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for path in _included_files(root):
                    relative = path.relative_to(root)
                    info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    info.mode = 0o644
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _put(url: str, data, auth: tuple[str, str], content_type: str) -> None:
    response = requests.put(
        url,
        data=data,
        auth=auth,
        headers={"Content-Type": content_type},
        timeout=1800,
    )
    if response.status_code not in {200, 201, 204}:
        raise RuntimeError(
            f"Nexus upload failed with HTTP {response.status_code}: "
            f"{response.text[:200]}"
        )


def publish() -> dict:
    auth = _nexus_auth()
    published = {}
    with tempfile.TemporaryDirectory(
        prefix="shift-lefter-models-",
        dir=experiment._research_root(),
    ) as temporary:
        temporary_path = Path(temporary)
        for name in MODELS:
            root = _model_root(name)
            archive = temporary_path / f"{name}.tar.gz"
            _package(root, archive)
            digest = _sha256(archive)
            version = digest[:16]
            base = f"{NEXUS_ROOT}/{name}/{version}"
            with archive.open("rb") as handle:
                _put(
                    f"{base}/{archive.name}",
                    handle,
                    auth,
                    "application/gzip",
                )
            checksum = (digest + "  " + archive.name + "\n").encode()
            _put(
                f"{base}/{archive.name}.sha256",
                checksum,
                auth,
                "text/plain",
            )
            response = requests.get(
                f"{base}/{archive.name}",
                auth=auth,
                stream=True,
                timeout=1800,
            )
            response.raise_for_status()
            downloaded = hashlib.sha256()
            for block in response.iter_content(1024 * 1024):
                downloaded.update(block)
            if downloaded.hexdigest() != digest:
                raise RuntimeError(f"Nexus checksum verification failed for {name}")
            published[name] = {
                "version": version,
                "sha256": digest,
                "size_bytes": archive.stat().st_size,
                "artifact_path": f"{name}/{version}/{archive.name}",
                "checksum_path": f"{name}/{version}/{archive.name}.sha256",
                "download_verified": True,
            }
    result = {
        "repository": "shift-lefter-models",
        "write_policy": "ALLOW_ONCE",
        "dataset_name": trained_review.DATASET_NAME,
        "artifacts": published,
    }
    destination = (
        experiment._research_root()
        / "sanitized-results"
        / "evaluation-v8-trained-review"
        / "model-publication.json"
    )
    experiment._write_json(destination, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(publish(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
