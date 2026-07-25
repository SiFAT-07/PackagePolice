#!/usr/bin/env python3
"""Download package archives safely and extract non-executing features.

This script never runs package install hooks, imports package code, or executes
anything from downloaded archives. It only performs HTTP downloads and reads
files as plain text.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import tarfile
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests


DATASET_FIELDS = [
    "package_name",
    "version",
    "ecosystem",
    "label",
    "sha256",
    "download_url",
    "registry_name",
    "registry_description_len",
    "version_count",
    "dependency_count",
    "maintainer_count",
    "github_repo_stars",
    "github_repo_forks",
    "install_script_count",
    "red_flag_count",
    "source_file_count",
    "source_code_bytes",
    "semantic_excerpt",
]


@dataclass
class PackageSpec:
    ecosystem: str
    package_name: str
    version: str
    label: str


def read_package_list(csv_path: Path) -> list[PackageSpec]:
    rows: list[PackageSpec] = []
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        expected = {"ecosystem", "package_name", "version", "label"}
        if set(reader.fieldnames or []) != expected:
            raise ValueError(
                f"Expected columns {sorted(expected)}, got {reader.fieldnames!r}"
            )
        for row in reader:
            rows.append(
                PackageSpec(
                    ecosystem=row["ecosystem"].strip(),
                    package_name=row["package_name"].strip(),
                    version=row["version"].strip(),
                    label=row["label"].strip(),
                )
            )
    return rows


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract_tar(archive_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive.getmembers():
            member_path = (target_dir / member.name).resolve()
            if not str(member_path).startswith(str(target_dir.resolve())):
                raise ValueError(f"Refusing path traversal in tar member: {member.name}")
        archive.extractall(target_dir)


def safe_extract_zip(archive_path: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            member_path = (target_dir / member.filename).resolve()
            if not str(member_path).startswith(str(target_dir.resolve())):
                raise ValueError(f"Refusing path traversal in zip member: {member.filename}")
        archive.extractall(target_dir, pwd=b"infected")


def download_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    response = requests.get(url, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return {}


def download_file(url: str, destination: Path, headers: dict[str, str] | None = None) -> None:
    with requests.get(url, headers=headers, timeout=120, stream=True) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    handle.write(chunk)


def parse_github_repo(url_value: str | None) -> tuple[str, str] | None:
    if not url_value:
        return None
    match = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/#.]+)", url_value)
    if not match:
        return None
    return match.group("owner"), match.group("repo")


@lru_cache(maxsize=1)
def datadog_npm_tree_paths() -> list[str]:
    url = "https://api.github.com/repos/DataDog/malicious-software-packages-dataset/git/trees/main?recursive=1"
    response = requests.get(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "Mozilla/5.0"},
        timeout=120,
    )
    response.raise_for_status()
    payload = response.json()
    tree = payload.get("tree", []) if isinstance(payload, dict) else []
    return [
        item["path"]
        for item in tree
        if isinstance(item, dict)
        and isinstance(item.get("path"), str)
        and item["path"].startswith("samples/npm/malicious_intent/")
        and item["path"].endswith(".zip")
    ]


def resolve_datadog_npm_sample_url(spec: PackageSpec) -> str:
    target_prefix = f"samples/npm/malicious_intent/{spec.package_name}/{spec.version}/"
    for path in datadog_npm_tree_paths():
        if path.startswith(target_prefix):
            return "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/" + path
    raise ValueError(f"No DataDog sample found for {spec.package_name} {spec.version}")


def count_source_files(root: Path) -> tuple[int, int, str]:
    text_extensions = {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".toml",
        ".txt",
        ".md",
        ".yaml",
        ".yml",
        ".cfg",
        ".ini",
    }
    file_count = 0
    byte_count = 0
    excerpt_parts: list[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        file_count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if path.suffix.lower() in text_extensions:
            byte_count += len(text.encode("utf-8", errors="ignore"))
            if len(excerpt_parts) < 5 and text.strip():
                excerpt_parts.append(f"## {path.name}\n{text[:2000]}")
    excerpt = "\n\n".join(excerpt_parts)[:10000]
    excerpt = excerpt.replace("\r", " ").replace("\n", "\\n")
    return file_count, byte_count, excerpt


def count_install_risks(root: Path) -> tuple[int, int]:
    script_keywords = [
        "preinstall",
        "postinstall",
        "install",
        "prepare",
        "setup.py",
        "subprocess",
        "os.system",
        "eval(",
        "exec(",
        "base64",
        "curl",
        "wget",
    ]
    install_script_count = 0
    red_flag_count = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.name == "package.json":
            try:
                package_json = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except json.JSONDecodeError:
                continue
            scripts = package_json.get("scripts", {})
            if isinstance(scripts, dict):
                for name, value in scripts.items():
                    if name in {"preinstall", "install", "postinstall", "prepare"}:
                        install_script_count += 1
                    text = f"{name} {value}".lower()
                    red_flag_count += sum(keyword in text for keyword in script_keywords)
        elif path.suffix.lower() in {".py", ".js", ".ts", ".json", ".sh"}:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            red_flag_count += sum(keyword in text for keyword in script_keywords)
    return install_script_count, red_flag_count


def first_package_json(root: Path) -> dict[str, Any]:
    for path in [root / "package.json", *root.rglob("package.json")]:
        if path.is_file():
            return read_json_file(path)
    return {}


def fetch_github_repo_stats(version_meta: dict[str, Any], repository_value: Any, token: str | None) -> dict[str, int]:
    candidate_urls: list[str] = []
    if isinstance(repository_value, dict):
        repo_url = repository_value.get("url")
        if isinstance(repo_url, str):
            candidate_urls.append(repo_url)
    elif isinstance(repository_value, str):
        candidate_urls.append(repository_value)

    if isinstance(version_meta, dict):
        repo_meta = version_meta.get("repository")
        if isinstance(repo_meta, dict):
            repo_url = repo_meta.get("url")
            if isinstance(repo_url, str):
                candidate_urls.append(repo_url)
        project_url = version_meta.get("project_url")
        if isinstance(project_url, str):
            candidate_urls.append(project_url)

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for value in candidate_urls:
        repo = parse_github_repo(value)
        if not repo:
            continue
        owner, name = repo
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{name}",
            headers=headers,
            timeout=30,
        )
        if response.status_code != 200:
            continue
        payload = response.json()
        return {
            "stars": int(payload.get("stargazers_count", 0) or 0),
            "forks": int(payload.get("forks_count", 0) or 0),
        }

    return {"stars": 0, "forks": 0}


def extract_npm_features(metadata: dict[str, Any], extracted_dir: Path, token: str | None) -> dict[str, Any]:
    versions = metadata.get("versions", {}) if isinstance(metadata.get("versions", {}), dict) else {}
    version_count = len(versions) if versions else int(bool(metadata.get("version")))
    latest = metadata.get("dist-tags", {}).get("latest", "") if isinstance(metadata.get("dist-tags", {}), dict) else ""
    version_meta = metadata.get("versions", {}).get(latest, {}) if isinstance(metadata.get("versions", {}), dict) else {}
    if not isinstance(version_meta, dict) or not version_meta:
        version_meta = metadata

    dependencies = version_meta.get("dependencies", {}) or metadata.get("dependencies", {})
    dependency_count = len(dependencies) if isinstance(dependencies, dict) else 0
    maintainers = metadata.get("maintainers", [])
    maintainer_count = len(maintainers) if isinstance(maintainers, list) else 0

    repo_stats = fetch_github_repo_stats(version_meta, metadata.get("repository"), token)
    install_script_count, red_flag_count = count_install_risks(extracted_dir)
    source_file_count, source_code_bytes, excerpt = count_source_files(extracted_dir)

    return {
        "registry_name": metadata.get("name", ""),
        "registry_description_len": len((metadata.get("description") or metadata.get("summary") or "") or ""),
        "version_count": version_count,
        "dependency_count": dependency_count,
        "maintainer_count": maintainer_count,
        "github_repo_stars": repo_stats.get("stars", 0),
        "github_repo_forks": repo_stats.get("forks", 0),
        "install_script_count": install_script_count,
        "red_flag_count": red_flag_count,
        "source_file_count": source_file_count,
        "source_code_bytes": source_code_bytes,
        "semantic_excerpt": excerpt,
    }


def extract_pypi_features(metadata: dict[str, Any], extracted_dir: Path, token: str | None) -> dict[str, Any]:
    info = metadata.get("info", {}) if isinstance(metadata.get("info", {}), dict) else {}
    dependency_lines = info.get("requires_dist", [])
    dependency_count = len(dependency_lines) if isinstance(dependency_lines, list) else 0
    maintainer_count = int(bool(info.get("maintainer"))) + int(bool(info.get("author")))
    version_count = len(metadata.get("releases", {})) if isinstance(metadata.get("releases", {}), dict) else 0

    repo_stats = fetch_github_repo_stats(info, info.get("project_urls") or info.get("home_page"), token)
    install_script_count, red_flag_count = count_install_risks(extracted_dir)
    source_file_count, source_code_bytes, excerpt = count_source_files(extracted_dir)

    return {
        "registry_name": info.get("name", ""),
        "registry_description_len": len(info.get("summary", "") or ""),
        "version_count": version_count,
        "dependency_count": dependency_count,
        "maintainer_count": maintainer_count,
        "github_repo_stars": repo_stats.get("stars", 0),
        "github_repo_forks": repo_stats.get("forks", 0),
        "install_script_count": install_script_count,
        "red_flag_count": red_flag_count,
        "source_file_count": source_file_count,
        "source_code_bytes": source_code_bytes,
        "semantic_excerpt": excerpt,
    }


def make_output_dirs(base_dir: Path, spec: PackageSpec) -> Path:
    package_dir = base_dir / "quarantine" / spec.ecosystem / spec.label / f"{spec.package_name}-{spec.version}"
    package_dir.mkdir(parents=True, exist_ok=True)
    return package_dir


def npm_metadata_url(spec: PackageSpec) -> str:
    if spec.version:
        return f"https://registry.npmjs.org/{spec.package_name}/{spec.version}"
    return f"https://registry.npmjs.org/{spec.package_name}"


def pypi_metadata_url(spec: PackageSpec) -> str:
    if spec.version:
        return f"https://pypi.org/pypi/{spec.package_name}/{spec.version}/json"
    return f"https://pypi.org/pypi/{spec.package_name}/json"


def download_npm_package(metadata: dict[str, Any], package_dir: Path) -> tuple[Path, Path]:
    dist = metadata.get("dist", {})
    if not isinstance(dist, dict) or not dist.get("tarball"):
        raise ValueError("npm metadata did not include a tarball URL")
    archive_path = package_dir / "package.tgz"
    download_file(dist["tarball"], archive_path)
    safe_extract_tar(archive_path, package_dir / "src")
    return archive_path, package_dir / "src"


def download_datadog_npm_package(spec: PackageSpec, package_dir: Path) -> tuple[Path, Path, str]:
    sample_url = resolve_datadog_npm_sample_url(spec)
    archive_name = sample_url.rsplit("/", 1)[-1]
    archive_path = package_dir / archive_name
    download_file(sample_url, archive_path)
    extract_root = package_dir / "src"
    safe_extract_zip(archive_path, extract_root)
    return archive_path, extract_root, sample_url


def download_pypi_package(metadata: dict[str, Any], package_dir: Path) -> tuple[Path, Path]:
    urls = metadata.get("urls", [])
    if not isinstance(urls, list) or not urls:
        raise ValueError("PyPI metadata did not include download URLs")
    chosen = None
    for entry in urls:
        if isinstance(entry, dict) and entry.get("url"):
            chosen = entry["url"]
            if str(entry.get("packagetype", "")).lower() in {"sdist", "bdist_wheel"}:
                break
    if not chosen:
        raise ValueError("PyPI metadata did not include a usable file URL")

    archive_name = chosen.split("?")[0].rsplit("/", 1)[-1]
    archive_path = package_dir / archive_name
    download_file(chosen, archive_path)
    extract_root = package_dir / "src"
    if archive_path.suffix == ".zip" or archive_name.endswith(".whl"):
        safe_extract_zip(archive_path, extract_root)
    else:
        safe_extract_tar(archive_path, extract_root)
    return archive_path, extract_root


def process_package(spec: PackageSpec, workspace_root: Path, token: str | None) -> dict[str, Any]:
    package_dir = make_output_dirs(workspace_root, spec)
    if spec.ecosystem == "npm" and spec.label == "malicious":
        archive_path, extracted_dir, download_url = download_datadog_npm_package(spec, package_dir)
        metadata = first_package_json(extracted_dir)
        feature_map = extract_npm_features(metadata, extracted_dir, token)
    elif spec.ecosystem == "npm":
        metadata_url = npm_metadata_url(spec)
        metadata = download_json(metadata_url)
        archive_path, extracted_dir = download_npm_package(metadata, package_dir)
        feature_map = extract_npm_features(metadata, extracted_dir, token)
        download_url = metadata.get("dist", {}).get("tarball", "") if isinstance(metadata.get("dist", {}), dict) else ""
    elif spec.ecosystem == "pypi":
        metadata_url = pypi_metadata_url(spec)
        metadata = download_json(metadata_url)
        archive_path, extracted_dir = download_pypi_package(metadata, package_dir)
        feature_map = extract_pypi_features(metadata, extracted_dir, token)
        download_url = ""
        urls = metadata.get("urls", [])
        if isinstance(urls, list) and urls:
            first = urls[0]
            if isinstance(first, dict):
                download_url = first.get("url", "") or ""
    else:
        raise ValueError(f"Unsupported ecosystem: {spec.ecosystem}")

    row = {
        "package_name": spec.package_name,
        "version": spec.version,
        "ecosystem": spec.ecosystem,
        "label": spec.label,
        "sha256": sha256_file(archive_path),
        "download_url": download_url,
        **feature_map,
    }
    return row


def ensure_dataset_file(dataset_path: Path) -> None:
    if dataset_path.exists() and dataset_path.stat().st_size > 0:
        return
    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    with dataset_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_FIELDS)
        writer.writeheader()


def load_existing_keys(dataset_path: Path) -> set[tuple[str, str, str]]:
    if not dataset_path.exists() or dataset_path.stat().st_size == 0:
        return set()
    with dataset_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        keys = set()
        for row in reader:
            keys.add((row.get("package_name", ""), row.get("version", ""), row.get("ecosystem", "")))
        return keys


def append_row(dataset_path: Path, row: dict[str, Any]) -> None:
    with dataset_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_FIELDS)
        if handle.tell() == 0:
            writer.writeheader()
        writer.writerow({key: row.get(key, "") for key in DATASET_FIELDS})


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely download packages and build the dataset.")
    parser.add_argument("--list", required=True, help="CSV with ecosystem,package_name,version,label")
    parser.add_argument(
        "--workspace-root",
        default=str(Path.cwd().parent),
        help="Project root containing dataset/, quarantine/, and logs/",
    )
    args = parser.parse_args()

    workspace_root = Path(args.workspace_root).resolve()
    package_list = Path(args.list).resolve()
    dataset_path = workspace_root / "dataset" / "dataset.csv"
    ensure_dataset_file(dataset_path)
    existing_keys = load_existing_keys(dataset_path)
    token = os.environ.get("GITHUB_TOKEN")

    rows = read_package_list(package_list)
    for spec in rows:
        key = (spec.package_name, spec.version, spec.ecosystem)
        if key in existing_keys:
            continue
        try:
            row = process_package(spec, workspace_root, token)
        except Exception as exc:  # pragma: no cover - preserve partial progress on failures
            log_path = workspace_root / "logs" / "safe_collect_errors.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{spec.ecosystem},{spec.package_name},{spec.version},{spec.label}: {exc}\n")
            continue
        append_row(dataset_path, row)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())