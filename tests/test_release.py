"""The build ships only intended sources and is byte-for-byte reproducible."""

import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from scripts import build_release


def prepare_sources(tmp_path, monkeypatch):
    component = tmp_path / "custom_components" / "tsidp"
    component.mkdir(parents=True)
    (component / "manifest.json").write_text(json.dumps({"version": "0.1.0"}))
    (component / "__init__.py").write_text('"""Test fixture."""\n')
    (component / "frontend.js").write_text("// Login restart bridge\n")
    (component / "strings.json").write_text('{"issues": {}}\n')
    (component / "translations").mkdir()
    (component / "translations" / "en.json").write_text('{"issues": {}}\n')
    (component / "private.token").write_text("never-ship-this")
    (component / "__pycache__").mkdir()
    (component / "__pycache__" / "compiled.pyc").write_bytes(b"never-ship-this")
    (tmp_path / "LICENSE").write_text("License fixture\n")
    (tmp_path / "README.md").write_text("Readme fixture\n")
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    monkeypatch.setattr(build_release, "COMPONENT", component)


def test_reproducible_release_and_no_caches_or_credentials(tmp_path, monkeypatch):
    prepare_sources(tmp_path, monkeypatch)
    artifact = build_release.build()
    original = artifact.read_bytes()
    assert build_release.build().read_bytes() == original
    digest = hashlib.sha256(original).hexdigest()
    assert artifact.with_suffix(".zip.sha256").read_text() == f"{digest}  {artifact.name}\n"
    with ZipFile(artifact) as archive:
        assert sorted(archive.namelist()) == [
            "LICENSE",
            "README.md",
            "custom_components/tsidp/__init__.py",
            "custom_components/tsidp/frontend.js",
            "custom_components/tsidp/manifest.json",
            "custom_components/tsidp/strings.json",
            "custom_components/tsidp/translations/en.json",
        ]
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in archive.infolist())


def test_hacs_release_has_installable_root_layout_and_stable_checksum(tmp_path, monkeypatch):
    prepare_sources(tmp_path, monkeypatch)
    artifact = build_release.build_hacs()
    original = artifact.read_bytes()
    assert build_release.build_hacs().read_bytes() == original
    assert artifact.name == "tsidp.zip"
    digest = hashlib.sha256(original).hexdigest()
    assert artifact.with_suffix(".zip.sha256").read_text() == f"{digest}  {artifact.name}\n"

    # HACS extracts release ZIPs straight into custom_components/<domain>/.
    installed = tmp_path / "ha-config" / "custom_components" / "tsidp"
    with ZipFile(artifact) as archive:
        assert sorted(archive.namelist()) == [
            "__init__.py",
            "frontend.js",
            "manifest.json",
            "strings.json",
            "translations/en.json",
        ]
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in archive.infolist())
        assert all(info.create_system == 3 for info in archive.infolist())
        archive.extractall(installed)
    assert json.loads((installed / "manifest.json").read_text())["version"] == "0.1.0"
    assert (installed / "frontend.js").read_text() == "// Login restart bridge\n"
    assert not (installed / "custom_components").exists()


def test_hacs_metadata_matches_release_builder():
    root = Path(__file__).resolve().parents[1]
    metadata = json.loads((root / "hacs.json").read_text())
    assert metadata["zip_release"] is True
    assert metadata["filename"] == "tsidp.zip"
    assert metadata["hide_default_branch"] is True
    assert metadata.get("content_in_root", False) is False
