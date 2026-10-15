"""The build ships only intended sources and is byte-for-byte reproducible."""

import hashlib
import json
from zipfile import ZipFile

from scripts import build_release


def test_reproducible_release_and_no_caches_or_credentials(tmp_path, monkeypatch):
    component = tmp_path / "custom_components" / "tsidp"
    component.mkdir(parents=True)
    (component / "manifest.json").write_text(json.dumps({"version": "0.1.0"}))
    (component / "__init__.py").write_text('"""Test fixture."""\n')
    (component / "private.token").write_text("never-ship-this")
    (component / "__pycache__").mkdir()
    (component / "__pycache__" / "compiled.pyc").write_bytes(b"never-ship-this")
    (tmp_path / "LICENSE").write_text("License fixture\n")
    (tmp_path / "README.md").write_text("Readme fixture\n")
    monkeypatch.setattr(build_release, "ROOT", tmp_path)
    monkeypatch.setattr(build_release, "COMPONENT", component)
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
            "custom_components/tsidp/manifest.json",
        ]
        assert all(info.date_time == (2026, 1, 1, 0, 0, 0) for info in archive.infolist())
