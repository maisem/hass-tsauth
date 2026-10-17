"""Build deterministic manual-install and HACS ZIPs without contacting live HA."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "tsidp"


def component_files() -> list[Path]:
    """Only ship runtime sources, never virtualenvs, caches or credentials."""
    return (
        sorted(COMPONENT.glob("*.py"))
        + sorted(COMPONENT.glob("*.js"))
        + sorted(COMPONENT.glob("*.json"))
        + sorted((COMPONENT / "translations").glob("*.json"))
    )


def write_archive(output: Path, files: list[tuple[Path, str]]) -> Path:
    """Write stable paths, timestamps, permissions and checksums on every build."""
    output.parent.mkdir(exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path, name in sorted(files, key=lambda item: item[1]):
            info = ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".zip.sha256").write_text(
        f"{digest}  {output.name}\n", encoding="utf-8", newline="\n"
    )
    return output


def build() -> Path:
    """Keep the versioned manual ZIP with its /config-relative folder structure."""
    manifest = json.loads((COMPONENT / "manifest.json").read_text())
    files = component_files() + [ROOT / "LICENSE", ROOT / "README.md"]
    return write_archive(
        ROOT / "dist" / f"tsidp-{manifest['version']}.zip",
        [(path, path.relative_to(ROOT).as_posix()) for path in files],
    )


def build_hacs() -> Path:
    """HACS extracts this ZIP directly into custom_components/tsidp."""
    return write_archive(
        ROOT / "dist" / "tsidp.zip",
        [(path, path.relative_to(COMPONENT).as_posix()) for path in component_files()],
    )


if __name__ == "__main__":
    print(build())
    print(build_hacs())
