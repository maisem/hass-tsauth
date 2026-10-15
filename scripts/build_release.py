"""Build a deterministic manual-install ZIP; never connect to a live HA instance."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "tsidp"


def build() -> Path:
    """Only ship source and documentation, never virtualenvs, caches or credentials."""
    manifest = json.loads((COMPONENT / "manifest.json").read_text())
    output = ROOT / "dist" / f"tsidp-{manifest['version']}.zip"
    output.parent.mkdir(exist_ok=True)
    files = sorted(COMPONENT.glob("*.py")) + [COMPONENT / "manifest.json"]
    files += [ROOT / "LICENSE", ROOT / "README.md"]
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = ZipInfo(path.relative_to(ROOT).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".zip.sha256").write_text(f"{digest}  {output.name}\n")
    return output


if __name__ == "__main__":
    print(build())
