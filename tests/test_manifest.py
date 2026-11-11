import json
from pathlib import Path


def test_requirements_are_not_exact_pins():
    # Home Assistant constrains shared packages (httpx2 among them) to its own
    # versions; an exact pin here stops the integration loading after an update.
    manifest = json.loads(Path("custom_components/tsidp/manifest.json").read_text())
    assert all("==" not in requirement for requirement in manifest["requirements"])
