"""Narrow security checks must not become calendar/module/build allowlists."""

from types import SimpleNamespace

import pytest

from custom_components.tsidp import compatibility


def native_finish(result):
    return {"mfa": True, "result": result}


def changed_finish(result):
    return {"mfa": False, "result": result}


def test_only_named_security_callables_are_checked(monkeypatch):
    good = SimpleNamespace(Finish=SimpleNamespace(run=native_finish), unrelated="changed")
    monkeypatch.setattr(compatibility, "import_module", lambda _: good)
    monkeypatch.setattr(
        compatibility,
        "SECURITY_CONTRACTS",
        {"future.module:Finish.run": (compatibility.security_fingerprint(native_finish),)},
    )
    compatibility.check_runtime_contracts()
    good.unrelated = "a harmless future release changed unrelated auth/frontend code"
    compatibility.check_runtime_contracts()
    good.Finish.run = changed_finish
    with pytest.raises(RuntimeError, match="Changed native security contract"):
        compatibility.check_runtime_contracts()


def test_source_comments_formatting_and_docstrings_do_not_disable_sso(monkeypatch):
    source = 'def finish(result):\n    """Old docs."""\n    return result\n'
    monkeypatch.setattr(compatibility.inspect, "getsource", lambda _: source)
    expected = compatibility.security_fingerprint(native_finish)
    source = (
        'def finish( result ):\n    """New docs."""\n    # harmless change\n    return result\n'
    )
    assert compatibility.security_fingerprint(native_finish) == expected


def test_missing_native_security_contract_requires_review(monkeypatch):
    monkeypatch.setattr(compatibility, "import_module", lambda _: SimpleNamespace())
    with pytest.raises(RuntimeError, match="Required native security callable/source"):
        compatibility.check_runtime_contracts()
