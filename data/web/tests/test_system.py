import subprocess

import pytest

from crassostrea.services import system

SHOW = """Id=postfix.service
Description=Postfix Mail Transport Agent
LoadState=loaded
ActiveState=active
SubState=running
ActiveEnterTimestamp=Mon 2026-10-19 10:00:00 UTC

Id=clamd@crassostrea.service
Description=clamd scanner (crassostrea) daemon
LoadState=loaded
ActiveState=failed
SubState=failed
ActiveEnterTimestamp=

Id=missing.service
Description=missing.service
LoadState=not-found
ActiveState=inactive
SubState=dead
ActiveEnterTimestamp=
"""


def test_units(app, monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, SHOW, "")
    monkeypatch.setattr(system.subprocess, "run", run)
    app.config["SERVICE_UNITS"] = ["postfix.service", "clamd@crassostrea.service", "missing.service"]
    units = system.units()
    assert calls[0][:3] == ["systemctl", "show", "--no-pager"] and calls[0][-3:] == app.config["SERVICE_UNITS"]
    assert [(u["unit"], u["state"]) for u in units] == [
        ("postfix.service", "active"), ("clamd@crassostrea.service", "failed"), ("missing.service", "not-found")]
    assert units[0]["since"] == "Mon 2026-10-19 10:00:00 UTC"


def test_units_errors(app, monkeypatch):
    monkeypatch.setattr(system.subprocess, "run",
                        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "Failed to connect to bus"))
    with pytest.raises(system.SystemStatusError, match="Failed to connect to bus"):
        system.units()

    def missing(*args, **kwargs):
        raise FileNotFoundError("systemctl")
    monkeypatch.setattr(system.subprocess, "run", missing)
    with pytest.raises(system.SystemStatusError):
        system.units()
