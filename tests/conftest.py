import datetime as dt

import pytest
import shio

from shio_iam import connectors

NOW = dt.datetime(2026, 10, 23, 9, 0, tzinfo=dt.timezone.utc)
DAN = "dan.okafor@northwind.example"
SAM = "sam.chen@northwind.example"
MARIA = "maria.lopez@northwind.example"


@pytest.fixture
def org(tmp_path, monkeypatch):
    """A fresh Northwind Labs org and workspace per test, with a fixed clock."""
    monkeypatch.setenv("SHIO_IAM_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SHIO_SIGNING_KEY", raising=False)
    monkeypatch.setenv("SHIO_IAM_MODEL", "scripted")
    o = connectors.use(connectors.MockOrg(tmp_path / "home" / "org-state.json", now=NOW))
    yield o
    shio.configure(None)
    connectors.use(None)
