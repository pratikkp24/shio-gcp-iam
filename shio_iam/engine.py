"""Running iam.shio: ask a question or propose a change, approve it, apply it. Each step is a signed record.

    from shio_iam import engine
    out, record = engine.ask("give Priya Raman read access to the billing dataset for two weeks", "dan.okafor@northwind.example")
    engine.approve(record, "sam.chen@northwind.example")
    out, _ = engine.apply(record)
"""
import json
from pathlib import Path

import shio
from shio import ledger

from . import approvals, models

HERE = Path(__file__).resolve().parent
_PROGRAM = None


def program():
    global _PROGRAM
    if _PROGRAM is None:
        _PROGRAM = shio.load(HERE / "iam.shio", name="shio_iam_program")
    return _PROGRAM


def setup():
    models.load_env()
    approvals.ensure_keys()
    approvals.records().mkdir(parents=True, exist_ok=True)


def ask(request, requester, llm=None):
    """-> (outcome, record path). The outcome is ANSWER, CLARIFY, REFUSE, or PENDING with the APPLY it decided."""
    setup()
    shio.configure(str(approvals.records()), actor=requester, signer=ledger.load_signer())
    llm = llm or models.chosen()[0]
    out = program().ask(request, requester, llm)
    return out, program().ask.last_trace


def approve(record, by, note="", reject=False):
    setup()
    return approvals.approve(record, by, note=note, reject=reject)


def apply(record, planner=None, actor="shio-iam"):
    """Write an approved change. -> (outcome, record path of the apply run)."""
    setup()
    shio.configure(str(approvals.records()), actor=actor, signer=ledger.load_signer())
    rec = json.loads(Path(record).read_text())
    decided = (rec.get("outcome") or {}).get("decided") or rec.get("outcome") or {}
    request = decided.get("request", "")
    planner = planner or models.chosen()[1]
    out = program().apply(str(record), request, planner)
    if isinstance(out, dict) and out.get("action") == "APPLIED":
        approvals.mark_applied(Path(record).name, out["applied"])
    return out, program().apply.last_trace


def outcome_of(out):
    """The decided outcome, whether or not it waits for sign-off."""
    if isinstance(out, dict) and out.get("status") == "PENDING":
        return {**out["decided"], "pending": out["signoff"]}
    return out
