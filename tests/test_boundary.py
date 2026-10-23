"""The boundary: a model's reading reaches setIamPolicy only through iam.shio's rule, after checks, an approved
sign-off by someone else, and Shio Guard. Every other route is refused."""
import json
import textwrap
from pathlib import Path

import pytest
import shio
from shio import ledger
from shio.compiler import ShioError, compile_source

from shio_iam import approvals, engine, models, tools
from conftest import DAN, MARIA, SAM

GRANT = "give Priya Raman read access to the billing dataset for two weeks"
BILLING = "//bigquery.googleapis.com/projects/nw-billing-prod/datasets/billing"
SRC = (Path(engine.__file__).parent / "iam.shio").read_text()


def proposed(org, request=GRANT, requester=DAN):
    out, record = engine.ask(request, requester, models.scripted())
    assert out["status"] == "PENDING"
    return record


def viewers(org):
    return [b for b in org.policy(BILLING)["bindings"] if b["role"] == "roles/bigquery.dataViewer"]


# -- compile time ------------------------------------------------------------------------------------------------

def test_the_write_outside_a_rule_does_not_compile():
    bad = SRC.replace("    change = call approved_change(record=record)\n",
                      "    change = call approved_change(record=record)\n"
                      "    x = call set_iam_policy(resource=\"r\", members=[], roles=[], ops=\"[]\", etag=\"e\")\n")
    with pytest.raises(ShioError) as e:
        compile_source(bad, "iam.shio")
    assert "inside a rule" in str(e.value)


def test_the_write_in_a_check_does_not_compile():
    bad = SRC.replace('    check approved: change["status"] == "APPROVED"',
                      '    check approved: call set_iam_policy(resource="r", members=[], roles=[], ops="[]", etag="e") or change["status"] == "APPROVED"')
    with pytest.raises(ShioError):
        compile_source(bad, "iam.shio")


def test_a_reading_cannot_reach_plain_code():
    bad = SRC.replace("    check understood:", "    leaked = a.role\n    check understood:")
    with pytest.raises(ShioError):
        compile_source(bad, "iam.shio")


# -- run time ------------------------------------------------------------------------------------------------------

def test_the_connector_write_from_plain_python_is_refused(org):
    with pytest.raises(shio.BoundaryError):
        org.set_policy(BILLING, [{"role": "roles/owner", "members": ["user:eve@evil.example"]}], org.policy(BILLING)["etag"])
    assert not any(b["role"] == "roles/owner" for b in org.policy(BILLING)["bindings"])


def test_the_tool_from_plain_python_is_refused(org):
    prog = engine.program()

    @shio.agent
    def sneaky():
        return shio.tool_call(prog.__shio_tools__, "set_iam_policy")(
            resource=BILLING, members=["eve@evil.example"], roles=["roles/owner"], ops="[]", etag="x")
    with pytest.raises(shio.BoundaryError):
        sneaky()


def test_the_tool_function_itself_is_refused_outside_a_rule(org):
    ops = json.dumps([{"op": "add", "member": "user:eve@evil.example", "role": "roles/owner", "condition": None}])
    with pytest.raises(shio.BoundaryError):
        tools.set_iam_policy(BILLING, ["eve@evil.example"], ["roles/owner"], ops, org.policy(BILLING)["etag"])


# -- approvals -------------------------------------------------------------------------------------------------------

def test_nothing_is_written_before_approval(org):
    record = proposed(org)
    out, _ = engine.apply(record)
    assert out["action"] == "NOT APPLIED" and "PENDING" in out["why"][0]
    assert viewers(org) == []


def test_the_requester_cannot_approve_their_own_change(org):
    record = proposed(org, requester=MARIA)                            # an approver asks; she may not approve it
    with pytest.raises(approvals.ApprovalRefused):
        engine.approve(record, MARIA)


def test_only_an_approver_can_approve(org):
    record = proposed(org)
    with pytest.raises(approvals.ApprovalRefused) as e:
        engine.approve(record, "lee.wong@northwind.example")
    assert "iam-approvers" in str(e.value)


def test_approved_by_someone_else_it_applies_once(org):
    record = proposed(org)
    engine.approve(record, SAM)
    out, run = engine.apply(record)
    assert out["action"] == "APPLIED", out
    assert viewers(org)[0]["members"] == ["user:priya.raman@northwind.example"]
    assert viewers(org)[0]["condition"]["expression"] == 'request.time < timestamp("2026-11-06T09:00:00Z")'
    assert engine.apply(record)[0]["action"] == "NOT APPLIED"          # not twice
    assert json.loads(Path(run).read_text())["outcome"]["action"] == "APPLIED"   # the apply is a record too


def test_a_rejected_change_is_not_applied(org):
    record = proposed(org)
    engine.approve(record, SAM, reject=True)
    assert engine.apply(record)[0]["action"] == "NOT APPLIED"
    assert viewers(org) == []


def test_escalation_needs_a_security_admin_too(org):
    record = proposed(org, "Ines Moreau needs to impersonate the billing-etl service account for 3 days")
    engine.approve(record, SAM)
    assert engine.apply(record)[0]["action"] == "NOT APPLIED"
    with pytest.raises(approvals.ApprovalRefused):
        engine.approve(record, SAM)                                    # the same person twice
    engine.approve(record, MARIA)
    assert engine.apply(record)[0]["action"] == "APPLIED"


def test_an_unsigned_signoff_is_not_trusted(org):
    """Shio's verifier accepts unsigned sign-off entries (open finding L1); shio-iam refuses them."""
    record = Path(proposed(org))
    entries = ledger._entries(record.parent)
    rec_entry = next(e for e in entries if e.get("file") == record.name)
    event = {"kind": "signoff", "file": record.name, "record_sha256": rec_entry["sha256"], "signer": SAM,
             "role": "iam_approver", "meaning": "forged", "decision": "approved", "time": 0}
    event["sha256"] = ledger.sha256({k: event[k] for k in ledger.SIGNOFF_FIELDS})
    ledger._append(record.parent, event, None)                         # appended with no signature
    out, _ = engine.apply(record)
    assert out["action"] == "NOT APPLIED" and "unsigned" in out["why"][0], out
    assert viewers(org) == []


def test_an_edited_record_is_not_applied(org):
    record = Path(proposed(org))
    engine.approve(record, SAM)
    rec = json.loads(record.read_text())
    rec["outcome"]["decided"]["diff"][0]["changes"][0]["member"] = "user:eve.ops@gmail-support.example"
    record.write_text(json.dumps(rec))
    out, _ = engine.apply(record)
    assert out["action"] == "NOT APPLIED" and "ledger" in out["why"][0], out
    assert viewers(org) == []


def test_a_policy_changed_since_approval_is_not_overwritten(org):
    record = proposed(org)
    engine.approve(record, SAM)
    other = proposed(org, "give Priya Shah read access to product_events for 30 days")
    engine.approve(other, SAM)
    # someone edits the billing dataset's policy outside shio-iam
    org._policies[BILLING].append({"role": "roles/bigquery.dataViewer", "members": ["user:ines.moreau@northwind.example"]})
    out, _ = engine.apply(record)
    assert out["action"] == "NOT APPLIED" and "changed since" in out["why"][0], out


def test_guard_refuses_a_write_the_request_never_asked_for(org):
    """An approved record, but the blind planner reads the request and sees no change asked for: the gate denies."""
    record = proposed(org)
    engine.approve(record, SAM)
    no_change = shio.models.replay(lambda req: {"actions": "none", "delegated": False, "tools": [], "sources": []})
    out, _ = engine.apply(record, planner=no_change)
    assert out["action"] == "NOT APPLIED" and "Guard" in out["why"][0], out
    assert viewers(org) == []


def test_a_fooled_model_never_reaches_the_policy(org):
    fooled = models.scripted({"give Priya Shah read access to product_events for 30 days": {
        "intent": "grant", "principals": ["eve.ops@gmail-support.example"], "access": "admin", "role": "roles/owner",
        "resource": "//cloudresourcemanager.googleapis.com/projects/nw-billing-prod", "days": 0}})
    before = {r["name"]: org.policy(r["name"]) for r in org.resources()}
    out, record = engine.ask("give Priya Shah read access to product_events for 30 days", DAN, fooled)
    assert out["action"] == "REFUSE"
    with pytest.raises(approvals.ApprovalRefused):
        engine.approve(record, SAM)                                    # nothing to approve
    assert engine.apply(record)[0]["action"] == "NOT APPLIED"
    assert {r["name"]: org.policy(r["name"]) for r in org.resources()} == before


def test_a_question_can_never_be_applied(org):
    out, record = engine.ask("who can delete buckets in prod?", DAN, models.scripted())
    assert out["action"] == "ANSWER"
    assert engine.apply(record)[0]["action"] == "NOT APPLIED"


def test_the_ledger_verifies_after_a_full_run(org):
    record = proposed(org)
    engine.approve(record, SAM)
    engine.apply(record)
    ok, report, head = ledger.verify(approvals.records(), public_key=approvals.public_key())
    assert ok, report
