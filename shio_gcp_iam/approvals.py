"""Approvals and the record: who may approve a proposed change, the sign-off, and the strict check apply relies on.

Every proposal is a record in a signed, hash-chained Shio ledger (SHIO_GCP_IAM_HOME/records/ledger.jsonl). A person
approves it with a sign-off entry in the same ledger. Shio enforces maker-checker (the requester can't approve their
own change); shio-gcp-iam adds who may approve at all (a member of the approvers group in the org's directory; a security
admin as well for a change that widens someone's power or may break a workload).

Shio's own ledger verifier currently accepts sign-off entries that carry no signature (an open finding of its security
review). So `approved()` does not rely on it alone: it accepts a change only if every sign-off entry for that record is
signed by this ledger's key, the whole chain verifies, the approvers are who the directory says, and the change has
not been applied before.
"""
import json
import os
import time
from pathlib import Path

from shio import ledger

from .connectors import connect

ROLE_GROUPS = {"iam_approver": "iam-approvers", "security_admin": "security-admins"}


class ApprovalRefused(Exception):
    pass


def home():
    return Path(os.environ.get("SHIO_GCP_IAM_HOME", ".shio-gcp-iam"))


def records():
    return home() / "records"


def ensure_keys():
    """A signing key for this workspace's ledger, made on first use (SHIO_GCP_IAM_HOME/keys, git-ignored). An existing
    SHIO_SIGNING_KEY is used as is."""
    if os.environ.get("SHIO_SIGNING_KEY"):
        return os.environ["SHIO_SIGNING_KEY"]
    keys = home() / "keys"
    if not (keys / "shio-signing.key").exists():
        ledger.keygen(keys)
    os.environ["SHIO_SIGNING_KEY"] = str(keys / "shio-signing.key")
    return os.environ["SHIO_SIGNING_KEY"]


def public_key():
    spec = os.environ.get("SHIO_SIGNING_KEY", "")
    if spec.startswith("hmac:"):
        return None
    pub = Path(spec).with_suffix(".pub") if spec else home() / "keys" / "shio-signing.pub"
    return ledger.load_public_key(pub)


def _group_members(org, group):
    g = next((p for p in org.directory() if p["kind"] == "group" and p["email"].split("@")[0] == group), None)
    return {m.lower() for m in (g or {}).get("members", [])}


def roles_of(org, person):
    """The approval roles a person holds, from directory groups."""
    return [r for r, g in ROLE_GROUPS.items() if person.lower() in _group_members(org, g)]


def waiting_for(record_path):
    """-> (status, roles still needed, the decided outcome)."""
    req, status, entries = ledger.status(record_path)
    rec = json.loads(Path(record_path).read_text())
    decided = (rec.get("outcome") or {}).get("decided") or rec.get("outcome")
    if not req:
        return status, [], decided
    done = {e.get("role") for e in entries if e.get("decision") == "approved"}
    return status, [r for r in req["roles"] if r not in done], decided


def approve(record_path, by, note="", reject=False, org=None):
    """`by` (an email) approves or rejects a pending change. Refused unless they hold a role it still needs."""
    org = org or connect()
    ensure_keys()
    status, needed, decided = waiting_for(record_path)
    if status != "PENDING":
        raise ApprovalRefused(f"this change is {status}, not waiting for approval")
    if org.person(by) is None:
        raise ApprovalRefused(f"{by} is not in the org's directory")
    mine = [r for r in needed if r in roles_of(org, by)]
    if not mine:
        groups = ", ".join(ROLE_GROUPS[r] for r in needed)
        raise ApprovalRefused(f"{by} can't approve this: it needs a member of {groups}")
    meaning = ("rejected" if reject else "approved") + " the IAM change shown in this record" + (f": {note}" if note else "")
    try:
        event, state = ledger.signoff(record_path, by, mine[0], meaning, signer=ledger.load_signer(), reject=reject)
    except ledger.SignoffRefused as e:
        raise ApprovalRefused(str(e)) from None
    return {"by": by, "role": mine[0], "decision": event["decision"], "status": state}


def _applied_path():
    return records() / "applied.jsonl"


def applied(record_name):
    p = _applied_path()
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        e = json.loads(line)
        if e.get("record") == record_name:
            return e
    return None


def mark_applied(record_name, results):
    p = _applied_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps({"record": record_name, "time": time.time(), "results": results}) + "\n")


def approved(record_path, org=None):
    """The approved change in a record, or why not. Strict: see the module docstring."""
    org = org or connect()
    path = Path(record_path)
    no = lambda why: {"status": "NOT APPROVED", "why": why}          # noqa: E731
    if not path.exists():
        return no(f"no record {path.name}")
    pub = public_key()
    ok, report, _ = ledger.verify(path.parent, public_key=pub)
    if not ok:
        bad = [l for l in report if "PROBLEM" in l or "BAD" in l or "TAMPER" in l or "broken" in l]
        return no("the ledger does not verify: " + "; ".join((bad or report)[:3]))
    entries = [e for e in ledger._entries(path.parent) if e.get("file") == path.name]
    if not any(e.get("kind", "record") == "record" for e in entries):
        return no(f"{path.name} is not in the ledger")
    signoffs = [e for e in entries if e.get("kind") == "signoff"]
    for e in signoffs:
        state = ledger._check_signature(e, pub)
        if state != "ok":
            return no(f"a sign-off by {e.get('signer')} is {state}: shio-gcp-iam accepts only signed sign-offs")
    status, needed, decided = waiting_for(path)
    if status != "APPROVED":
        return no(f"the change is {status}" + (f"; waiting for {', '.join(needed)}" if needed else ""))
    if not isinstance(decided, dict) or decided.get("action") != "APPLY":
        return no("the record is not a proposed IAM change")
    for e in signoffs:
        if e.get("decision") == "approved" and e.get("role") not in roles_of(org, e.get("signer", "")):
            return no(f"{e.get('signer')} signed as {e.get('role')} but is not in {ROLE_GROUPS.get(e.get('role'))}")
    if applied(path.name):
        return no("this change was already applied")
    return {"status": "APPROVED", "record": path.name, "request": decided["request"],
            "requester": decided["requester"], "diff": decided["diff"],
            "approved_by": [e["signer"] for e in signoffs if e.get("decision") == "approved"]}
