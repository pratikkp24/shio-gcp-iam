"""The functions iam.shio declares as tools. Reads return the org's data as text for the model and the ledger; the
one write, set_iam_policy, is declared `acts` and so runs only from a rule, through Shio Guard."""
import json

from . import approvals, rules
from .connectors import ConnectorError, connect, member_email


def directory_list():
    return json.dumps([{k: p.get(k) for k in ("email", "kind", "name", "title") if p.get(k)}
                       for p in connect().directory()], indent=0)


def resource_list():
    org = connect()
    out = []
    for r in org.resources():
        parent = org.resource(r["parent"]) if r.get("parent") else None
        out.append({"name": r["name"], "type": r["type"], "display": r["display"],
                    "parent": parent["display"] if parent else None})
    return json.dumps(out, indent=0)


def resource_notes():
    """Labels and descriptions: written by anyone who can edit the resource, so untrusted."""
    return json.dumps([{"name": r["name"], "labels": r.get("labels", {}), "description": r.get("description", "")}
                       for r in connect().resources() if r.get("labels") or r.get("description")], indent=0)


def role_list():
    return json.dumps([{"role": k, "title": v.get("title"), "service": v.get("service")}
                       for k, v in sorted(connect().roles().items())], indent=0)


def approved_change(record):
    return approvals.approved(record)


def set_iam_policy(resource, members, roles, ops, etag):
    """Apply one resource's approved ops. members and roles are the gate-checked values; ops must use exactly
    those, so nothing reaches the policy that the gate didn't see."""
    org = connect()
    ops = json.loads(ops)
    if sorted({member_email(o["member"]) for o in ops}) != sorted(set(members)) or \
            sorted({o["role"] for o in ops}) != sorted(set(roles)):
        raise ConnectorError("the ops don't match the members and roles the gate checked")
    current = org.policy(resource)
    if current["etag"] != etag:
        raise ConnectorError(f"the policy on {resource} changed since the change was approved; propose it again")
    return org.set_policy(resource, rules.apply_ops(current["bindings"], ops), etag)
