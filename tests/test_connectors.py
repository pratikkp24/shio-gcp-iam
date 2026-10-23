"""The gcloud connector, against canned gcloud output (no GCP account), and the pure rules."""
import json

import pytest
import shio

from shio_iam import catalogue, rules
from shio_iam.connectors import ConnectorError, GcloudOrg, condition_holds
from conftest import NOW

PROJECTS = [{"projectId": "acme-prod", "parent": {"type": "folder", "id": "77"}, "labels": {}}]
POLICY = {"bindings": [{"role": "roles/owner", "members": ["user:ana@acme.example"]},
                       {"role": "roles/storage.admin", "members": ["group:ops@acme.example"]}], "etag": "BwX1", "version": 1}


def fake(calls):
    def run(*args):
        calls.append(args)
        key = " ".join(args[:3])
        if args[:2] == ("projects", "list"):
            return PROJECTS
        if args[:2] == ("storage", "buckets") and args[2] == "list":
            return [{"name": "acme-logs", "uniform_bucket_level_access": True}]
        if args[:2] == ("projects", "get-iam-policy"):
            return POLICY
        if args[:3] == ("storage", "buckets", "get-iam-policy"):
            return {"bindings": [], "etag": "BwB1"}
        if args[:2] == ("iam", "service-accounts"):
            return [{"email": "ci@acme-prod.iam.gserviceaccount.com", "displayName": "CI"}]
        if args[:3] == ("iam", "roles", "describe"):
            return {"includedPermissions": catalogue.ROLES.get(args[3], {}).get("permissions", [])}
        if args[:2] == ("asset", "analyze-iam-policy"):
            return {"mainAnalysis": {"analysisResults": [{
                "attachedResourceFullName": "//cloudresourcemanager.googleapis.com/projects/acme-prod",
                "iamBinding": {"role": "roles/storage.admin", "members": ["group:ops@acme.example"]},
                "accessControlLists": [{"resources": [{"fullResourceName": "//storage.googleapis.com/projects/_/buckets/acme-logs"}]}],
                "identityList": {"identities": [{"name": "user:bo@acme.example"}]}}]}}
        raise ConnectorError(f"unexpected {key}")
    return run


def test_reads_resources_policies_and_a_directory_from_policies():
    calls = []
    g = GcloudOrg(org_id="", runner=fake(calls))
    names = [r["display"] for r in g.resources()]
    assert names == ["folders/77", "acme-prod", "acme-logs"]
    assert g.policy("//cloudresourcemanager.googleapis.com/projects/acme-prod")["etag"] == "BwX1"
    emails = {p["email"] for p in g.directory()}
    assert emails == {"ana@acme.example", "ops@acme.example", "ci@acme-prod.iam.gserviceaccount.com"}
    assert all(c[0] != "set-iam-policy" and "set-iam-policy" not in c for c in calls)   # reads only


def test_policy_analyzer_output_is_parsed():
    g = GcloudOrg(org_id="123", runner=fake([]))
    rows = g.analyze("storage.buckets.delete", "//cloudresourcemanager.googleapis.com/projects/acme-prod")
    assert rows[0]["principal"] == "bo@acme.example" and rows[0]["role"] == "roles/storage.admin"


def test_writes_to_a_real_org_are_off_by_default(monkeypatch):
    g = GcloudOrg(org_id="", runner=fake([]))
    monkeypatch.delenv("SHIO_IAM_ALLOW_APPLY", raising=False)
    with pytest.raises(ConnectorError):
        g._write("//cloudresourcemanager.googleapis.com/projects/acme-prod", [], "BwX1")
    with pytest.raises(shio.BoundaryError):
        g.set_policy("//cloudresourcemanager.googleapis.com/projects/acme-prod", [], "BwX1")


def test_durations():
    assert rules.requested_days("give X read access for two weeks") == 14
    assert rules.requested_days("for 3 days") == 3
    assert rules.requested_days("for a week") == 7
    assert rules.requested_days("forever") is None


def test_least_privilege_and_escalation(org):
    ds = "//bigquery.googleapis.com/projects/nw-billing-prod/datasets/billing"
    assert rules.least_privilege(org, ds, "read", "roles/bigquery.dataViewer")
    assert not rules.least_privilege(org, ds, "read", "roles/bigquery.dataEditor")
    assert catalogue.escalates("roles/iam.serviceAccountTokenCreator")
    assert catalogue.escalates("roles/bigquery.dataOwner") == ["bigquery.datasets.setIamPolicy", "bigquery.tables.setIamPolicy"]
    assert not catalogue.escalates("roles/bigquery.dataViewer")


def test_names_resolve_to_the_longest_match(org):
    got = [r["display"] for r in rules.resources_named(org, "give Lee Editor on nw-billing-prod")]
    assert got == ["nw-billing-prod"]
    assert [r["display"] for r in rules.resources_named(org, "who can delete buckets in prod?")] == ["prod"]
    assert rules.ambiguous_names(org, "give Priya access") == {"Priya": ["Priya Raman", "Priya Shah"]}


def test_expired_conditions_grant_nothing():
    cond = {"expression": 'request.time < timestamp("2026-09-30T00:00:00Z")'}
    assert not condition_holds(cond, NOW)
    assert condition_holds({"expression": "resource.name.startsWith('x')"}, NOW)   # unknown: assume it may grant


def test_deny_policy_blocks_bucket_delete_except_sre(org):
    a = rules.answer(org, permission="storage.buckets.delete",
                     scope="//cloudresourcemanager.googleapis.com/folders/310000000001")
    assert "lee.wong@northwind.example" in a["blocked_by_deny"]
    assert "ines.moreau@northwind.example" in a["principals"]                       # in sre-oncall: excepted
