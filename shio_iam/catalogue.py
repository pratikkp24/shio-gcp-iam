"""What code knows about IAM roles, without asking a model.

The mock's catalogue is abridged: about twenty real predefined roles, each with a real subset of its permissions
(enough for the checks below to be meaningful). The live connector reads the full role from `gcloud iam roles
describe`, so on a real org every check runs over the complete permission list.
"""

# Owner, Editor and Viewer are now Google's "legacy basic roles"; Admin, Writer and Reader are the newer basic roles.
LEGACY_BASIC = {"roles/owner", "roles/editor", "roles/viewer"}
BASIC = LEGACY_BASIC | {"roles/admin", "roles/writer", "roles/reader"}

# Permissions, by role. Abridged but real: each permission listed is in that role in Google's roles reference.
PREDEFINED = {
    "roles/bigquery.dataViewer": {
        "title": "BigQuery Data Viewer", "service": "bigquery", "levels": ["dataset", "project"],
        "permissions": ["bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "bigquery.tables.get",
                        "bigquery.tables.getData", "bigquery.tables.list"]},
    "roles/bigquery.dataEditor": {
        "title": "BigQuery Data Editor", "service": "bigquery", "levels": ["dataset", "project"],
        "permissions": ["bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "bigquery.tables.get",
                        "bigquery.tables.getData", "bigquery.tables.list", "bigquery.tables.create",
                        "bigquery.tables.update", "bigquery.tables.updateData", "bigquery.tables.delete"]},
    "roles/bigquery.dataOwner": {
        "title": "BigQuery Data Owner", "service": "bigquery", "levels": ["dataset", "project"],
        "permissions": ["bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "bigquery.tables.get",
                        "bigquery.tables.getData", "bigquery.tables.list", "bigquery.tables.create",
                        "bigquery.tables.update", "bigquery.tables.updateData", "bigquery.tables.delete",
                        "bigquery.datasets.update", "bigquery.datasets.delete", "bigquery.datasets.setIamPolicy",
                        "bigquery.tables.setIamPolicy"]},
    "roles/bigquery.jobUser": {
        "title": "BigQuery Job User", "service": "bigquery", "levels": ["project"],
        "permissions": ["bigquery.jobs.create"]},
    "roles/bigquery.admin": {
        "title": "BigQuery Admin", "service": "bigquery", "levels": ["dataset", "project"],
        "permissions": ["bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "bigquery.tables.get",
                        "bigquery.tables.getData", "bigquery.tables.list", "bigquery.tables.create",
                        "bigquery.tables.update", "bigquery.tables.updateData", "bigquery.tables.delete",
                        "bigquery.datasets.create", "bigquery.datasets.update", "bigquery.datasets.delete",
                        "bigquery.datasets.setIamPolicy", "bigquery.tables.setIamPolicy", "bigquery.jobs.create"]},
    "roles/storage.objectViewer": {
        "title": "Storage Object Viewer", "service": "storage", "levels": ["bucket", "project"],
        "permissions": ["storage.objects.get", "storage.objects.list"]},
    "roles/storage.objectCreator": {
        "title": "Storage Object Creator", "service": "storage", "levels": ["bucket", "project"],
        "permissions": ["storage.objects.create"]},
    "roles/storage.objectAdmin": {
        "title": "Storage Object Admin", "service": "storage", "levels": ["bucket", "project"],
        "permissions": ["storage.objects.create", "storage.objects.delete", "storage.objects.get",
                        "storage.objects.list", "storage.objects.update"]},
    "roles/storage.admin": {
        "title": "Storage Admin", "service": "storage", "levels": ["bucket", "project"],
        "permissions": ["storage.buckets.create", "storage.buckets.delete", "storage.buckets.get",
                        "storage.buckets.list", "storage.buckets.update", "storage.buckets.getIamPolicy",
                        "storage.buckets.setIamPolicy", "storage.objects.create", "storage.objects.delete",
                        "storage.objects.get", "storage.objects.list", "storage.objects.update"]},
    "roles/logging.viewer": {
        "title": "Logs Viewer", "service": "logging", "levels": ["project"],
        "permissions": ["logging.logEntries.list", "logging.logs.list"]},
    "roles/iam.securityReviewer": {
        "title": "Security Reviewer", "service": "iam", "levels": ["project", "folder", "organization"],
        "permissions": ["resourcemanager.projects.getIamPolicy", "resourcemanager.folders.getIamPolicy",
                        "storage.buckets.getIamPolicy", "bigquery.datasets.getIamPolicy", "iam.roles.list"]},
    "roles/iam.serviceAccountUser": {
        "title": "Service Account User", "service": "iam", "levels": ["service_account", "project"],
        "permissions": ["iam.serviceAccounts.actAs", "iam.serviceAccounts.get", "iam.serviceAccounts.list"]},
    "roles/iam.serviceAccountTokenCreator": {
        "title": "Service Account Token Creator", "service": "iam", "levels": ["service_account", "project"],
        "permissions": ["iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.getOpenIdToken",
                        "iam.serviceAccounts.implicitDelegation", "iam.serviceAccounts.signBlob",
                        "iam.serviceAccounts.signJwt"]},
    "roles/iam.serviceAccountKeyAdmin": {
        "title": "Service Account Key Admin", "service": "iam", "levels": ["service_account", "project"],
        "permissions": ["iam.serviceAccountKeys.create", "iam.serviceAccountKeys.delete",
                        "iam.serviceAccountKeys.get", "iam.serviceAccountKeys.list"]},
    "roles/resourcemanager.projectIamAdmin": {
        "title": "Project IAM Admin", "service": "resourcemanager", "levels": ["project"],
        "permissions": ["resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"]},
    "roles/browser": {
        "title": "Browser", "service": "resourcemanager", "levels": ["project", "folder", "organization"],
        "permissions": ["resourcemanager.projects.get", "resourcemanager.folders.get"]},
}

ALL_PERMISSIONS = sorted({p for r in PREDEFINED.values() for p in r["permissions"]} |
                         {"resourcemanager.projects.delete", "resourcemanager.projects.setIamPolicy",
                          "resourcemanager.folders.setIamPolicy", "resourcemanager.organizations.setIamPolicy"})


def _basic(name):
    if name in ("roles/owner", "roles/admin"):
        perms = ALL_PERMISSIONS
    elif name in ("roles/editor", "roles/writer"):            # Editor can change resources but not IAM policies
        perms = [p for p in ALL_PERMISSIONS if not p.endswith(".setIamPolicy")]
    else:                                    # Viewer: read-only
        perms = [p for p in ALL_PERMISSIONS if p.rsplit(".", 1)[-1] in ("get", "list", "getIamPolicy", "getData")]
    return {"title": name.split("/")[1].title(), "service": "basic", "levels": ["project", "folder", "organization",
            "dataset", "bucket", "service_account"], "permissions": perms, "basic": True}


ROLES = {**PREDEFINED, **{r: _basic(r) for r in BASIC}}

# Permissions that let a principal widen its own access or act as someone else (Rhino Security Labs' GCP privilege
# escalation research lists these routes). A role holding any of them needs a security admin's approval too.
ESCALATION_PERMISSIONS = {
    "resourcemanager.projects.setIamPolicy", "resourcemanager.folders.setIamPolicy",
    "resourcemanager.organizations.setIamPolicy", "storage.buckets.setIamPolicy", "bigquery.datasets.setIamPolicy",
    "bigquery.tables.setIamPolicy", "iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccounts.signBlob", "iam.serviceAccounts.signJwt", "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccountKeys.create", "iam.roles.update", "iam.roles.create",
}

# (service, access asked for) -> the narrowest predefined role that covers it. Code picks; the model only reads
# which service and which kind of access the person asked for.
NARROWEST = {
    ("bigquery", "read"): "roles/bigquery.dataViewer",
    ("bigquery", "write"): "roles/bigquery.dataEditor",
    ("bigquery", "admin"): "roles/bigquery.dataOwner",
    ("bigquery", "query"): "roles/bigquery.jobUser",
    ("storage", "read"): "roles/storage.objectViewer",
    ("storage", "write"): "roles/storage.objectCreator",
    ("storage", "admin"): "roles/storage.admin",
    ("logging", "read"): "roles/logging.viewer",
    ("iam", "read"): "roles/iam.securityReviewer",
    ("iam", "impersonate"): "roles/iam.serviceAccountTokenCreator",
    ("iam", "act_as"): "roles/iam.serviceAccountUser",
    ("resourcemanager", "read"): "roles/browser",
}

# The resource types each service's roles can be granted on.
TYPE_SERVICE = {"dataset": "bigquery", "bucket": "storage", "service_account": "iam"}

# Plain-English actions people ask about -> the permission behind them. Questions are answered from the policy for
# this permission, never from a model's idea of who has access.
ACTIONS = {
    "delete buckets": "storage.buckets.delete", "create buckets": "storage.buckets.create",
    "read objects": "storage.objects.get", "delete objects": "storage.objects.delete",
    "change bucket permissions": "storage.buckets.setIamPolicy",
    "read tables": "bigquery.tables.getData", "delete tables": "bigquery.tables.delete",
    "delete datasets": "bigquery.datasets.delete", "change dataset permissions": "bigquery.datasets.setIamPolicy",
    "change project permissions": "resourcemanager.projects.setIamPolicy", "delete projects":
    "resourcemanager.projects.delete", "impersonate service accounts": "iam.serviceAccounts.getAccessToken",
    "act as service accounts": "iam.serviceAccounts.actAs", "create service account keys":
    "iam.serviceAccountKeys.create", "read logs": "logging.logEntries.list",
}


def permissions(role, roles=None):
    r = (roles or ROLES).get(role)
    return set(r["permissions"]) if r else set()


def escalates(role, roles=None):
    """The escalation permissions a role holds (empty if none)."""
    return sorted(permissions(role, roles) & ESCALATION_PERMISSIONS)
