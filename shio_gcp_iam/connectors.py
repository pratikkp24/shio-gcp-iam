"""Read-only views of a Google Cloud org, behind one interface, and the one write.

    org = connect()                 # MockOrg unless SHIO_GCP_IAM_MODE=gcloud
    org.directory()                 # people, groups, service accounts
    org.resources()                 # org, folders, projects, datasets, buckets, service accounts
    org.policy(resource)            # {"bindings": [...], "etag": "...", "version": 3}
    org.deny_policies(resource)     # IAM deny policies attached there
    org.analyze(permission, scope)  # who has `permission` on or below `scope`, and through which binding

MockOrg serves the fictional Northwind Labs org (sample_org.py) and keeps its state in a JSON file, so a change you
approve shows up in the next question. GcloudOrg runs read-only `gcloud` commands with the credentials gcloud already
has on this machine (`gcloud auth login`); it never reads, copies or stores a key.

The write, `Org.set_policy`, is not for callers: `iam.shio` declares it as an `acts` tool, so it runs only from a
rule, through Shio Guard, after an approved sign-off. Called any other way it raises BoundaryError.
"""
import copy
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import catalogue, sample_org


class ConnectorError(RuntimeError):
    pass


def etag_of(bindings):
    return "BwY" + hashlib.sha256(json.dumps(bindings, sort_keys=True).encode()).hexdigest()[:12]


def member_email(member):
    return member.split(":", 1)[1] if ":" in member else member


def member_for(email, kind):
    return {"user": "user", "group": "group", "serviceAccount": "serviceAccount"}[kind] + ":" + email


def _inside_a_rule():
    """True only while Shio runs a check or rule body (its own context flag). Shio sets it; plain Python can't
    without importing Shio's internals, which a regulated program refuses to compile."""
    try:
        from shio.core import _open
        return bool(_open.get())
    except Exception:
        return False


def condition_holds(condition, now):
    """Evaluate the one condition shape this tool writes and reads: request.time < timestamp("..."). Anything else
    is treated as possibly true (it might grant access), so questions about access never under-report."""
    if not condition:
        return True
    m = re.fullmatch(r'\s*request\.time\s*<\s*timestamp\("([^"]+)"\)\s*', condition.get("expression", ""))
    if not m:
        return True
    return now < dt.datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))


class Org:
    """What every connector offers. Subclasses fill in the reads; analysis is shared."""
    mode = "base"

    def __init__(self, now=None):
        self._now = now

    def now(self):
        return self._now or dt.datetime.now(dt.timezone.utc)

    # -- reads, per connector -----------------------------------------------------------------------------------
    def directory(self):
        raise NotImplementedError

    def resources(self):
        raise NotImplementedError

    def policy(self, resource):
        raise NotImplementedError

    def deny_policies(self, resource):
        return []

    def roles(self):
        return catalogue.ROLES

    def allowed_domains(self):
        return []

    # -- shared --------------------------------------------------------------------------------------------------
    def resource(self, name):
        return next((r for r in self.resources() if r["name"] == name), None)

    def ancestors(self, name):
        """The resource and every parent up to the organization, nearest first."""
        out, seen = [], set()
        r = self.resource(name)
        while r is not None and r["name"] not in seen:
            out.append(r)
            seen.add(r["name"])
            r = self.resource(r["parent"]) if r.get("parent") else None
        return out

    def below(self, scope):
        """Every resource at or below `scope`."""
        return [r for r in self.resources() if any(a["name"] == scope for a in self.ancestors(r["name"]))]

    def person(self, email):
        return next((p for p in self.directory() if p["email"].lower() == (email or "").lower()), None)

    def groups_of(self, email):
        return [g["email"] for g in self.directory() if g["kind"] == "group" and email in g.get("members", [])]

    def expand(self, member):
        """A binding member -> the directory emails it covers (a group expands to its members)."""
        if member in ("allUsers", "allAuthenticatedUsers"):
            return [member]
        kind, _, email = member.partition(":")
        if kind == "domain":
            return [p["email"] for p in self.directory() if p["kind"] == "user" and p["email"].endswith("@" + email)]
        p = self.person(email)
        if p and p["kind"] == "group":
            return list(p.get("members", []))
        return [email]

    def denied(self, email, permission, resource):
        """The deny policy (on the resource or above it) that blocks `email` from `permission`, or None."""
        service, _, rest = permission.partition(".")
        v2 = f"{service}.googleapis.com/{rest}"
        groups = self.groups_of(email)
        for a in self.ancestors(resource):
            for pol in self.deny_policies(a["name"]):
                for rule in pol.get("rules", []):
                    d = rule.get("denyRule", {})
                    if v2 not in d.get("deniedPermissions", []):
                        continue

                    def hits(principals):
                        for p in principals:
                            if p == "principalSet://goog/public:all":
                                return True
                            if p == f"principal://goog/subject/{email}":
                                return True
                            if any(p == f"principalSet://goog/group/{g}" for g in groups):
                                return True
                        return False
                    if hits(d.get("deniedPrincipals", [])) and not hits(d.get("exceptionPrincipals", [])):
                        return {"policy": pol.get("displayName") or pol["name"], "on": a["display"]}
        return None

    def analyze(self, permission, scope):
        """Who holds `permission` on `scope` or anything below it. One row per (principal, binding), with the path:
        where the binding sits, which role, through which group, and whether a deny policy blocks it in the end."""
        roles = self.roles()
        rows = []
        for target in self.below(scope):
            for a in self.ancestors(target["name"]):
                for b in self.policy(a["name"])["bindings"]:
                    if permission not in roles.get(b["role"], {}).get("permissions", []):
                        continue
                    if not condition_holds(b.get("condition"), self.now()):
                        continue
                    for m in b["members"]:
                        for email in self.expand(m):
                            rows.append({"principal": email, "via": m if member_email(m) != email else None,
                                         "role": b["role"], "bound_on": a["display"], "bound_on_type": a["type"],
                                         "resource": target["display"], "resource_type": target["type"],
                                         "inherited": a["name"] != target["name"],
                                         "condition": (b.get("condition") or {}).get("expression"),
                                         "denied_by": self.denied(email, permission, target["name"])})
        return rows

    # -- the one write --------------------------------------------------------------------------------------------
    def set_policy(self, resource, bindings, etag):
        if not _inside_a_rule():
            from shio.core import BoundaryError
            raise BoundaryError("set_policy acts on the world: it runs only from a rule in iam.shio, through the gate")
        return self._write(resource, bindings, etag)

    def _write(self, resource, bindings, etag):
        raise NotImplementedError


class MockOrg(Org):
    """The Northwind Labs sample org. state: a JSON file holding its policies (created from sample_org on first use);
    without one, the state lives in memory."""
    mode = "mock"

    def __init__(self, state=None, now=None):
        super().__init__(now)
        self.state_path = Path(state) if state else None
        if self.state_path and self.state_path.exists():
            self._policies = json.loads(self.state_path.read_text())
        else:
            self._policies = copy.deepcopy(sample_org.POLICIES)
            self._save()

    def _save(self):
        if self.state_path:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(self._policies, indent=1))

    def directory(self):
        return sample_org.DIRECTORY

    def resources(self):
        return sample_org.RESOURCES

    def policy(self, resource):
        b = self._policies.get(resource)
        if b is None:
            raise ConnectorError(f"no such resource: {resource}")
        return {"bindings": copy.deepcopy(b), "etag": etag_of(b), "version": 3}

    def deny_policies(self, resource):
        return sample_org.DENY_POLICIES.get(resource, [])

    def allowed_domains(self):
        return sample_org.ALLOWED_DOMAINS

    def _write(self, resource, bindings, etag):
        current = self.policy(resource)
        if current["etag"] != etag:            # what Google's setIamPolicy does with a stale etag: refuse
            raise ConnectorError(f"the policy on {resource} changed since this change was approved (etag "
                                 f"{current['etag']}, approved against {etag}); propose it again")
        self._policies[resource] = copy.deepcopy(bindings)
        self._save()
        return {"resource": resource, "etag": etag_of(bindings), "bindings": len(bindings)}


class GcloudOrg(Org):
    """A real org, read with the `gcloud` CLI and the credentials it already holds. Nothing is stored.

    SHIO_GCP_IAM_ORG: the organization id. SHIO_GCP_IAM_PROJECTS: optional comma-separated project ids to limit the scope.
    SHIO_GCP_IAM_DIRECTORY: optional JSON file of people and groups ([{"email", "kind", "name", "members"}]); without it
    the directory is the principals already in the policies plus the service accounts gcloud lists, so a person who
    holds no role yet can't be found (the check fails closed and says so).

    Writes need SHIO_GCP_IAM_ALLOW_APPLY=1 as well as an approved sign-off. Not yet tested against a live org.
    """
    mode = "gcloud"

    def __init__(self, org_id=None, projects=None, now=None, runner=None):
        super().__init__(now)
        self.org_id = org_id or os.environ.get("SHIO_GCP_IAM_ORG", "")
        self.projects = projects or [p for p in os.environ.get("SHIO_GCP_IAM_PROJECTS", "").split(",") if p]
        self.run = runner or self._gcloud
        self._cache = {}

    @staticmethod
    def available():
        return shutil.which("gcloud") is not None

    def _gcloud(self, *args):
        if not self.available():
            raise ConnectorError("gcloud is not installed; install the Google Cloud CLI and run `gcloud auth login`")
        p = subprocess.run(["gcloud", *args, "--format=json"], capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise ConnectorError(f"gcloud {' '.join(args[:3])} failed: {p.stderr.strip()[:300]}")
        return json.loads(p.stdout or "null")

    def _memo(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def resources(self):
        def load():
            out = []
            if self.org_id:
                out.append({"name": f"//cloudresourcemanager.googleapis.com/organizations/{self.org_id}",
                            "type": "organization", "display": self.org_id, "parent": None})
            projects = self.run("projects", "list") or []
            for p in projects:
                pid = p["projectId"]
                if self.projects and pid not in self.projects:
                    continue
                parent = p.get("parent") or {}
                pname = (f"//cloudresourcemanager.googleapis.com/{parent.get('type')}s/{parent.get('id')}"
                         if parent else None)
                if parent.get("type") == "folder" and not any(r["name"] == pname for r in out):
                    out.append({"name": pname, "type": "folder", "display": f"folders/{parent['id']}",
                                "parent": None})
                out.append({"name": f"//cloudresourcemanager.googleapis.com/projects/{pid}", "type": "project",
                            "display": pid, "parent": pname, "labels": p.get("labels", {})})
                for b in self.run("storage", "buckets", "list", f"--project={pid}") or []:
                    name = b.get("name") or b.get("id")
                    out.append({"name": f"//storage.googleapis.com/projects/_/buckets/{name}", "type": "bucket",
                                "display": name, "parent": f"//cloudresourcemanager.googleapis.com/projects/{pid}",
                                "labels": b.get("labels", {}),
                                "uniform_access": bool(b.get("uniform_bucket_level_access"))})
            return out
        return self._memo("resources", load)

    def policy(self, resource):
        def load():
            kind, ident = self._kind(resource)
            if kind == "organization":
                p = self.run("organizations", "get-iam-policy", ident)
            elif kind == "folder":
                p = self.run("resource-manager", "folders", "get-iam-policy", ident)
            elif kind == "project":
                p = self.run("projects", "get-iam-policy", ident)
            elif kind == "bucket":
                p = self.run("storage", "buckets", "get-iam-policy", f"gs://{ident}")
            else:
                raise ConnectorError(f"reading the policy of a {kind} is not supported yet")
            p = p or {}
            return {"bindings": p.get("bindings", []), "etag": p.get("etag", ""), "version": p.get("version", 1)}
        return copy.deepcopy(self._memo(("policy", resource), load))

    def directory(self):
        def load():
            path = os.environ.get("SHIO_GCP_IAM_DIRECTORY")
            if path:
                return json.loads(Path(path).read_text())
            seen = {}
            for r in self.resources():
                if r["type"] not in ("organization", "folder", "project", "bucket"):
                    continue
                try:
                    bindings = self.policy(r["name"])["bindings"]
                except ConnectorError:
                    continue
                for b in bindings:
                    for m in b["members"]:
                        kind, _, email = m.partition(":")
                        if kind in ("user", "group", "serviceAccount"):
                            seen.setdefault(email, {"email": email, "kind": kind, "name": email})
            for r in self.resources():
                if r["type"] == "project":
                    for sa in self.run("iam", "service-accounts", "list", f"--project={r['display']}") or []:
                        seen.setdefault(sa["email"], {"email": sa["email"], "kind": "serviceAccount",
                                                      "name": sa.get("displayName") or sa["email"]})
            return list(seen.values())
        return self._memo("directory", load)

    def roles(self):
        """The full permission list of each role these policies use, from `gcloud iam roles describe`, on top of
        the abridged catalogue."""
        def load():
            out = dict(catalogue.ROLES)
            used = {b["role"] for r in self.resources() if r["type"] in ("organization", "folder", "project", "bucket")
                    for b in self._safe_bindings(r["name"])} | set(catalogue.PREDEFINED)
            for role in sorted(used):
                if not role.startswith("roles/"):
                    continue
                try:
                    d = self.run("iam", "roles", "describe", role)
                except ConnectorError:
                    continue
                base = out.get(role, {"title": d.get("title", role), "service": role.split("/")[1].split(".")[0],
                                      "levels": ["project"]})
                out[role] = {**base, "permissions": d.get("includedPermissions", base.get("permissions", []))}
            return out
        return self._memo("roles", load)

    def _safe_bindings(self, name):
        try:
            return self.policy(name)["bindings"]
        except ConnectorError:
            return []

    def analyze(self, permission, scope):
        """Policy Analyzer (Cloud Asset API): `gcloud asset analyze-iam-policy`, which expands groups and covers
        inheritance. Needs the Cloud Asset API enabled and cloudasset.assets.analyzeIamPolicy on the scope."""
        if not self.org_id:
            return super().analyze(permission, scope)
        out = self.run("asset", "analyze-iam-policy", f"--organization={self.org_id}",
                       f"--full-resource-name={scope}", f"--permissions={permission}",
                       "--expand-groups")
        rows = []
        main = (out[0] if isinstance(out, list) and out else out or {})
        main = main.get("mainAnalysis", main)
        for res in main.get("analysisResults", []):
            binding = res.get("iamBinding", {})
            for acl in res.get("accessControlLists", []):
                for target in acl.get("resources", []):
                    for ident in (res.get("identityList") or {}).get("identities", []):
                        rows.append({"principal": member_email(ident.get("name", "")), "via": None,
                                     "role": binding.get("role"), "bound_on": res.get("attachedResourceFullName"),
                                     "bound_on_type": "", "resource": target.get("fullResourceName"),
                                     "resource_type": "", "inherited": res.get("attachedResourceFullName") !=
                                     target.get("fullResourceName"), "condition":
                                     (binding.get("condition") or {}).get("expression"), "denied_by": None})
        return rows

    @staticmethod
    def _kind(resource):
        m = re.match(r"//cloudresourcemanager\.googleapis\.com/(organizations|folders|projects)/(.+)", resource)
        if m:
            return m.group(1)[:-1], m.group(2)
        m = re.match(r"//storage\.googleapis\.com/projects/_/buckets/(.+)", resource)
        if m:
            return "bucket", m.group(1)
        return "other", resource

    def _write(self, resource, bindings, etag):
        if os.environ.get("SHIO_GCP_IAM_ALLOW_APPLY") != "1":
            raise ConnectorError("writing to a real org needs SHIO_GCP_IAM_ALLOW_APPLY=1 (as well as the approval)")
        import tempfile
        kind, ident = self._kind(resource)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"bindings": bindings, "etag": etag, "version": 3}, f)
        try:
            if kind == "project":
                out = self.run("projects", "set-iam-policy", ident, f.name)
            elif kind == "folder":
                out = self.run("resource-manager", "folders", "set-iam-policy", ident, f.name)
            elif kind == "organization":
                out = self.run("organizations", "set-iam-policy", ident, f.name)
            elif kind == "bucket":
                out = self.run("storage", "buckets", "set-iam-policy", f"gs://{ident}", f.name)
            else:
                raise ConnectorError(f"writing the policy of a {kind} is not supported yet")
        finally:
            os.unlink(f.name)
        self._cache.pop(("policy", resource), None)
        return {"resource": resource, "etag": (out or {}).get("etag", ""), "bindings": len(bindings)}


_ORG = None


def connect(reset=False):
    """The org this process works on: SHIO_GCP_IAM_MODE=gcloud for a real one, otherwise the mock (state in
    SHIO_GCP_IAM_HOME/org-state.json)."""
    global _ORG
    if _ORG is None or reset:
        if os.environ.get("SHIO_GCP_IAM_MODE") == "gcloud":
            _ORG = GcloudOrg()
        else:
            home = Path(os.environ.get("SHIO_GCP_IAM_HOME", ".shio-gcp-iam"))
            _ORG = MockOrg(home / "org-state.json")
    return _ORG


def use(org):
    """Point the program at a given org (tests, the demo exporter)."""
    global _ORG
    _ORG = org
    return org
