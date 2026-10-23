"""The code that decides. Every function here is pure over the org's data and the request text: the checks in
iam.shio call them, and none of them asks a model anything.

The model's reading says what the person seems to want (who, what access, on what, for how long). Code then finds,
from the request text and the org's own data, what the request can actually mean, and each check compares the two.
A value the request never named, a person the directory doesn't hold or a role broader than needed fails a check.
"""
import datetime as dt
import json
import re

from . import catalogue
from .connectors import condition_holds, member_email, member_for

MAX_DAYS = 90                 # the longest time-bound grant this org allows
PROD_FOLDER = "prod"          # human access under this folder must expire

WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
         "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "fourteen": 14, "thirty": 30, "ninety": 90}
UNITS = {"hour": 1 / 24, "day": 1, "week": 7, "fortnight": 14, "month": 30}


def _norm(s):
    return " " + re.sub(r"[^a-z0-9@.]+", " ", str(s or "").lower()) + " "


def says(text, phrase):
    """`phrase` appears in `text` as whole words (hyphens, underscores and case ignored)."""
    p = _norm(phrase).strip()
    return bool(p) and f" {p} " in _norm(text)


# -- reading the request with code -------------------------------------------------------------------------------

def requested_days(text):
    """The duration the request states, in days, or None. 'two weeks' -> 14, 'for 3 days' -> 3, 'until 2026-11-06'
    -> days from today is left to the caller (returned as the date string)."""
    t = str(text).lower()
    m = re.search(r"\buntil\s+(\d{4}-\d{2}-\d{2})", t)
    if m:
        return m.group(1)
    m = re.search(r"\bfor\s+(?:the\s+next\s+)?(\d+|[a-z]+)\s+(hour|day|week|fortnight|month)s?\b", t)
    if m:
        n = int(m.group(1)) if m.group(1).isdigit() else WORDS.get(m.group(1))
        if n is not None:
            return max(1, round(n * UNITS[m.group(2)]))
    if re.search(r"\bfor\s+(?:a|one)\s+fortnight\b", t):
        return 14
    return None


def days_until(value, now):
    if isinstance(value, str):
        end = dt.datetime.fromisoformat(value).replace(tzinfo=dt.timezone.utc)
        return max(0, (end - now).days)
    return value


def principals_named(org, text):
    """Directory entries the request names: by email, by full name, or by a first name / group name it holds alone.
    -> {email: how it was named}."""
    out = {}
    people = org.directory()
    for p in people:
        if says(text, p["email"]):
            out[p["email"]] = p["email"]
        elif says(text, p["name"]):
            out[p["email"]] = p["name"]
        elif p["kind"] == "group" and says(text, p["email"].split("@")[0].replace("-", " ")):
            out[p["email"]] = p["email"].split("@")[0]
        elif p["kind"] == "serviceAccount" and says(text, p["email"].split("@")[0]):
            out[p["email"]] = p["email"].split("@")[0]
        elif "break-glass" in p.get("tags", []) and re.search(r"break[- ]?glass", str(text), re.I):
            out[p["email"]] = "break-glass"
    for p in people:          # first names, kept only where unambiguous is decided by the caller (see ambiguous)
        if p["kind"] == "user" and p["email"] not in out:
            first = p["name"].split()[0]
            if says(text, first) and not any(says(text, q["name"]) for q in people if q["name"].startswith(first)):
                out[p["email"]] = first
    return out


def ambiguous_names(org, text):
    """First names in the request that fit more than one person: {first name: [full names]}."""
    found = {}
    for p in org.directory():
        if p["kind"] != "user":
            continue
        first = p["name"].split()[0]
        if says(text, first) and not says(text, p["name"]) and not says(text, p["email"]):
            found.setdefault(first, []).append(p["name"])
    return {k: v for k, v in found.items() if len(v) > 1 and not any(says(text, n) for n in v)}


TYPE_WORDS = {"dataset": "dataset", "table": "dataset", "bucket": "bucket", "project": "project", "folder": "folder",
              "org": "organization", "organization": "organization", "service account": "service_account"}


def resources_named(org, text, skip=()):
    """Resources the request names by their own name (full display name, hyphens and underscores as spaces), kept to
    the type the request says if it says one ('the billing dataset'). The longest name wins ('nw-billing-prod' is not
    also 'prod' and 'billing'), and words that name a person or group (`skip`) never name a resource."""
    for phrase in sorted(skip, key=len, reverse=True):
        text = re.sub(re.escape(str(phrase)), " ", str(text), flags=re.I)
    hits = [r for r in org.resources() if r["type"] != "organization" and says(text, r["display"])]
    hits = [r for r in hits if not any(q is not r and len(_norm(q["display"])) > len(_norm(r["display"])) and
                                       f" {_norm(r['display']).strip()} " in _norm(q["display"]) for q in hits)]
    types = {t for w, t in TYPE_WORDS.items() if says(text, w) or says(text, w + "s")}
    typed = [r for r in hits if r["type"] in types]
    if typed:
        return typed
    # 'buckets in prod': the type word describes what's asked about, not the scope; keep scope-like resources
    return [r for r in hits if not types or r["type"] in ("folder", "project")] or hits


def action_permission(text):
    """The permission behind an action the request names ('delete buckets' -> storage.buckets.delete), or None."""
    for phrase, perm in sorted(catalogue.ACTIONS.items(), key=lambda kv: -len(kv[0])):
        if says(text, phrase) or says(text, phrase.rstrip("s")):
            return perm
    return None


def roles_named(text, roles):
    """Roles the request names: 'Owner' -> roles/owner, 'roles/storage.admin', 'Storage Admin'."""
    out = []
    for rid, r in roles.items():
        short = rid.split("/", 1)[1]
        if says(text, rid) or says(text, short) or says(text, r.get("title", "")):
            out.append(rid)
    return out


# -- facts about a proposal ---------------------------------------------------------------------------------------

def is_basic(role):
    return role in catalogue.BASIC


def is_public(email):
    return email in ("allUsers", "allAuthenticatedUsers")


def domain_ok(org, email):
    domains = org.allowed_domains()
    return not domains or email.split("@")[-1].lower() in domains


def in_directory(org, email):
    return org.person(email) is not None


def kind_of(org, email):
    p = org.person(email)
    return p["kind"] if p else None


def self_grant(org, email, requester):
    """The requester, or a group the requester is in."""
    if not requester:
        return False
    if email.lower() == requester.lower():
        return True
    return requester in (org.person(email) or {}).get("members", [])


def narrowest(org, resource, access):
    r = org.resource(resource)
    if not r:
        return None
    service = catalogue.TYPE_SERVICE.get(r["type"])
    return catalogue.NARROWEST.get((service, access)) if service else None


def least_privilege(org, resource, access, role):
    """The role is the narrowest that covers the access, or holds no permission that one doesn't."""
    want = narrowest(org, resource, access)
    if want is None:
        return False
    roles = org.roles()
    return role == want or catalogue.permissions(role, roles) <= catalogue.permissions(want, roles)


def extra_permissions(org, resource, access, role):
    want = narrowest(org, resource, access)
    roles = org.roles()
    return len(catalogue.permissions(role, roles) - catalogue.permissions(want, roles)) if want else 0


def role_fits(org, role, resource):
    r, info = org.resource(resource), org.roles().get(role)
    if not r or not info:
        return False
    service = catalogue.TYPE_SERVICE.get(r["type"])
    return r["type"] in info["levels"] and (info["service"] in (service, "basic") or service is None)


def under_prod(org, resource):
    return any(a["type"] == "folder" and a["display"] == PROD_FOLDER for a in org.ancestors(resource))


def conditions_supported(org, resource):
    """Cloud Storage allows IAM Conditions only on buckets with uniform bucket-level access."""
    r = org.resource(resource) or {}
    return r.get("type") != "bucket" or bool(r.get("uniform_access"))


def expiry_condition(days, now):
    end = (now + dt.timedelta(days=days)).replace(microsecond=0).astimezone(dt.timezone.utc)
    stamp = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"title": f"expires {end.strftime('%d %b %Y')}", "description": "time-bound access granted by shio-iam",
            "expression": f'request.time < timestamp("{stamp}")'}


def break_glass(org):
    return [p["email"] for p in org.directory() if "break-glass" in p.get("tags", [])]


# -- the change set ------------------------------------------------------------------------------------------------

def bindings_with(org, scope, role, email=None):
    """[(resource, member)] where `role` is bound at or below `scope` (to `email` only, if given)."""
    out = []
    for r in org.below(scope):
        try:
            bs = org.policy(r["name"])["bindings"]
        except Exception:
            continue
        for b in bs:
            if b["role"] != role:
                continue
            for m in b["members"]:
                if email is None or member_email(m).lower() == email.lower():
                    out.append((r["name"], m))
    return out


def plan(org, p, now):
    """The exact policy changes a checked proposal means. p: the proposal as a dict (intent, principals, except,
    role, resource, days). -> {resource: [{"op": "add"|"remove", "member", "role", "condition"}]}"""
    ops = {}
    if p["intent"] == "grant":
        cond = expiry_condition(p["days"], now) if p.get("days") else None
        for email in p["principals"]:
            kind = kind_of(org, email) or "user"
            ops.setdefault(p["resource"], []).append(
                {"op": "add", "member": member_for(email, kind), "role": p["role"], "condition": cond})
    elif p["intent"] == "revoke":
        scope = p["resource"] or org_root(org)
        everyone = p["principals"] == ["*"]
        targets = [None] if everyone else p["principals"]
        keep = {e.lower() for e in p.get("except", [])}
        for email in targets:
            for res, m in bindings_with(org, scope, p["role"], email):
                if member_email(m).lower() in keep:
                    continue
                ops.setdefault(res, []).append({"op": "remove", "member": m, "role": p["role"], "condition": None})
    return ops


def org_root(org):
    return next(r["name"] for r in org.resources() if r["type"] == "organization")


def apply_ops(bindings, ops):
    """New bindings from old ones and a list of ops. Pure: the dry run and the apply both use it."""
    out = [dict(b, members=list(b["members"])) for b in bindings]
    for o in ops:
        cond = o.get("condition")
        if o["op"] == "add":
            same = next((b for b in out if b["role"] == o["role"] and b.get("condition") == cond), None)
            if same is None:
                same = {"role": o["role"], "members": []}
                if cond:
                    same["condition"] = cond
                out.append(same)
            if o["member"] not in same["members"]:
                same["members"].append(o["member"])
        else:
            for b in out:
                if b["role"] == o["role"] and o["member"] in b["members"]:
                    b["members"].remove(o["member"])
    return [b for b in out if b["members"]]


def diff(org, ops):
    """The dry run: for each resource, its current etag, the bindings before and after, and +/- lines."""
    out = []
    for res, changes in ops.items():
        pol = org.policy(res)
        after = apply_ops(pol["bindings"], changes)
        lines = []
        for c in changes:
            sign = "+" if c["op"] == "add" else "-"
            cond = f'  if {c["condition"]["expression"]}' if c.get("condition") else ""
            lines.append(f'{sign} {c["role"]}  {c["member"]}{cond}')
        r = org.resource(res)
        out.append({"resource": res, "display": r["display"] if r else res, "type": r["type"] if r else "",
                    "etag": pol["etag"], "before": pol["bindings"], "after": after, "lines": lines,
                    "changes": changes})
    return out


def losses(org, ops):
    """What each removal actually takes away, after inheritance: [{member, role, on, keeps_via}] where keeps_via is
    another binding that still grants the same role there (inherited or direct), if any."""
    out = []
    for res, changes in ops.items():
        for c in changes:
            if c["op"] != "remove":
                continue
            email = member_email(c["member"])
            keeps = None
            for a in org.ancestors(res)[1:]:
                for b in org.policy(a["name"])["bindings"]:
                    if b["role"] == c["role"] and any(email in org.expand(m) for m in b["members"]):
                        keeps = a["display"]
            r = org.resource(res)
            out.append({"member": c["member"], "kind": kind_of(org, email), "role": c["role"],
                        "on": r["display"] if r else res, "keeps_via": keeps})
    return out


def breaking(org, ops):
    """Removals that may stop something working: a service account losing a role it holds directly (a workload uses
    it), or a resource left with no one who can change its IAM policy."""
    out = []
    for l in losses(org, ops):
        if l["kind"] == "serviceAccount" and not l["keeps_via"]:
            out.append(f'{member_email(l["member"])} loses {l["role"]} on {l["on"]}: a workload may stop working')
    roles = org.roles()
    for res, changes in ops.items():
        after = apply_ops(org.policy(res)["bindings"], changes)
        admins = []
        for a in org.ancestors(res):
            bs = after if a["name"] == res else org.policy(a["name"])["bindings"]
            for b in bs:
                if any(p.endswith(".setIamPolicy") for p in catalogue.permissions(b["role"], roles)):
                    admins += b["members"]
        if not admins:
            r = org.resource(res)
            out.append(f'no one could change IAM on {r["display"] if r else res} afterwards')
    return out


def already_granted(org, ops):
    """Adds that change nothing: the member already holds the role there or above it, with no condition."""
    out = []
    for res, changes in ops.items():
        for c in changes:
            if c["op"] != "add":
                continue
            for a in org.ancestors(res):
                for b in org.policy(a["name"])["bindings"]:
                    if b["role"] == c["role"] and c["member"] in b["members"] and not b.get("condition"):
                        out.append(f'{member_email(c["member"])} already has {c["role"]} on {a["display"]}'
                                   + (" (inherited)" if a["name"] != res else ""))
    return out


MAX_PRINCIPALS = 1500        # per allow policy; every appearance counts (docs.cloud.google.com/iam/quotas)


def over_limits(org, ops):
    """Policies the change would push past Google's principal limit."""
    out = []
    for res, changes in ops.items():
        n = sum(len(b["members"]) for b in apply_ops(org.policy(res)["bindings"], changes))
        if n > MAX_PRINCIPALS:
            out.append(f"{(org.resource(res) or {}).get('display', res)} would hold {n} principals (limit {MAX_PRINCIPALS})")
    return out


def removes_break_glass(org, ops):
    bg = {e.lower() for e in break_glass(org)}
    return sorted({member_email(c["member"]) for cs in ops.values() for c in cs
                   if c["op"] == "remove" and member_email(c["member"]).lower() in bg})


def denied_after(org, ops, permission_hint=None):
    """Grants a deny policy will block anyway: [(member, policy)]. Checked for each permission the role holds."""
    out = []
    roles = org.roles()
    for res, changes in ops.items():
        for c in changes:
            if c["op"] != "add":
                continue
            for perm in sorted(catalogue.permissions(c["role"], roles)):
                d = org.denied(member_email(c["member"]), perm, res)
                if d:
                    out.append(f'{member_email(c["member"])}: {perm} is blocked by deny policy "{d["policy"]}"')
                    break
    return out


COMMON = ["understood"]
FOR_INTENT = {
    "grant": ["one_person", "principals_given", "principals_exist", "principals_named", "not_public", "domain_allowed",
              "no_self_grant", "resource_exists", "resource_named", "role_exists", "no_basic_role", "access_matches",
              "least_privilege", "role_fits", "duration_matches", "within_max", "prod_expires", "conditions_supported",
              "something_to_change", "not_redundant", "within_limits"],
    "revoke": ["one_person", "principals_given", "principals_exist", "principals_named", "domain_allowed",
               "exceptions_named", "resource_exists", "resource_named", "role_exists", "role_named_for_revoke",
               "something_to_change", "keeps_break_glass", "someone_can_admin"],
    "question": ["resource_exists", "resource_named", "question_target", "permission_exists", "permission_matches",
                 "asked_principal_exists"],
}


def relevant(intent, names):
    """The checks that mean something for this kind of request (the others pass trivially)."""
    keep = set(COMMON + FOR_INTENT.get(intent, []))
    return [n for n in names if n in keep]


# -- answering questions --------------------------------------------------------------------------------------------

def answer(org, permission=None, role=None, principal=None, scope=None):
    """The answer to an access question, computed from the policies (Policy Analyzer for a real org). Every person
    and every count in it comes from these rows."""
    scope = scope or org_root(org)
    rows = []
    if permission:
        rows = org.analyze(permission, scope)
    elif role:
        above = [(a["name"], m) for a in org.ancestors(scope)[1:] for b in org.policy(a["name"])["bindings"]
                 if b["role"] == role and condition_holds(b.get("condition"), org.now()) for m in b["members"]]
        for res, m in above + bindings_with(org, scope, role):
            r = org.resource(res)
            for email in org.expand(m):
                rows.append({"principal": email, "via": m if member_email(m) != email else None, "role": role,
                             "bound_on": r["display"], "bound_on_type": r["type"], "resource": r["display"],
                             "resource_type": r["type"], "inherited": (res, m) in above, "condition": None,
                             "denied_by": None})
    elif principal:
        emails = {principal.lower()} | {g.lower() for g in org.groups_of(principal)}
        for r in org.below(scope):
            for b in org.policy(r["name"])["bindings"]:
                if not condition_holds(b.get("condition"), org.now()):
                    continue
                for m in b["members"]:
                    if member_email(m).lower() in emails or (m.startswith("domain:") and principal.endswith(m[7:])):
                        rows.append({"principal": principal, "via": m if member_email(m).lower() != principal.lower()
                                     else None, "role": b["role"], "bound_on": r["display"], "bound_on_type": r["type"],
                                     "resource": r["display"], "resource_type": r["type"], "inherited": False,
                                     "condition": (b.get("condition") or {}).get("expression"), "denied_by": None})
    effective = [x for x in rows if not x["denied_by"]]
    people = sorted({x["principal"] for x in effective})
    blocked = sorted({x["principal"] for x in rows if x["denied_by"]} - set(people))
    risks = []
    basic = {}
    for x in effective:
        if is_basic(x["role"]) and not role:
            basic.setdefault(x["principal"], set()).add(x["role"].split("/")[1].title())
        if is_public(x["principal"]):
            risks.append(f'{x["principal"]} (anyone on the internet) has it on {x["resource"]}')
    for who, rs in sorted(basic.items()):
        risks.append(f'{who} has it only through a basic role ({", ".join(sorted(rs))})' if all(
            is_basic(x["role"]) for x in effective if x["principal"] == who) else
            f'{who} also has it through a basic role ({", ".join(sorted(rs))})')
    for x in effective:
        if (org.person(x["principal"]) or {}).get("kind") == "serviceAccount" and \
                (org.person(x["principal"]) or {}).get("keys"):
            risks.append(f'{x["principal"]} is a service account with {org.person(x["principal"])["keys"]} '
                         f'user-managed key(s): anyone holding a key has this access')
    return {"scope": (org.resource(scope) or {}).get("display", scope), "permission": permission, "role": role,
            "principal": principal, "rows": rows, "principals": people, "blocked_by_deny": blocked,
            "count": len(people), "risks": sorted(set(risks))}


def answer_text(a):
    what = a["permission"] or a["role"] or a["principal"]
    if a["principal"]:
        if not a["rows"]:
            return f'{a["principal"]} holds no roles in {a["scope"]}.'
        lines = [f'{a["principal"]} holds {len(a["rows"])} role binding(s) in {a["scope"]}:']
        for x in a["rows"]:
            via = f' (through {x["via"]})' if x["via"] else ""
            lines.append(f'  {x["role"]} on {x["bound_on"]}{via}')
        return "\n".join(lines)
    if not a["principals"]:
        head = f'No one has {what} in {a["scope"]}.'
    else:
        verb = "hold" if a["role"] else "can use"
        head = f'{a["count"]} principal(s) {verb} {what} in {a["scope"]}:'
    lines = [head]
    by = {}
    for x in a["rows"]:
        if x["denied_by"]:
            continue
        by.setdefault(x["principal"], set()).add(
            f'{x["role"]} on {x["bound_on"]}' + (" (inherited)" if x["inherited"] and a["role"] else "")
            + (f' via {member_email(x["via"])}' if x["via"] else ""))
    for p in a["principals"]:
        lines.append(f'  {p}: ' + "; ".join(sorted(by[p])))
    if a["blocked_by_deny"]:
        lines.append(f'  Allowed by an allow policy but blocked by a deny policy: {", ".join(a["blocked_by_deny"])}')
    for r in sorted(set(a["risks"])):
        lines.append(f"  Risk: {r}")
    return "\n".join(lines)


def to_json(x):
    return json.dumps(x, indent=1, default=str)
