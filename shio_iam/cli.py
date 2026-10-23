"""shio-iam: Google Cloud IAM in plain English, with checks and a second person before anything changes.

    shio-iam init                                    set up a workspace here (.shio-iam/), sample org, signing key
    shio-iam chat --as dan.okafor@northwind.example  ask and approve in the terminal
    shio-iam ask "who can delete buckets in prod?" --as dan.okafor@northwind.example
    shio-iam approve <record> --as sam.chen@northwind.example
    shio-iam apply <record>
    shio-iam pending | verify | doctor | reset
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from . import approvals, connectors, engine, models

GREEN, RED, YELLOW, DIM, BOLD, END = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    GREEN = RED = YELLOW = DIM = BOLD = END = ""

ENV_EXAMPLE = """# shio-iam settings. Copy to .env (git-ignored). Never commit real tokens.
# Who you are when you ask (an email in your org's directory):
SHIO_IAM_USER=dan.okafor@northwind.example
# Which model reads requests: scripted (no model, demo requests only), claude-cli, anthropic, ollama:qwen3:8b
SHIO_IAM_MODEL=scripted
# ANTHROPIC_API_KEY=
# A real org instead of the Northwind Labs mock (read-only; uses your own `gcloud auth login`):
# SHIO_IAM_MODE=gcloud
# SHIO_IAM_ORG=123456789012
# SHIO_IAM_PROJECTS=my-project-a,my-project-b
# SHIO_IAM_DIRECTORY=directory.json
# Writing to a real org also needs this, and an approved change:
# SHIO_IAM_ALLOW_APPLY=1
# Slack approval cards (Socket Mode):
# SLACK_BOT_TOKEN=
# SLACK_APP_TOKEN=
# SLACK_CHANNEL=#iam-approvals
"""


def find_record(ref):
    p = Path(ref)
    if p.exists():
        return p
    hits = sorted(approvals.records().glob(f"*{ref}*.json"))
    if len(hits) == 1:
        return hits[0]
    raise SystemExit(f"no single record matches {ref!r} in {approvals.records()}")


def who(args):
    w = getattr(args, "as_", None) or os.environ.get("SHIO_IAM_USER")
    if not w:
        raise SystemExit("say who you are: --as you@yourdomain (or SHIO_IAM_USER in .env)")
    return w


def show(out, record=None):
    o = engine.outcome_of(out)
    action = o.get("action")
    if action == "ANSWER":
        print(o["text"])
    elif action == "CLARIFY":
        print(f"{YELLOW}?{END} {o['question']}")
    elif action == "REFUSE":
        print(f"{RED}Refused.{END} Nothing will change:")
        for w in o.get("why", []):
            print(f"  {RED}x{END} {w}")
    elif action == "APPLY":
        print(f"{BOLD}Proposed change{END} (dry run; nothing written yet)")
        for d in o["diff"]:
            print(f"  {d['display']} ({d['type']}), etag {d['etag']}")
            for line in d["lines"]:
                print(f"    {GREEN if line.startswith('+') else RED}{line}{END}")
        print(f"  {GREEN}{len(o['passed'])} checks passed{END}: {', '.join(o['passed'])}")
        for b in o["breaking"]:
            print(f"  {YELLOW}! may break:{END} {b}")
        if o["escalation"]:
            print(f"  {YELLOW}! widens power:{END} {', '.join(o['escalation'])}")
        for d in o["denied"]:
            print(f"  {YELLOW}! no effect:{END} {d}")
        needs = " and ".join(approvals.ROLE_GROUPS[r] for r in o["pending"]["roles"])
        print(f"  Needs approval from {needs} (not {o['requester']}).")
    else:
        print(json.dumps(o, indent=1, default=str))
    if record:
        print(f"{DIM}record: {Path(record).name}{END}")


def cmd_init(args):
    home = approvals.home()
    approvals.ensure_keys()
    connectors.connect(reset=True)
    approvals.records().mkdir(parents=True, exist_ok=True)
    if not Path(".env.example").exists():
        Path(".env.example").write_text(ENV_EXAMPLE)
    gi = Path(".gitignore")
    lines = gi.read_text().splitlines() if gi.exists() else []
    add = [x for x in (".env", ".shio-iam/") if x not in lines]
    if add:
        gi.write_text("\n".join(lines + add) + "\n")
    print(f"workspace: {home.resolve()}  (signing key in {home / 'keys'}, records in {home / 'records'})")
    print(f"org: {connectors.connect().mode}  model: {os.environ.get('SHIO_IAM_MODEL', 'scripted')}")
    print("next: shio-iam chat --as dan.okafor@northwind.example")


def cmd_ask(args):
    out, record = engine.ask(" ".join(args.request), who(args))
    show(out, record)
    o = engine.outcome_of(out)
    if o.get("action") == "APPLY" and args.slack:
        from . import slack
        print(slack.post(record))


def cmd_approve(args):
    rec = find_record(args.record)
    try:
        res = engine.approve(rec, who(args), note=args.note or "", reject=args.reject)
    except approvals.ApprovalRefused as e:
        raise SystemExit(f"{RED}not accepted:{END} {e}")
    print(f"{res['decision']} by {res['by']} as {res['role']}: the change is now {res['status']}")
    if res["status"] == "APPROVED" and args.apply:
        cmd_apply(argparse.Namespace(record=str(rec)))


def cmd_apply(args):
    out, run = engine.apply(find_record(args.record))
    if out["action"] == "APPLIED":
        print(f"{GREEN}Applied{END} (approved by {', '.join(out['approved_by'])}):")
        for a in out["applied"]:
            print(f"  {a['resource']}  new etag {a['etag']}")
    else:
        print(f"{RED}Not applied:{END} " + "; ".join(out.get("why", [])))
    print(f"{DIM}record: {Path(run).name}{END}")


def cmd_pending(args):
    n = 0
    for rec in sorted(approvals.records().glob("ask-*.json")):
        status, needed, decided = approvals.waiting_for(rec)
        if status == "PENDING":
            n += 1
            print(f"{rec.stem.split('-')[-1]}  {decided['requester']}: {decided['request']}  "
                  f"(needs {', '.join(approvals.ROLE_GROUPS[r] for r in needed)})")
        elif status == "APPROVED" and not approvals.applied(rec.name):
            n += 1
            print(f"{rec.stem.split('-')[-1]}  APPROVED, not applied yet: {decided['request']}")
    if not n:
        print("nothing waiting")


def cmd_verify(args):
    from shio import ledger
    approvals.ensure_keys()
    ok, report, head = ledger.verify(approvals.records(), public_key=approvals.public_key())
    print("\n".join(report))
    sys.exit(0 if ok else 1)


def cmd_doctor(args):
    models.load_env()
    org = connectors.connect()
    print(f"workspace     {approvals.home().resolve()}")
    print(f"org           {org.mode}" + (f" (org {getattr(org, 'org_id', '')})" if org.mode == "gcloud" else
                                           " (Northwind Labs sample org)"))
    print(f"gcloud        {'found' if shutil.which('gcloud') else 'not installed (only needed for a real org)'}")
    print(f"model         {os.environ.get('SHIO_IAM_MODEL', 'scripted')}"
          f"{'' if os.environ.get('SHIO_IAM_MODEL', 'scripted') != 'claude-cli' else ' (claude ' + ('found)' if shutil.which('claude') else 'NOT found)')}")
    print(f"signing key   {os.environ.get('SHIO_SIGNING_KEY') or 'made on first run in ' + str(approvals.home() / 'keys')}")
    print(f"slack         {'live' if os.environ.get('SLACK_BOT_TOKEN') else 'mock (cards go to slack-outbox.jsonl)'}")
    print(f"writes        {'ALLOWED to the real org' if os.environ.get('SHIO_IAM_ALLOW_APPLY') == '1' and org.mode == 'gcloud' else 'mock org only' if org.mode == 'mock' else 'off (read-only)'}")


def cmd_reset(args):
    p = approvals.home() / "org-state.json"
    if p.exists():
        p.unlink()
    connectors.connect(reset=True)
    print("the sample org is back to its starting policies (records are kept)")


def cmd_slack(args):
    from . import slack
    slack.listen()


def cmd_chat(args):
    me = who(args)
    print(f"{BOLD}shio-iam{END} as {me}, org: {connectors.connect().mode}. Ask in plain English; empty line to quit.")
    print(f"{DIM}Try: who can delete buckets in prod? | give Priya Raman read access to the billing dataset for two weeks"
          f" | remove everyone's Owner role except the break-glass account{END}")
    while True:
        try:
            q = input(f"\n{BOLD}>{END} ").strip()
        except EOFError:
            break
        if not q:
            break
        out, record = engine.ask(q, me)
        show(out, record)
        o = engine.outcome_of(out)
        while o.get("action") == "APPLY":
            status, needed, _ = approvals.waiting_for(record)
            if status != "PENDING":
                break
            approver = input(f"Approver's email for {approvals.ROLE_GROUPS[needed[0]]} (empty to leave it pending): ").strip()
            if not approver:
                print(f"left pending: shio-iam approve {Path(record).stem.split('-')[-1]} --as <approver>")
                break
            ok = input("Approve? [y/N/r=reject]: ").strip().lower()
            if ok not in ("y", "yes", "r"):
                continue
            try:
                res = engine.approve(record, approver, reject=ok == "r")
                print(f"{res['decision']} by {res['by']} as {res['role']}: now {res['status']}")
            except approvals.ApprovalRefused as e:
                print(f"{RED}not accepted:{END} {e}")
                continue
            if res["status"] == "APPROVED":
                cmd_apply(argparse.Namespace(record=str(record)))
                break
            if res["status"] == "REJECTED":
                break


def main(argv=None):
    models.load_env()
    p = argparse.ArgumentParser(prog="shio-iam", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="set up a workspace here").set_defaults(fn=cmd_init)
    a = sub.add_parser("ask", help="ask a question or request a change")
    a.add_argument("request", nargs="+")
    a.add_argument("--as", dest="as_")
    a.add_argument("--slack", action="store_true", help="post the approval card to Slack")
    a.set_defaults(fn=cmd_ask)
    c = sub.add_parser("chat", help="ask and approve interactively")
    c.add_argument("--as", dest="as_")
    c.set_defaults(fn=cmd_chat)
    ap = sub.add_parser("approve", help="approve (or --reject) a pending change")
    ap.add_argument("record")
    ap.add_argument("--as", dest="as_")
    ap.add_argument("--note")
    ap.add_argument("--reject", action="store_true")
    ap.add_argument("--apply", action="store_true", help="apply it if this makes it fully approved")
    ap.set_defaults(fn=cmd_approve)
    y = sub.add_parser("apply", help="apply an approved change")
    y.add_argument("record")
    y.set_defaults(fn=cmd_apply)
    sub.add_parser("pending", help="changes waiting for approval or to be applied").set_defaults(fn=cmd_pending)
    sub.add_parser("verify", help="check the signed ledger").set_defaults(fn=cmd_verify)
    sub.add_parser("doctor", help="show how this workspace is set up").set_defaults(fn=cmd_doctor)
    sub.add_parser("reset", help="put the sample org back to its starting policies").set_defaults(fn=cmd_reset)
    sub.add_parser("slack", help="listen for Approve/Reject clicks in Slack (live mode)").set_defaults(fn=cmd_slack)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
