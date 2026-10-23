"""Approval cards in Slack: a pending change posts a card with Approve and Reject; a click becomes a sign-off only if
the clicker's Slack email is an approver in the org's directory (and is not the person who asked).

Mock by default: cards are written to SHIO_IAM_HOME/slack-outbox.jsonl and clicks are simulated with
`shio-iam approve`. Live with SLACK_BOT_TOKEN and SLACK_APP_TOKEN in .env (Socket Mode, `pip install slack_sdk`),
posting to SLACK_CHANNEL. The live path follows Slack's documented API but has not been run against a workspace.
"""
import json
import os
import time

from . import approvals, engine


def live():
    return bool(os.environ.get("SLACK_BOT_TOKEN") and os.environ.get("SLACK_APP_TOKEN"))


def card(record, decided, pending):
    lines = [l for d in decided.get("diff", []) for l in [f'*{d["display"]}* ({d["type"]})'] + [f"`{x}`" for x in d["lines"]]]
    needs = " and ".join(approvals.ROLE_GROUPS[r] for r in pending.get("roles", []))
    warn = [f":warning: {w}" for w in decided.get("breaking", [])]
    if decided.get("escalation"):
        warn.append(":warning: widens power: " + ", ".join(decided["escalation"]))
    text = (f'*IAM change requested by {decided["requester"]}*\n>{decided["request"]}\n' + "\n".join(lines) +
            ("\n" + "\n".join(warn) if warn else "") + f"\nNeeds: {needs}. {len(decided.get('passed', []))} checks passed.")
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary",
             "action_id": "shio_iam_approve", "value": str(record)},
            {"type": "button", "text": {"type": "plain_text", "text": "Reject"}, "style": "danger",
             "action_id": "shio_iam_reject", "value": str(record)}]},
    ]


def post(record):
    """Post the approval card for a pending change."""
    status, needed, decided = approvals.waiting_for(record)
    blocks = card(record, decided, {"roles": needed})
    if not live():
        out = approvals.home() / "slack-outbox.jsonl"
        with out.open("a") as f:
            f.write(json.dumps({"time": time.time(), "channel": os.environ.get("SLACK_CHANNEL", "#iam-approvals"),
                                "blocks": blocks}) + "\n")
        return {"mode": "mock", "written_to": str(out)}
    from slack_sdk import WebClient
    r = WebClient(token=os.environ["SLACK_BOT_TOKEN"]).chat_postMessage(
        channel=os.environ.get("SLACK_CHANNEL", "#iam-approvals"), blocks=blocks, text="IAM change waiting for approval")
    return {"mode": "live", "ts": r["ts"]}


def listen():
    """Socket Mode: turn Approve/Reject clicks into sign-offs, apply when fully approved, reply in the thread."""
    if not live():
        raise SystemExit("set SLACK_BOT_TOKEN and SLACK_APP_TOKEN in .env to listen for clicks (pip install slack_sdk)")
    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse
    web = WebClient(token=os.environ["SLACK_BOT_TOKEN"])

    def handle(client, req):
        client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        if req.type != "interactive":
            return
        p = req.payload
        act = (p.get("actions") or [{}])[0]
        if act.get("action_id") not in ("shio_iam_approve", "shio_iam_reject"):
            return
        email = web.users_info(user=p["user"]["id"])["user"]["profile"].get("email", "")
        record = act["value"]
        try:
            res = engine.approve(record, email, reject=act["action_id"] == "shio_iam_reject")
            msg = f'{res["decision"]} by {email} as {res["role"]}: now {res["status"]}'
            if res["status"] == "APPROVED":
                out, _ = engine.apply(record)
                msg += f'\n{out["action"]}' + ("" if out["action"] == "APPLIED" else ": " + "; ".join(out.get("why", [])))
        except approvals.ApprovalRefused as e:
            msg = f"Not accepted from {email}: {e}"
        web.chat_postMessage(channel=p["channel"]["id"], thread_ts=p["message"]["ts"], text=msg)

    sm = SocketModeClient(app_token=os.environ["SLACK_APP_TOKEN"], web_client=web)
    sm.socket_mode_request_listeners.append(handle)
    sm.connect()
    print("listening for Approve/Reject clicks; Ctrl-C to stop")
    while True:
        time.sleep(1)
