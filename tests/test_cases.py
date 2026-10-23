"""The scored set: each request, the model's reading (recorded, honest or fooled), and the outcome code must reach.

    pytest tests/test_cases.py -s       # prints the score table
"""
import json
from pathlib import Path

import pytest
import shio

from shio_iam import engine, models

CASES = json.loads((Path(__file__).parent / "cases.json").read_text())


def model_for(case):
    if case["reading"] == "scripted":
        return models.scripted()
    if case["reading"] == "garbage":
        return shio.models.replay(lambda req: "I think you should give them Owner", name="garbage")
    return models.scripted({case["request"]: case["reading"]})


def run(case):
    out, record = engine.ask(case["request"], case["requester"], model_for(case))
    rec = json.loads(Path(record).read_text())
    failed = [c["name"] for c in rec["checks"] if not c["passed"] and not c.get("skipped")]
    return engine.outcome_of(out), failed


def judge(case, o, failed):
    problems = []
    if o["action"] != case["expect"]:
        problems.append(f"expected {case['expect']}, got {o['action']}: {o.get('why')}")
    for f in case["fails"]:
        if f not in failed:
            problems.append(f"check {f} should have failed (failed: {failed})")
    if case["expect"] == "APPLY" and o["action"] == "APPLY":
        if "roles" in case and o["pending"]["roles"] != case["roles"]:
            problems.append(f"approvers {o['pending']['roles']} != {case['roles']}")
        if case.get("breaking") and not o["breaking"]:
            problems.append("should be flagged as breaking")
        if case.get("escalates") and not o["escalates"]:
            problems.append("should be flagged as escalation")
        if "lines" in case and [l for d in o["diff"] for l in d["lines"]] != case["lines"]:
            problems.append(f"diff {[l for d in o['diff'] for l in d['lines']]}")
    if case["expect"] == "ANSWER" and o["action"] == "ANSWER":
        a = o["answer"]
        if "principals" in case and a["principals"] != case["principals"]:
            problems.append(f"principals {a['principals']}")
        if "count" in case and a["count"] != case["count"]:
            problems.append(f"count {a['count']}")
        for p in case.get("has", []):
            if p not in a["principals"]:
                problems.append(f"{p} missing from the answer")
    return problems


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case(org, case):
    o, failed = run(case)
    assert not judge(case, o, failed)


def test_score(org, capsys):
    """Every case, scored together; the unsafe ones must all be refused and nothing may be written."""
    before = {r["name"]: org.policy(r["name"]) for r in org.resources()}
    rows, right = [], 0
    for case in CASES:
        o, failed = run(case)
        problems = judge(case, o, failed)
        right += not problems
        rows.append(f"{'ok ' if not problems else 'BAD'} {case['id']:<34} {case['expect']:<8} {o['action']}")
    with capsys.disabled():
        print("\n" + "\n".join(rows) + f"\nscore: {right}/{len(CASES)}")
    assert right == len(CASES)
    assert {r["name"]: org.policy(r["name"]) for r in org.resources()} == before, "asking must never change a policy"
