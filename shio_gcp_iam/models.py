"""Which model reads the request. Pick with SHIO_GCP_IAM_MODEL:

    scripted      (default) recorded answers for the demo requests: no model, no key, no network
    claude-cli    the `claude` CLI already logged in on this machine (Claude Code); nothing to configure
    anthropic     the Anthropic API; needs ANTHROPIC_API_KEY in the environment or .env
    ollama:NAME   a local model served by Ollama, e.g. ollama:qwen3:8b

Whatever the model answers is only a reading: iam.shio's checks decide, and a person approves before anything is
written.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import shio

HERE = Path(__file__).resolve().parent
_SCRIPT = None


def _key(text):
    return re.sub(r"\s+", " ", str(text).strip().lower().rstrip("?.!"))


def script():
    global _SCRIPT
    if _SCRIPT is None:
        _SCRIPT = {_key(c["request"]): c["reading"] for c in json.loads((HERE / "scripted.json").read_text())}
    return _SCRIPT


UNCLEAR = {"intent": "unclear", "principals": [], "except_principals": [], "access": "", "role": "", "resource": "",
           "days": 0, "permission": "", "asked_role": "", "asked_principal": ""}


def _request_of(req):
    """The person's request inside a read: the source named 'request'."""
    for s in req.sources:
        if s.name == "request" and s.text:
            return s.text
    return req.ask


def scripted(answers=None, name="scripted"):
    """A stand-in model that answers from recorded readings (scripted.json, or `answers`: {request: reading}). For an
    unknown request it answers 'unclear', which the checks refuse: it never guesses."""
    table = {_key(k): v for k, v in (answers or {}).items()} if answers is not None else None

    def answer(req):
        got = (table if table is not None else script()).get(_key(_request_of(req)))
        return {**UNCLEAR, **(got or {})}
    return shio.models.replay(answer, name=name)


CHANGE_WORDS = re.compile(r"\b(give|grant|add|allow|let|make|needs?|remove|revoke|take away|drop|strip|delete .* role)\b", re.I)


def scripted_planner():
    """The blind planner for Shio Guard, as a stand-in: from the request alone, does it ask for an IAM change?"""
    def plan(req):
        text = req.sources[0].text if req.sources else req.ask
        acts = bool(CHANGE_WORDS.search(text or "")) and not re.match(r"\s*(who|what|which|how|can|does|list|show)\b",
                                                                      text or "", re.I)
        return {"actions": "change an IAM policy" if acts else "none", "delegated": False,
                "tools": ["set_iam_policy"] if acts else [], "sources": []}
    return shio.models.replay(plan, name="scripted-planner")


class ClaudeCLI:
    """A model behind the `claude` command (Claude Code), using the login it already has. Slow (a process per read)
    but needs no key in this project."""

    def __init__(self, model=None, timeout=240):
        self.model, self.timeout, self.name = model, timeout, "claude-cli"

    def identity(self):
        return {"kind": "claude-cli", "model": self.model or "default"}

    def propose(self, req):
        if not shutil.which("claude"):
            raise RuntimeError("the claude CLI is not installed (https://claude.com/claude-code)")
        msgs = shio.models.messages_for(req)
        prompt = "\n\n".join(m["content"] for m in msgs)
        cmd = ["claude", "-p", "--output-format", "json"] + (["--model", self.model] if self.model else [])
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=self.timeout)
        if p.returncode != 0:
            raise RuntimeError(f"claude CLI failed: {p.stderr.strip()[:300]}")
        text = json.loads(p.stdout).get("result", "")
        m = re.search(r"\{.*\}", text, re.S)
        return m.group(0) if m else text


def load_env(path=".env"):
    """Read KEY=VALUE lines from a git-ignored .env into the environment (never printed, never traced)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def chosen(kind=None):
    """-> (reader model, planner model) for SHIO_GCP_IAM_MODEL (or `kind`)."""
    kind = kind or os.environ.get("SHIO_GCP_IAM_MODEL", "scripted")
    if kind == "scripted":
        return scripted(), scripted_planner()
    if kind == "claude-cli":
        m = ClaudeCLI(os.environ.get("SHIO_GCP_IAM_CLAUDE_MODEL"))
        return m, m
    if kind == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise SystemExit("SHIO_GCP_IAM_MODEL=anthropic needs ANTHROPIC_API_KEY (put it in .env, which git ignores)")
        m = shio.models.anthropic(os.environ.get("SHIO_GCP_IAM_ANTHROPIC_MODEL", "claude-opus-5-5"))
        return m, m
    if kind.startswith("ollama:"):
        m = shio.models.ollama(kind.split(":", 1)[1])
        return m, m
    raise SystemExit(f"unknown SHIO_GCP_IAM_MODEL {kind!r}: use scripted, claude-cli, anthropic or ollama:NAME")
