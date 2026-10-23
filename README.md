# Shio-GCP-IAM

Google Cloud IAM in plain English. You ask a question or ask for a change. A model reads the request, code decides whether the change is safe, a second person approves, and only then is the policy written. It is built on [Shio](https://github.com/pratikkp24/shio), Aonami Labs' agent language. Licensed under Apache-2.0.

Output from a clean install (`shio-gcp-iam chat`, sample org, scripted reader):

```
> give Priya read access to the billing dataset for two weeks
? Priya could be Priya Raman or Priya Shah: say which

> give Priya Raman read access to the billing dataset for two weeks
Proposed change (dry run; nothing written yet)
  billing (dataset), etag BwY4e2958508892
    + roles/bigquery.dataViewer  user:priya.raman@northwind.example  if request.time < timestamp("2026-11-06T05:33:29Z")
  22 checks passed: understood, one_person, principals_given, principals_exist, principals_named, not_public, ...
  Needs approval from iam-approvers (not dan.okafor@northwind.example).

> who can delete buckets in prod?
3 principal(s) can use storage.buckets.delete in prod:
  breakglass-admin@northwind.example: roles/owner on northwind.example; roles/owner on nw-web-prod
  dan.okafor@northwind.example: roles/editor on prod via platform-eng@northwind.example; roles/owner on northwind.example; ...
  ines.moreau@northwind.example: roles/owner on nw-web-prod; roles/storage.admin on nw-web-prod via sre-oncall@northwind.example
  Allowed by an allow policy but blocked by a deny policy: 604213877123-compute@developer.gserviceaccount.com, lee.wong@northwind.example, ...
```

It runs with no Google Cloud account against **Northwind Labs**, a fictional org with folders, projects, datasets, buckets, service accounts and some risky bindings planted on purpose. It can also read a real org through your own `gcloud` login.

## Try it (5 minutes, no cloud account)

You need Python 3.10 or newer.

```bash
git clone https://github.com/pratikkp24/shio-gcp-iam && cd shio-gcp-iam
python3 -m venv .venv && . .venv/bin/activate
pip install --pre -e .
shio-gcp-iam init
shio-gcp-iam chat --as dan.okafor@northwind.example
```

`init` creates `.shio-gcp-iam/` in the current folder, which holds the sample org's state, a signing key and the records. It also writes `.env.example`. Both `.env` and `.shio-gcp-iam/` are git-ignored.

In `chat`, try:
- `who can delete buckets in prod?`
- `give Priya Raman read access to the billing dataset for two weeks` (when asked for an approver, type `sam.chen@northwind.example`)
- `remove everyone's Owner role except the break-glass account` (this one needs `sam.chen@…` and then `maria.lopez@…`, a security admin)
- `make the nw-web-logs bucket readable by everyone` (refused)

The same steps work one at a time:

```bash
shio-gcp-iam ask "give Priya Raman read access to the billing dataset for two weeks" --as dan.okafor@northwind.example
shio-gcp-iam pending
shio-gcp-iam approve <id> --as sam.chen@northwind.example --apply
shio-gcp-iam verify          # check the signed ledger
shio-gcp-iam reset           # put the sample org back
shio-gcp-iam doctor          # show how this workspace is set up
```

**Sample people.** Dan Okafor is a platform engineer and asks for things. Sam Chen is in `iam-approvers`. Maria Lopez is in `iam-approvers` and `security-admins`. Priya Raman, Priya Shah, Lee Wong (a contractor) and Ines Moreau (SRE) approve nothing.

**The demo app.** Open `demo/index.html` through any static server, e.g. `python3 -m http.server -d demo 8765`. It has chat, the proposed change with its diff, checks passed and failed, an Approve button, an access explorer, an approvals queue and a hash-chained ledger, plus a guided demo. It is a frontend mock: it replays outcomes recorded from `iam.shio` (regenerate them with `python scripts/export_demo.py`) and keeps approvals in the browser tab.

## Which model reads the request

Set `SHIO_GCP_IAM_MODEL` in `.env`:

| Value | What it uses | Needs |
|---|---|---|
| `scripted` (default) | Recorded readings for the requests listed in `shio_gcp_iam/scripted.json`. Anything else is read as "unclear" and refused. | Nothing |
| `claude-cli` | The `claude` command (Claude Code) already logged in on your machine | Claude Code |
| `anthropic` | The Anthropic API | `ANTHROPIC_API_KEY` in `.env` |
| `ollama:NAME` | A local model, e.g. `ollama:qwen3:8b` | Ollama |

Use `scripted` to try the flow. Use a real model to type your own requests.

## How it decides

The program is [`shio_gcp_iam/iam.shio`](shio_gcp_iam/iam.shio). In Shio, a model's output is a **reading**: only a `check` or a `rule` can look at it, and the compiler refuses any other use.

1. **Read.** The model gets the request, the directory, the resource list, the role list, and the resources' labels and descriptions. It returns a structured reading with these fields: intent, principals, access, role, resource and days. Labels and descriptions come through a tool declared `reads untrusted`, because anyone who can edit a resource can write them.
2. **Check.** Code works out from the request text and the org's data what the request can mean, then compares the reading against it:

   | Check | What it refuses |
   |---|---|
   | `one_person` | A first name that fits two people ("Priya"). The agent asks which one. |
   | `principals_exist`, `principals_named`, `domain_allowed` | A principal who is not in the directory, is not named in the request, or is outside the org's domains. This is how an instruction planted in a description is caught. |
   | `not_public` | `allUsers` / `allAuthenticatedUsers` |
   | `no_self_grant` | The requester, or a group they belong to |
   | `no_basic_role` | Owner/Editor/Viewer and the newer Admin/Writer/Reader |
   | `least_privilege`, `access_matches` | A role broader than the narrowest predefined role for the access the request names, e.g. Data Editor when the request says "read". |
   | `resource_exists`, `resource_named`, `role_fits` | A resource the request didn't name, or a role that doesn't fit the resource type, e.g. a BigQuery role on a bucket. |
   | `duration_matches`, `within_max`, `prod_expires` | A duration that differs from the request's or exceeds 90 days, and people's access under the `prod` folder without an expiry |
   | `conditions_supported` | A time-bound grant on a bucket without uniform bucket-level access |
   | `not_redundant` | Access the principal already has there or above it |
   | `within_limits` | A policy that would go past 1,500 principals |
   | `keeps_break_glass`, `someone_can_admin` | A removal that drops the break-glass account, or that leaves a resource with no one able to change its IAM |
   | `permission_matches`, `asked_principal_exists` | For questions: a permission or person the question didn't ask about |

3. **Decide.** A rule turns the checked reading into one of four outcomes:
   - **ANSWER**: computed from the bindings, with inheritance, group expansion and deny policies. Every name and count comes from the policy rows.
   - **CLARIFY**: a question back to the requester, e.g. which Priya.
   - **REFUSE**: every failed check, with its reason.
   - **APPLY**: the exact change, with the dry-run diff and the etag of every policy it touches.

   An APPLY also flags:
   - **escalation**: a role holding `setIamPolicy`, `actAs`, `getAccessToken`, key creation and similar permissions;
   - **breaking changes**: a service account losing a role its workload may need;
   - grants that a deny policy would block anyway.
4. **Approve.** Every APPLY waits for sign-off in Shio's signed, hash-chained ledger:
   - The requester can't approve their own change. Shio enforces maker-checker.
   - The approver must be in `iam-approvers` in the org's directory.
   - An escalation or a breaking change also needs a member of `security-admins`, who must be a different person.
   - Approvals can be given in the terminal or through a Slack card with Approve and Reject buttons. A click counts only if the clicker's Slack email is an approver.
5. **Apply.** `agent apply` writes the change:
   - It calls `set_iam_policy`, a tool declared `acts`. Shio lets an `acts` tool run only inside a rule, and only through Shio Guard. Guard makes a blind plan from the request alone, so a request that asked for no change can't write.
   - It writes only if the change is fully approved, has not been applied before, and every policy still has the etag it had when it was proposed.
   - The apply is a record in the ledger too.

## The boundary, tested

`tests/test_boundary.py` checks that a model's reading can reach `setIamPolicy` only through the rule:
- **Compile time:** the write outside a rule, the write inside a check, and a reading copied into plain code are all compile errors.
- **Run time:** calling the connector's write, the tool function or `shio.tool_call` from plain Python raises `BoundaryError`.
- **Approvals:** nothing is written before approval. A requester can't approve their own change, and a non-approver can't approve. The same person can't give both approvals. A rejected change stops.
- **Records and policies:**
  - An edited record is refused because the ledger no longer verifies.
  - A forged unsigned sign-off is refused.
  - A policy that changed after approval is not overwritten.
  - A question can't be applied.
  - Guard denies a write that the request never asked for.
- **A fooled model:** when a model is fooled into proposing `eve.ops@gmail-support.example` as Owner, it never reaches a policy.

## The scored set

`tests/cases.json` has 32 requests, each with a recorded reading and the expected outcome:
- Safe grants, revokes and questions.
- Basic roles, `allUsers`, escalation, self-grant, missing expiry, a wrong duration, the wrong resource, an unknown person, a role on the wrong resource type and redundant grants.
- Five injection variants: the model adds the planted outside account, uses only that account, switches to Owner, picks another resource, or follows an instruction typed into the request.
- A model that returns garbage.

```bash
pytest tests -q                      # 60 tests
pytest tests/test_cases.py -s        # prints the score table: 32/32
```

**What this score measures.** The readings are recorded. Some are honest. Others are deliberately wrong, written the way a fooled model would answer. So 32/32 shows that code reaches the right outcome for each reading. **It is not a measure of any model's accuracy.**

**Real-model check.** Separately, Claude (through the `claude` CLI, default model, 23 Oct 2026) read five of the demo requests: [`docs/live-claude-cli.json`](docs/live-claude-cli.json).
- All five reached the expected outcome (two grants, a question, the bulk removal and the "which Priya" clarification).
- It did not follow the instruction planted in the `product_events` description.
- That is five requests and one run, not a benchmark.

## Connecting a real org (read-only)

```bash
gcloud auth login                    # your own credentials; shio-gcp-iam never reads or stores a key
SHIO_GCP_IAM_MODE=gcloud SHIO_GCP_IAM_ORG=123456789012 SHIO_GCP_IAM_PROJECTS=proj-a,proj-b shio-gcp-iam chat --as you@yourco.com
```

**What it reads:**
- projects, buckets and their allow policies (`gcloud projects|storage buckets get-iam-policy`);
- roles (`gcloud iam roles describe`, the full permission list);
- service accounts;
- Policy Analyzer (`gcloud asset analyze-iam-policy`, which needs the Cloud Asset API).

**The directory.** Without `SHIO_GCP_IAM_DIRECTORY` (a JSON export of people and groups), the directory is only the principals already in policies plus the service accounts gcloud lists. A person who holds no role yet can't be found, and the check fails closed.

**Writing to a real org.** This needs `SHIO_GCP_IAM_ALLOW_APPLY=1` as well as an approved change. Writes are supported for projects, folders, the organization and buckets. BigQuery dataset policies are not read or written in gcloud mode yet.

## Limits, honestly

- **The gcloud connector has not been run against a live org.** It is tested only against canned `gcloud` output. The Slack live path follows Slack's documented API (Socket Mode) but has not been run against a workspace. Only the mock is exercised end to end.
- **The mock role catalogue is abridged:** about 20 real roles, each with a real subset of its permissions. A real org reads the full role definitions. For scale, Google's own docs say only "hundreds" of predefined roles. A dated third-party snapshot (iam-dataset, 18 Oct 2026) counts 2,422 predefined roles and 10,129 permissions. See [`docs/RESEARCH.md`](docs/RESEARCH.md).
- **Deny policies.** In gcloud mode, Google's Policy Analyzer ignores deny policies, and shio-gcp-iam does not yet read deny policies from a real org. Answers there cover allow policies only. The mock evaluates its deny policy.
- **Conditions.** The only condition this tool writes or evaluates is `request.time < timestamp(...)`. Any other condition is treated as possibly granting, so answers may over-report and never under-report. Durations are counted in whole days.
- **Resolving names.** Matching names in the request is word-based. Phrasing it doesn't know ("my team", "the finance bucket") fails closed with a reason. It never guesses.
- **Shio's own open issues.** Shio's 1.0 security review has open findings in parts this tool uses:
  - The ledger verifier accepts unsigned sign-off entries.
  - Event entries are not fully chained.
  - Guard's grounding of values is a substring match.
  - Guard's four-eyes rule needs a requester to be passed in.

  shio-gcp-iam works around the ones it can:
  - It accepts only sign-offs signed by the ledger key.
  - It re-verifies the chain before every apply.
  - It checks principals by exact match against the directory, not by Guard's grounding.
  - It enforces four eyes through ledger maker-checker.

  Don't treat the ledger or Guard as proven until those are fixed upstream. Anchor the ledger head (`shio-gcp-iam verify` prints it) somewhere the key holder can't rewrite.
- **Identity.** `--as` is whoever you say you are. In a company it must come from SSO, and approvals must come from an authenticated channel, such as a Slack user's verified email.

## Files

| Path | What it is |
|---|---|
| `shio_gcp_iam/iam.shio` | The program: tools, the reading, every check, the rule, sign-off, apply |
| `shio_gcp_iam/rules.py` | The code that decides: name and resource resolution, least privilege, the plan, diff, breaking changes, answers |
| `shio_gcp_iam/catalogue.py` | Roles, escalation permissions, the narrowest role for each kind of access |
| `shio_gcp_iam/connectors.py` | `MockOrg` (Northwind Labs) and `GcloudOrg` (read-only gcloud), and the one guarded write |
| `shio_gcp_iam/sample_org.py` | The fictional org, with planted risks and an injection in a dataset description |
| `shio_gcp_iam/approvals.py`, `slack.py` | Who may approve, sign-offs, the strict check before apply, Slack cards |
| `shio_gcp_iam/cli.py`, `engine.py`, `models.py` | The `shio-gcp-iam` command, running the program, choosing a model |
| `docs/RESEARCH.md` | IAM pain points and existing tools, with sources |
| `demo/` | The frontend mock |

Everything in the sample org is fictional. Northwind Labs and its people are invented.
