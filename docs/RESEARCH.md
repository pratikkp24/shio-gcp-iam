# Google Cloud IAM: pain points and tool landscape

Research note for shio-gcp-iam: a natural-language IAM agent where a model proposes a change, code checks decide whether it is safe, and a person approves before apply.

**Conventions.** Every claim has its source next to it. All sources were accessed on **23 Oct 2026** unless a line says otherwise. Google docs now live at `docs.cloud.google.com`, and `cloud.google.com/iam/docs/...` returns a 301 redirect there. The Google IAM pages fetched show "Last updated 2026-10-20 UTC". **Unverified** means I could not find the claim at a primary source.

---

## 1. Basic roles are still over-used

- Google's caution, as written: "Basic roles include thousands of permissions across all Google Cloud services. In production environments, do not grant basic roles unless there is no alternative." The page recommends granting predefined or custom roles instead. [roles-overview](https://docs.cloud.google.com/iam/docs/roles-overview), [allow-policies](https://docs.cloud.google.com/iam/docs/allow-policies)
- **New since most guides were written:** IAM now has basic roles **Admin / Writer / Reader** (`roles/admin`, `roles/writer`, `roles/reader`). Owner, Editor and Viewer are now called "legacy basic roles". You **cannot add conditions** to legacy basic roles. Holders also get extra service-specific access, such as Cloud Storage convenience values and BigQuery special groups. [roles-overview](https://docs.cloud.google.com/iam/docs/roles-overview)
- Default service accounts: "depending on organization policy, the default service account might automatically be granted the Editor role on your project". The page says to enforce `iam.automaticIamGrantsForDefaultServiceAccounts` to stop this. [service-account-types](https://docs.cloud.google.com/iam/docs/service-account-types)
- How common it is (Datadog, *State of Cloud Security*, updated Oct 2025, data from Sep 2025). [datadoghq.com/state-of-cloud-security](https://www.datadoghq.com/state-of-cloud-security/)
  - **17%** of Google Cloud VMs have project "editor" access through the default compute SA with the `cloud-platform` scope.
  - **23%** of VMs have overly permissive project access in total. The chart shows this falling from 37% (2023) and 33% (2024).
  - **10%** of GKE clusters have a privileged SA. The text says 10% and the chart says 11%, so the report is inconsistent with itself.
- Datadog Security Labs, 29 Oct 2024, sample of "thousands" of instances and clusters. [securitylabs.datadoghq.com](https://securitylabs.datadoghq.com/articles/google-cloud-default-service-accounts/)
  - "over one in three" compute instances use the default compute SA.
  - **46%** of GKE clusters use the default SA.
  - Only **31%** of projects don't bind the default compute SA to a privileged role. So roughly two thirds of projects still do.
- Tenable, 26 Mar 2025: **77%** of orgs that had set up Vertex AI Workbench had at least one notebook using the overly privileged default compute SA. [tenable.com blog](https://www.tenable.com/blog/whos-afraid-of-ai-risk-in-cloud-environments)
- Cross-cloud context (old, not GCP-specific): Unit 42, 12 Apr 2022, studied over 680,000 identities across 18,000 accounts. "99% of the cloud users, roles, services and resources were granted excessive permissions" that were left unused. [paloaltonetworks.com](https://www.paloaltonetworks.com/prisma/unit42-cloud-threat-research-volume-six) The "60-day" definition that press coverage attributes to this report was **not** on the page I fetched.

## 2. How many roles and permissions

- Google's docs do not give a total on the index page. [roles-permissions index](https://docs.cloud.google.com/iam/docs/roles-permissions) Google's own wording is "there are hundreds of predefined roles, which can make it difficult to identify the most appropriate roles". [choose-predefined-roles](https://docs.cloud.google.com/iam/docs/choose-predefined-roles)
- Dated third-party count. These figures come from **iam-dataset** (Ian Mckay), whose `gcp/predefined_roles.json` was last committed **2026-10-18**. I counted the files myself. [github.com/iann0036/iam-dataset](https://github.com/iann0036/iam-dataset/tree/main/gcp)
  - **2,422 predefined roles** (1,798 GA, 621 Beta, 3 Deprecated).
  - **10,129 permissions** in `permissions.json`. The file `role_permissions.json` has 14,173 keys, which include permissions the dataset marks as undocumented.
  - In the same dataset, `roles/owner` maps to about 9,996 permissions, `roles/editor` to about 8,782 and `roles/viewer` to about 4,412.
  - Treat all of these as "about N per iam-dataset, 18 Oct 2026", not as an official Google figure.
- Custom roles have their own ceilings. There can be **300** custom roles per org and **300** per project. A custom role can hold **3,000** permissions, and its title, description and permission names together are limited to **64 KB**. [IAM quotas](https://docs.cloud.google.com/iam/quotas)
- Practitioner side: an HN comment (2022) describes over-permissioning "to just get the damn thing to work" when granting BigQuery query access. [HN 33568895](https://news.ycombinator.com/item?id=33568895) A DevOps agency owner (2024) names networking and IAM as the two things that "always trip me up" across clouds. [HN 41184401](https://news.ycombinator.com/item?id=41184401) I found no substantive Reddit threads through search, so none are cited here.

## 3. IAM Conditions and time-bound access

- Time-bound grants use `request.time < timestamp('2020-07-01T00:00:00.000Z')` in a conditional binding. This requires policy **version 3** and the etag read-modify-write pattern. [configuring-temporary-access](https://docs.cloud.google.com/iam/docs/configuring-temporary-access)
- Date and time functions such as `getHours` and `getDayOfWeek` take IANA time zones. `getDayOfWeek` counts 0 as Sunday. [conditions-overview](https://docs.cloud.google.com/iam/docs/conditions-overview)
- Restrictions [conditions-overview](https://docs.cloud.google.com/iam/docs/conditions-overview):
  - "Only some resource types accept conditions."
  - Buckets need uniform bucket-level access before they accept conditions.
  - Conditions are not allowed on legacy basic roles.
  - Conditions are not allowed with `allUsers` or `allAuthenticatedUsers`.
- Limits, all hard limits that cannot be changed [IAM quotas](https://docs.cloud.google.com/iam/quotas):
  - **1** allow policy per resource.
  - **1,500** principals per policy. Every appearance counts and principals are not deduplicated. Conditions or long identifiers can lower this.
  - **250** groups or domains per policy.
  - **12** logic operators per condition expression.
  - **20** bindings with the same role and principal but different conditions.
- Conditional bindings: the 100 figure is **best-practice guidance, not a hard limit**. "don't add more than 100 conditional role bindings to a single allow policy", or "you might exceed the overall size limit". [conditions-overview](https://docs.cloud.google.com/iam/docs/conditions-overview)
- **64 KB policy size: not verified.** The quotas page gives no byte limit for allow policies, and its 64 KB figure is the custom-role limit. The conditions page mentions an "overall size limit" without giving a number. Don't hard-code 64 KB. Count principals against 1,500 and treat the size limit as unknown.

## 4. Inheritance makes "who has access" hard

- The effective policy is "the union of" the resource's own policy and "the allow policies set on all of resource's ancestry". A request is granted "if any of the higher-level role bindings grant access". Conditional bindings "don't override role bindings with no conditions." [allow-policies](https://docs.cloud.google.com/iam/docs/allow-policies)
- What follows: you cannot remove access at a project if it is granted at a folder or the org. Only deny policies or principal access boundary policies can subtract (sections 7 and 8). The answer to "who can X" therefore needs the whole ancestry, group expansion, deny policies and PAB policies.
- Changes are eventually consistent:
  - Allow and deny policy changes take "typically 2 minutes", but "potentially 7 minutes or longer".
  - Group membership changes take "typically several minutes", but "potentially hours or longer".
  - [access-change-propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation) A practitioner write-up describes the Terraform CI/CD failures this lag causes. [emilytburak.net, 22 Sep 2026](https://emilytburak.net/posts/2026-09-22-gcp-iam-eventual-consistency/) I saw this only through its [HN listing](https://news.ycombinator.com/item?id=49815908) and did not read the post.

## 5. Service account keys, impersonation and privilege escalation

- Google's guidance [best-practices-service-accounts](https://docs.cloud.google.com/iam/docs/best-practices-service-accounts):
  - Keys bring "a non-repudiation threat", because "there is no reliable way to tell who used the key".
  - "don't manage access to service accounts at the Google Cloud project or folder level".
  - Token Creator granted on a project lets a user "impersonate any service account in the Google Cloud project".
  - The page describes lateral movement, where an SA in one project can impersonate an SA in another.
- Impersonation needs `iam.serviceAccounts.getAccessToken`, which comes with `roles/iam.serviceAccountTokenCreator`. [service-account-impersonation](https://docs.cloud.google.com/iam/docs/service-account-impersonation)
- Secure-by-default orgs: these constraints are enforced for orgs **created on or after 3 May 2024** (some orgs from Feb to Apr 2024 too). Older orgs must turn them on themselves. [secure-by-default-organizations](https://docs.cloud.google.com/resource-manager/docs/secure-by-default-organizations)
  - `iam.managed.disableServiceAccountKeyCreation`. This is the managed name; the older name was `iam.disableServiceAccountKeyCreation`.
  - `iam.disableServiceAccountKeyUpload`
  - `iam.automaticIamGrantsForDefaultServiceAccounts`
  - `iam.allowedPolicyMemberDomains`
- Key age (Datadog, Oct 2025) [datadoghq.com/state-of-cloud-security](https://www.datadoghq.com/state-of-cloud-security/):
  - **55%** of Google Cloud SAs have active keys older than 1 year, down from 62%.
  - **25%** have keys older than 3 years.
  - **8%** have keys older than 5 years.
- Attack reality, from Google Cloud *Threat Horizons* H1 2026, covering H2 2025 [cloud-threat-horizons-report-h1-2026](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026):
  - Weak or absent credentials fell from **47.1%** of initial access in H1 2025 to **27.2%** in H2 2025.
  - Software exploitation, at **44.5%**, overtook credentials as the top initial access vector for the first time.
- Rhino Security Labs privilege-escalation research by Spencer Gietzen lists **13 method headings**. The page shows no publication date. [rhinosecuritylabs.com](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
  - Credential and role methods: `iam.roles.update`, `iam.serviceAccounts.getAccessToken`, `iam.serviceAccountKeys.create`, `iam.serviceAccounts.implicitDelegation`, `signBlob`, `signJwt`.
  - `iam.serviceAccounts.actAs` combined with creating a resource: `cloudfunctions.functions.create` or `update`, `compute.instances.create`, `run.services.create`, `cloudscheduler.jobs.create`.
  - `deploymentmanager.deployments.create`.
  - `*.setIamPolicy` is used inside several of these chains, for example `cloudfunctions.functions.setIamPolicy` and `run.services.setIamPolicy`.

## 6. Policy Intelligence (Google's own analysis tools)

| Tool | What it does | Limits (verified) |
|---|---|---|
| **Role recommendations (IAM Recommender)** | Compares granted permissions with use over at most the last **90 days**. Projects can be set to 30 or 60 days. Recommends only revoking or replacing a role. Uses ML to predict permissions a principal will need. | **Free only for basic-role recommendations.** Non-basic roles, buckets, datasets, custom-role suggestions, policy insights and lateral-movement insights need **SCC Premium or Enterprise**. No insights for conditional bindings. Only IAM is considered (no ACLs or K8s RBAC). Up to 15 days for new grants. Won't suggest removing the last Owner. [role-recommendations-overview](https://docs.cloud.google.com/policy-intelligence/docs/role-recommendations-overview) |
| **Policy Analyzer** | "which principals have what access to which Google Cloud resources" | **20 queries per day per org free**. More needs an org-level SCC Premium or Enterprise activation. **Ignores deny policies** and may report access a deny blocks. Ignores PAB, GKE RBAC and storage ACLs. Groups expand to at most 1,000 members. Results are best-effort and may lag. [policy-analyzer-overview](https://docs.cloud.google.com/policy-intelligence/docs/policy-analyzer-overview) |
| **Policy Troubleshooter** | Checks one principal, resource and permission against allow, deny and PAB policies | Returns `Unknown` without group-read or domain-admin rights. Groups, domains and workforce identities can't be entered as the principal. Ignores storage ACLs and VPC-SC. PAB and conditional-binding support is Pre-GA. Pricing not shown on the part of the page I read. [troubleshoot-access](https://docs.cloud.google.com/policy-intelligence/docs/troubleshoot-access) |
| **Policy Simulator (allow)** | Replays the last 90 days of access logs against the current and proposed policy, and diffs the result | **At most 5,000 logs**, and the simulation **fails** above that. Conditional bindings come back as `unknown`. Deny policies are not evaluated here. Supports only some resource types. Pricing not stated. [iam-simulator-overview](https://docs.cloud.google.com/policy-intelligence/docs/iam-simulator-overview) |

## 7. Deny policies and principal access boundaries

- Deny policies [deny-overview](https://docs.cloud.google.com/iam/docs/deny-overview), [IAM quotas](https://docs.cloud.google.com/iam/quotas):
  - They are checked **before** allow policies.
  - They attach to an org, folder or project and are inherited by children.
  - Only permissions on the [deny-supported list](https://docs.cloud.google.com/iam/docs/deny-permissions-support) can be denied. Names use the `SERVICE_FQDN/RESOURCE.ACTION` format, and wildcards work only in supported groups.
  - Denial conditions "only recognize resource tag functions", so there is no `request.time` in a deny rule.
  - Limits: 500 deny policies and 500 deny rules per resource, and 2,500 principals across a resource's deny policies.
  - My count of distinct `*.googleapis.com/...` strings on the deny-support page is about 10,800, using a regex on 23 Oct 2026. Treat this as rough.
- Principal Access Boundary (PAB) policies [principal-access-boundary-policies](https://docs.cloud.google.com/iam/docs/principal-access-boundary-policies):
  - They "can only block or not block access—they can't grant access".
  - They attach to principal sets, not resources. A principal with no PAB policy can access any resource.
  - Limits: 500 rules per policy, 500 resources per policy, 1,000 PAB policies per org, 10 policies per principal set, and 10 logic operators per condition.
  - They block only permissions in the enforcement version.
  - The page does not state a launch stage.

## 8. Existing tools, including natural-language and AI

**Google, built in**
- **Gemini role picker** in the IAM console [role-picker-gemini](https://docs.cloud.google.com/iam/docs/role-picker-gemini):
  - You describe actions and resources, and it suggests **predefined** roles.
  - It can't suggest custom roles, roles for multiple principals in one prompt, or Workspace roles.
  - The Policy Assist API behind it is **Preview**.
  - Google warns it "can generate output that seems plausible but is factually incorrect" and says to check suggestions yourself.
- **Gemini Cloud Assist** acts with the calling user's permissions. It needs roles such as Gemini Cloud Assist User, Cloud Asset Viewer and Recommender Viewer. Starting a chat itself grants `roles/cloudaicompanion.topicAdmin` on the topic. This summary comes from search snippets of [cloud-assist/iam-requirements](https://docs.cloud.google.com/cloud-assist/iam-requirements); I did not fetch the page directly.
- **Privileged Access Manager (PAM)** [pam-overview](https://docs.cloud.google.com/iam/docs/pam-overview):
  - **GA on 16 Sep 2024** per the [IAM release notes](https://docs.cloud.google.com/iam/docs/release-notes).
  - Provides just-in-time temporary grants. Entitlements set who can request, which roles, an optional condition, the maximum duration and whether justification is required.
  - Approvals are optional. Multi-level approval (2 levels, up to 5 approvers per level) is **Preview**.
  - Events go to Cloud Audit Logs.
  - **Does not support the legacy basic roles** (Owner, Editor, Viewer).
  - Some Preview features need SCC Enterprise or Premium.
- **JIT Groups**: Google's open-source app, which supersedes JIT Access. The repo says JIT Access "has largely outlived its purpose" now that PAM exists. [GoogleCloudPlatform/jit-access](https://github.com/GoogleCloudPlatform/jit-access)

**Third-party just-in-time access**
- **ConductorOne (now C1)**: GCP connector; marks projects and roles as eligible for JIT. [c1 docs](https://www.c1.ai/docs/product/how-to/qs-gcp-jit) This summary comes from a search snippet; the page fetch hit a redirect.
- **Opal**: time-bounded access to orgs, folders, projects, buckets, Cloud SQL, GCE and BigQuery. Needs Data Access audit logs to find unused grants. [docs.opal.dev](https://docs.opal.dev/integrations/google-cloud-platform) This summary comes from a search snippet.
- **Apono**: JIT on GCP projects and orgs. "now part of 1Password", per its own page. [apono.io](https://apono.io/integrations/google-cloud-platform-gcp/)
- **Entitle**: acquired by BeyondTrust, press release dated 16 Apr 2024. [beyondtrust.com](https://www.beyondtrust.com/press/beyondtrust-acquires-entitle)
- **Common Fate**: self-hosted authorization engine with a Google Cloud integration. The OSS repo is **archived** under AGPL-3.0. [docs.commonfate.io](https://docs.commonfate.io/introduction), [github](https://github.com/common-fate/common-fate)
- **Indent**: on-demand access requests. I could not verify its current status. [indent.com](https://indent.com/blog/announcing-indent)
- **Sym**: not researched (unverified).

**Cloud Infrastructure Entitlement Management (CIEM) vendors**
- **Wiz CIEM**: effective-permission mapping and generated least-privilege policies. [wiz.io/solutions/ciem](https://www.wiz.io/solutions/ciem)
- **Tenable Cloud Security**: formerly Ermetic. The acquisition closed on 2 Oct 2023. [tenable.com](https://www.tenable.com/press-releases/tenable-completes-acquisition-of-ermetic)
- **Sonrai "Cloud Permissions Firewall"**: launched in Apr 2024 for AWS, with GCP added later. Default-deny guardrails and permission-on-demand. I saw this only through search snippets of Sonrai's [product page](https://sonraisecurity.com/resource/cloud-permissions-firewall/), and the claims are vendor marketing.
- **Not covered:** Mandiant and Sysdig reports were not checked, so nothing here is cited from them.

## Where the gap is

What exists today:
- **Natural-language role suggestions** (the Gemini role picker). These are only predefined roles, they are not verified, and Google itself warns the output can be "plausible but factually incorrect".
- **Workflow tools** (PAM, C1, Opal, Apono and others) that grant a role picked in advance from a catalogue.
- **Analysis tools** (Policy Intelligence, CIEM) that each have blind spots:
  - Policy Analyzer ignores deny policies and has a 20-query daily free cap.
  - Policy Simulator gives up on conditions and has a 5,000-log ceiling.
  - Most Recommender features are SCC-paid.

None of the sources I read describe a single tool that does all of the following:
1. Turns a request in plain English into the **exact binding diff** (member, role, resource, condition, etag).
2. Runs **deterministic checks** on that diff: escalation-capable permissions, basic roles, project-level `actAs`/Token Creator, condition and operator limits, and the 1,500-principal limit.
3. Shows a **dry-run diff** that includes inherited and deny effects.
4. Requires **four-eyes approval**: a second person who is not the requester.
5. Writes a **tamper-evident log** of proposal, check results, approver and the applied etag.
6. Answers "who can X" by **evaluating the real policies**: ancestry, group expansion, deny and PAB, rather than letting a model guess.

This is a gap in what I found, not proof that no such product exists.

## Design implications for the agent (pain → check or feature)

- Basic roles over-used → **hard block** on `roles/owner|editor|viewer`. Flag `roles/admin|writer|reader` and suggest predefined roles instead. PAM can't serve the legacy roles either.
- About 2,422 roles and 10,000+ permissions → the model may only cite roles found in a **local role catalogue snapshot** (iam-dataset or `gcloud iam roles list`). Unknown role IDs fail the check.
- Gemini can be "plausible but factually incorrect" → the model proposes, the code verifies. Every proposed permission set is re-derived from the catalogue, never taken from model text.
- Condition limits → the linter checks:
  - at most 12 logic operators;
  - at most 20 same-role, same-member conditional variants;
  - a warning above 100 conditional bindings;
  - policy version 3;
  - no conditions on legacy roles or `allUsers`;
  - the resource type accepts conditions, and buckets have uniform bucket-level access.
- Time-bound access → default every human grant to `request.time < timestamp(...)` with a maximum TTL. Prefer PAM entitlements where they are available. Schedule cleanup of expired bindings. This assumes expired bindings stay in the policy and count toward the limits; I have not verified that against a doc page.
- 1,500-principal and 250-group caps → **pre-apply capacity check** on the merged policy.
- Inheritance is additive → the dry-run computes **effective access** across the org, folder and project chain. Warn when a grant is redundant (already inherited) or when a revoke is ineffective (still granted higher up).
- Privilege escalation (Rhino list) → **escalation denylist**: `setIamPolicy`, `actAs`, `getAccessToken`, `signBlob`, `signJwt`, `implicitDelegation`, `serviceAccountKeys.create`, `roles.update`, and `deploymentmanager.deployments.create`. A role containing any of these needs a second approver and a resource-level (not project-level) scope.
- SA keys and old keys → block roles that include `serviceAccountKeys.create`. Report whether `iam.managed.disableServiceAccountKeyCreation` is enforced, especially for orgs created before 3 May 2024.
- Default compute SA with Editor → a read-only "posture" query that lists default SAs holding Editor, and offers proposals to replace it.
- Deny and PAB are invisible to Policy Analyzer → the "who can X" answer must include deny and PAB evaluation, or say plainly that it did not.
- Policy Simulator gives `unknown` on conditions and fails above 5,000 logs → our own deterministic diff is the main check. The Simulator is an optional extra.
- Changes take about 2 to 7 minutes to propagate, and group changes take longer → after apply, run a **verify-after-propagation** step and don't report success at write time. Use the etag to detect concurrent edits.
- Non-repudiation → **four-eyes approval** (approver ≠ requester), plus a hash-chained log of the request, the model proposal, the check outputs, the approval and the applied policy etag.

## Example requests an admin would type

1. "Give alice@example.com read access to BigQuery dataset `sales_eu` in project `analytics-prod` until Friday 18:00 IST."
2. "Who can impersonate `deploy-bot@ci-prod.iam.gserviceaccount.com`?"
3. "Who can delete objects in bucket `gs://customer-exports`, including through folder-level grants?"
4. "Remove Editor from the default compute service account in every project under folder `payments`, and tell me what breaks."
5. "Let the on-call group restart Cloud Run services in `api-prod` for 4 hours."
6. "Why does bob@example.com get permission denied on `secretmanager.versions.access` in `core-prod`?"
7. "Replace bob's Owner on `sandbox-42` with the smallest set of roles that covers what he actually used."
8. "List service accounts with user-managed keys older than one year."
9. "Make sure nobody outside `example.com` can be granted roles in folder `prod`."
10. "Let the data-eng group read BigQuery tables in `analytics-prod`, but only for dataset `sales_eu`."
