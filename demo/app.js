/* Shio IAM demo. A frontend mock: it replays outcomes recorded from iam.shio (data.js) and keeps approvals, policy
   changes and a hash-chained ledger in this browser tab. No backend, no model calls. */
(function () {
  "use strict";
  const D = window.SHIO_IAM;
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const ROLE_GROUP = { iam_approver: "iam-approvers", security_admin: "security-admins" };
  const ROLE_LABEL = { iam_approver: "IAM approver", security_admin: "Security admin" };

  const S = {
    actor: D.requester, tab: "ask", reader: "honest", policies: clone(D.policies),
    changes: [], ledger: [], filter: "all", selected: null, tour: -1,
  };

  // -- helpers ------------------------------------------------------------------------------------------------
  const person = (email) => D.directory.find((p) => p.email.toLowerCase() === String(email).toLowerCase());
  const nameOf = (email) => (person(email) || {}).name || email;
  const memberEmail = (m) => (m.includes(":") ? m.split(":").slice(1).join(":") : m);
  const res = (name) => D.resources.find((r) => r.name === name);
  const resByDisplay = (d) => D.resources.find((r) => r.display === d);
  const ancestors = (name) => { const out = []; let r = res(name); while (r) { out.push(r); r = r.parent ? res(r.parent) : null; } return out; };
  const groupsOf = (email) => D.directory.filter((g) => g.kind === "group" && (g.members || []).includes(email)).map((g) => g.email);
  const members = (group) => ((D.directory.find((g) => g.email.split("@")[0] === group) || {}).members || []);
  const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9@.]+/g, " ").trim();
  const keyOf = (s) => String(s).trim().toLowerCase().replace(/\s+/g, " ").replace(/[?.!]+$/, "");
  const fmtDate = (iso) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
  const expiresOf = (cond) => { const m = /timestamp\("([^"]+)"\)/.exec((cond || {}).expression || ""); return m ? m[1] : null; };
  const NOW = new Date(D.now);

  function toast(t) {
    const el = $("#toast"); el.textContent = t; el.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => (el.hidden = true), 2600);
  }

  async function sha256(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function record(kind, what, who, body) {
    const prev = S.ledger.length ? S.ledger[S.ledger.length - 1].hash : "0".repeat(64);
    const entry = { seq: S.ledger.length, kind, what, who, time: new Date().toISOString(), prev, body };
    entry.hash = await sha256(JSON.stringify({ seq: entry.seq, kind, what, who, time: entry.time, prev, body }));
    S.ledger.push(entry);
    renderLedger();
    return entry;
  }

  // -- the recorded runs ----------------------------------------------------------------------------------------
  function runsFor(actor) {
    const base = D.runs[actor] || D.runs[D.requester];
    if (S.reader === "fooled") return { ...base, ...(D.fooled[actor] || D.fooled[D.requester]) };
    return base;
  }

  function findRun(text) {
    const runs = runsFor(S.actor);
    const k = keyOf(text);
    for (const req of Object.keys(runs)) if (keyOf(req) === k) return { req, run: runs[req], exact: true };
    const words = new Set(norm(text).split(" "));
    let best = null, score = 0;
    for (const req of Object.keys(runs)) {
      const w = new Set(norm(req).split(" "));
      const inter = [...words].filter((x) => w.has(x)).length;
      const j = inter / new Set([...words, ...w]).size;
      if (j > score) { score = j; best = req; }
    }
    return score >= 0.8 ? { req: best, run: runs[best], exact: false } : null;
  }

  // -- tabs ----------------------------------------------------------------------------------------------------
  function show(tab) {
    S.tab = tab;
    $$(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
    $$(".view").forEach((v) => (v.hidden = v.dataset.view !== tab));
    if (tab === "access") renderAccess();
    if (tab === "approvals") renderApprovals();
    if (tab === "ledger") renderLedger();
    window.scrollTo({ top: 0 });
  }

  // -- chat ------------------------------------------------------------------------------------------------------
  const SUGGEST = [
    "who can delete buckets in prod?",
    "give Priya read access to the billing dataset for two weeks",
    "remove everyone's Owner role except the break-glass account",
    "give Priya Shah read access to product_events for 30 days",
    "what can Lee Wong access?",
    "make the nw-web-logs bucket readable by everyone",
  ];

  function renderSuggest() {
    $("#suggest").innerHTML = SUGGEST.map((s) => `<button class="chip" data-ask="${esc(s)}">${esc(s)}</button>`).join("");
  }

  function hello() {
    $("#chat").innerHTML = `<div class="empty-hello"><p class="eyebrow">Google Cloud IAM</p><h1>What do you need to know or change?</h1>
      <p class="muted">Changes are checked, shown as an exact diff and wait for a second person to approve.</p></div>`;
  }

  function add(html, cls = "") {
    const hi = $(".empty-hello"); if (hi) hi.remove();
    const el = document.createElement("div"); el.className = "msg " + cls; el.innerHTML = html;
    $("#chat").appendChild(el); el.scrollIntoView({ behavior: "smooth", block: "end" });
    return el;
  }

  async function ask(text) {
    text = text.trim(); if (!text) return;
    add(esc(text), "me");
    const found = findRun(text);
    const steps = add(`<div class="thinking"><span>Reading the request</span></div>`);
    await wait(250);
    if (!found) {
      steps.innerHTML = `<div class="card"><p class="eyebrow">Not a recorded request</p>
        <p>This demo replays recorded runs of the agent, and this request isn't one of them. Try one of these:</p>
        <div class="suggest">${SUGGEST.map((s) => `<button class="chip" data-ask="${esc(s)}">${esc(s)}</button>`).join("")}</div></div>`;
      return;
    }
    const { run } = found;
    const o = run.outcome;
    steps.innerHTML = `<div class="thinking"><span>Read by ${esc(run.model.name)}: ${esc(o.action === "ANSWER" ? "a question" : run.reading.intent)}</span>
      <span>Looked up the directory, resources and policies</span><span>${run.checks.filter((c) => !c.skipped).length} checks ran</span></div>`;
    await wait(250);
    const entry = await record(o.action === "APPLY" ? "proposal" : o.action.toLowerCase(), found.req, S.actor, { outcome: o.action, sha256: run.record_sha256 });
    if (o.action === "ANSWER") add(answerCard(o, run));
    else if (o.action === "CLARIFY") add(clarifyCard(o));
    else if (o.action === "REFUSE") add(refuseCard(o, run));
    else if (o.action === "APPLY") {
      const ch = { id: entry.hash.slice(0, 8), request: found.req, requester: S.actor, run, status: "PENDING", signoffs: [], applied: null, created: new Date() };
      S.changes.unshift(ch);
      const el = add(""); el.dataset.change = ch.id; renderChangeCard(ch);
      renderBadge();
    }
    if (!found.exact) add(`<p class="note">Matched to the recorded request “${esc(found.req)}”.</p>`);
  }

  const wait = (ms) => new Promise((r) => setTimeout(r, $("html").dataset.motion === "off" ? 0 : ms));

  function answerCard(o) {
    const a = o.answer;
    const by = {};
    for (const x of a.rows) if (!x.denied_by) (by[x.principal] = by[x.principal] || []).push(x);
    const lines = o.text.split("\n");
    const people = a.principal ? "" : `<div class="who">${a.principals.map((p) => `<button data-person="${esc(p)}">${esc(nameOf(p))}
        <small>${esc(by[p].map((x) => `${x.role.replace("roles/", "")} on ${x.bound_on}${x.via ? " via " + memberEmail(x.via).split("@")[0] : ""}`).filter((v, i, s) => s.indexOf(v) === i).join(" · "))}</small></button>`).join("")}</div>`;
    const list = a.principal ? `<ul class="checks">${a.rows.map((x) => `<li><span class="tick">✓</span><span>${esc(x.role)} on
        <button class="link" data-res="${esc(x.bound_on)}">${esc(x.bound_on)}</button>${x.via ? ` <span class="muted">through ${esc(memberEmail(x.via))}</span>` : ""}</span></li>`).join("")}</ul>` : "";
    const blocked = a.blocked_by_deny.length ? `<p class="note">Allowed by an allow policy but blocked by a deny policy: ${a.blocked_by_deny.map((p) => `<button class="link" data-person="${esc(p)}">${esc(nameOf(p))}</button>`).join(", ")}</p>` : "";
    const risks = a.risks.length ? `<ul class="checks">${[...new Set(a.risks)].map((r) => `<li><span class="tick warn">!</span><span>${esc(r)}</span></li>`).join("")}</ul>` : "";
    return `<div class="card"><p class="eyebrow">Answer · from the policies${a.permission ? " · " + esc(a.permission) : ""}</p>
      <h3>${esc(lines[0])}</h3>${people}${list}${blocked}${risks}
      <div class="actions"><button class="pill ghost" data-res="${esc(a.scope)}">Open ${esc(a.scope)}</button>
      <span class="note">Every name and count comes from the bindings, with inheritance and deny policies applied.</span></div></div>`;
  }

  function clarifyCard(o) {
    const first = o.question.split(" ")[0];
    return `<div class="card"><p class="eyebrow">Which one?</p><h3>${esc(o.question)}</h3>
      <div class="actions">${o.options.map((n) => `<button class="pill ghost" data-ask="${esc(o.request.replace(first, n))}">${esc(n)}</button>`).join("")}</div>
      <p class="note">Nothing is proposed until the request names one person.</p></div>`;
  }

  function checkList(run, onlyFailed) {
    return run.checks.filter((c) => !c.skipped && (onlyFailed ? !c.passed : true)).map((c) =>
      `<li><span class="tick ${c.passed ? "" : "x"}">${c.passed ? "✓" : "×"}</span><span><b class="mono">${esc(c.name)}</b>${c.detail ? " · " + esc(c.detail) : ""}</span></li>`).join("");
  }

  function refuseCard(o, run) {
    const passed = run.checks.filter((c) => c.passed && !c.skipped).length;
    return `<div class="card"><p class="eyebrow">Refused · nothing will change</p><h3>${esc(o.why.length === 1 ? o.why[0] : o.why.length + " checks failed")}</h3>
      <ul class="checks">${checkList(run, true)}</ul>
      <div class="actions"><button class="link" data-reading="${esc(o.request)}">What the model read</button><span class="note">${passed} other checks passed</span></div></div>`;
  }

  function summary(o) {
    const p = o.proposal;
    if (o.intent === "grant") {
      const d = o.diff[0]; const cond = d.changes[0].condition;
      return `Grant ${p.role.replace("roles/", "")} to ${p.principals.map(nameOf).join(", ")} on ${d.display}` + (cond ? ` until ${fmtDate(expiresOf(cond))}` : "");
    }
    const n = o.diff.reduce((s, d) => s + d.changes.length, 0);
    return `Remove ${p.role.replace("roles/", "")} from ${n} binding${n > 1 ? "s" : ""} on ${o.diff.length} resource${o.diff.length > 1 ? "s" : ""}`;
  }

  function needed(ch) { return ch.run.outcome.pending.roles.filter((r) => !ch.signoffs.some((s) => s.role === r && s.decision === "approved")); }

  function canApprove(ch, who) {
    if (ch.status !== "PENDING") return { ok: false, why: `This change is ${ch.status.toLowerCase()}.` };
    if (who.toLowerCase() === ch.requester.toLowerCase()) return { ok: false, why: `${nameOf(who)} asked for this change, so someone else has to approve it.` };
    if (ch.signoffs.some((s) => s.by === who)) return { ok: false, why: `${nameOf(who)} has already approved this change.` };
    const role = needed(ch).find((r) => members(ROLE_GROUP[r]).includes(who));
    if (!role) return { ok: false, why: `${nameOf(who)} isn't in ${needed(ch).map((r) => ROLE_GROUP[r]).join(" or ")}.` };
    return { ok: true, role };
  }

  function stepper(ch) {
    const roles = ch.run.outcome.pending.roles;
    const done = (r) => ch.signoffs.find((s) => s.role === r);
    const s = [`<div class="s done"><span class="eyebrow">Requested</span><b>${esc(nameOf(ch.requester))}</b>${ch.created.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</div>`];
    let current = false;
    for (const r of roles) {
      const d = done(r);
      const cls = d ? "done" : !current ? (current = true, "now") : "";
      s.push(`<div class="s ${cls}"><span class="eyebrow">${ROLE_LABEL[r]}</span><b>${d ? esc(nameOf(d.by)) + (d.decision === "rejected" ? " rejected" : " approved") : "Waiting"}</b>${esc(ROLE_GROUP[r])}</div>`);
    }
    const ap = ch.status === "APPLIED" ? "done" : ch.status === "PENDING" && !needed(ch).length ? "now" : "";
    s.push(`<div class="s ${ap}"><span class="eyebrow">Apply</span><b>${ch.status === "APPLIED" ? "Applied" : ch.status === "NOT APPLIED" ? "Not applied" : ch.status === "REJECTED" ? "Stopped" : "After approval"}</b>${ch.applied ? esc(ch.applied) : "setIamPolicy, with the approved etag"}</div>`);
    return `<div class="stepper">${s.join("")}</div>`;
  }

  function diffHtml(o) {
    return `<div class="diff">${o.diff.map((d) => `<div class="res">${esc(d.display)} · ${esc(d.type)} · etag ${esc(d.etag)}</div>${d.lines.map((l) =>
      `<div class="l ${l[0] === "+" ? "add" : "rem"}">${esc(l)}</div>`).join("")}`).join("")}</div>`;
  }

  function changeBody(ch, inSheet) {
    const o = ch.run.outcome;
    const warn = [...o.breaking.map((b) => "May break: " + b), ...(o.escalation.length ? ["Widens power: " + o.escalation.join(", ")] : []), ...o.denied.map((d) => "No effect: " + d)];
    const passed = o.passed.map((n) => `<span>${esc(n.replace(/_/g, " "))}</span>`).join("");
    const me = canApprove(ch, S.actor);
    const chip = { PENDING: "", APPLIED: "pos", REJECTED: "neg", "NOT APPLIED": "neg" }[ch.status];
    return `<p class="eyebrow">Proposed change · dry run <span class="tag ${chip}">${esc(ch.status === "PENDING" ? "Waiting for approval" : ch.status)}</span></p>
      <h3>${esc(summary(o))}</h3>${diffHtml(o)}
      ${warn.length ? `<ul class="checks">${warn.map((w) => `<li><span class="tick warn">!</span><span>${esc(w)}</span></li>`).join("")}</ul>` : ""}
      <p class="eyebrow" style="margin-top:12px">${o.passed.length} checks passed</p><div class="steps">${passed}</div>
      ${stepper(ch)}
      <div class="actions">${ch.status === "PENDING" ? `<button class="pill" data-approve="${ch.id}" ${me.ok ? "" : "disabled"}>Approve as ${esc(nameOf(S.actor))}</button>
        <button class="pill danger" data-reject="${ch.id}" ${me.ok ? "" : "disabled"}>Reject</button>` : ""}
        ${inSheet ? `<button class="link" data-reading="${esc(ch.request)}">What the model read</button>` : `<button class="link" data-open-change="${ch.id}">Details</button>`}
        ${ch.status === "PENDING" && !me.ok ? `<span class="note">${esc(me.why)}${needed(ch).length ? " Switch “Acting as” to an approver." : ""}</span>` : ""}</div>`;
  }

  function renderChangeCard(ch) {
    $$(`[data-change="${ch.id}"]`).forEach((el) => (el.innerHTML = `<div class="card">${changeBody(ch, false)}</div>`));
    if (!$("#sheet").hidden && $("#sheet").dataset.change === ch.id) openChange(ch.id);
  }

  async function decide(id, reject) {
    const ch = S.changes.find((c) => c.id === id);
    const me = canApprove(ch, S.actor);
    if (!me.ok) { toast(me.why); return; }
    ch.signoffs.push({ by: S.actor, role: me.role, decision: reject ? "rejected" : "approved", time: new Date() });
    await record(reject ? "rejection" : "approval", ch.request, S.actor, { change: ch.id, role: me.role });
    if (reject) { ch.status = "REJECTED"; toast("Rejected"); }
    else if (!needed(ch).length) await applyChange(ch);
    else toast(`Approved as ${ROLE_LABEL[me.role]}. Waiting for ${needed(ch).map((r) => ROLE_GROUP[r]).join(", ")}`);
    renderChangeCard(ch); renderBadge(); if (S.tab === "approvals") renderApprovals();
  }

  async function applyChange(ch) {
    for (const d of ch.run.outcome.diff) {
      if (JSON.stringify(S.policies[d.resource]) !== JSON.stringify(d.before)) {
        ch.status = "NOT APPLIED"; ch.applied = `the policy on ${d.display} changed since this was proposed; ask again`;
        await record("apply", ch.request, "shio-iam", { result: "NOT APPLIED" });
        toast("Not applied: the policy changed since it was proposed"); return;
      }
    }
    for (const d of ch.run.outcome.diff) S.policies[d.resource] = clone(d.after);
    ch.status = "APPLIED"; ch.applied = `${ch.run.outcome.diff.length} polic${ch.run.outcome.diff.length > 1 ? "ies" : "y"} written`;
    await record("apply", ch.request, "shio-iam", { result: "APPLIED", resources: ch.run.outcome.diff.map((d) => d.resource) });
    toast("Approved and applied");
  }

  function renderBadge() {
    const n = S.changes.filter((c) => c.status === "PENDING").length;
    const b = $("#pendingCount"); b.hidden = !n; b.textContent = n;
  }

  // -- access ----------------------------------------------------------------------------------------------------
  const KIND = { organization: "Org", folder: "Folder", project: "Project", dataset: "Dataset", bucket: "Bucket", service_account: "SA" };

  function risky(name) {
    return (S.policies[name] || []).some((b) => /roles\/(owner|editor|admin|writer)$/.test(b.role) && name !== D.resources[0].name || b.members.some((m) => m === "allUsers" || m === "allAuthenticatedUsers"));
  }

  function renderAccess() {
    if (!S.selected) S.selected = D.resources.find((r) => r.type === "dataset").name;
    const kids = (p) => D.resources.filter((r) => r.parent === p);
    const walk = (r, depth) => [`<button data-select="${esc(r.name)}" class="${S.selected === r.name ? "on" : ""}" style="padding-left:${8 + depth * 14}px">
      <span class="k">${KIND[r.type]}</span><span>${esc(r.display)}</span>${risky(r.name) ? '<span class="flag" title="Has a risky binding"></span>' : ""}</button>`,
      ...kids(r.name).map((k) => walk(k, depth + 1))].join("");
    $("#tree").innerHTML = walk(D.resources[0], 0);
    renderResource(S.selected);
  }

  const INSTRUCTION = /(assistant|ignore (all|previous)|you must|whenever you|grant .* roles\/|approved by)/i;

  function renderResource(name) {
    const r = res(name);
    const path = ancestors(name).reverse().map((a) => a.display).join(" / ");
    const rows = [];
    for (const a of ancestors(name)) for (const b of S.policies[a.name] || []) rows.push({ ...b, from: a });
    const deny = ancestors(name).flatMap((a) => (D.deny[a.name] || []).map((p) => ({ ...p, on: a.display })));
    const flags = (b) => {
      const t = [];
      if (/roles\/(owner|editor|viewer|admin|writer|reader)$/.test(b.role)) t.push('<span class="tag warn">Basic role</span>');
      if (b.members.some((m) => m === "allUsers" || m === "allAuthenticatedUsers")) t.push('<span class="tag neg">Public</span>');
      const exp = expiresOf(b.condition);
      if (exp) t.push(new Date(exp) < NOW ? '<span class="tag">Expired</span>' : `<span class="tag pos">Until ${fmtDate(exp)}</span>`);
      if (b.members.some((m) => (person(memberEmail(m)) || {}).keys)) t.push('<span class="tag warn">SA with keys</span>');
      if (/TokenCreator|serviceAccountUser|IamAdmin|dataOwner|storage\.admin/.test(b.role)) t.push('<span class="tag warn">Can widen access</span>');
      return t.join(" ");
    };
    $("#resDetail").innerHTML = `<p class="eyebrow">${KIND[r.type]}</p><h2>${esc(r.display)}</h2><p class="muted mono">${esc(path)}</p>
      ${r.description ? `<div class="notes"><p class="eyebrow">Description${INSTRUCTION.test(r.description) ? ' <span class="tag warn">Contains instructions</span>' : ""}</p>${esc(r.description)}
        <p class="note">Written by people who can edit this ${esc(r.type)}. The agent reads it as data, never as instructions.</p></div>` : ""}
      ${r.labels ? `<p>${Object.entries(r.labels).map(([k, v]) => `<span class="tag">${esc(k)}: ${esc(v)}</span>`).join(" ")}</p>` : ""}
      ${r.type === "bucket" ? `<p class="note">${r.uniform_access ? "Uniform bucket-level access: on" : "Uniform bucket-level access: off (no time-bound grants)"}</p>` : ""}
      <table class="table resp"><thead><tr><th>Role</th><th>Members</th><th>Where</th><th></th></tr></thead><tbody>
      ${rows.map((b) => `<tr><td class="mono">${esc(b.role)}</td><td>${b.members.map((m) => `<button class="member" data-person="${esc(memberEmail(m))}">${esc(m.startsWith("user:") || m.startsWith("serviceAccount:") || m.startsWith("group:") ? nameOf(memberEmail(m)) : m)}</button>`).join("")}</td>
        <td>${b.from.name === name ? "Here" : `<button class="link" data-select="${esc(b.from.name)}">Inherited from ${esc(b.from.display)}</button>`}</td><td>${flags(b)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">No bindings here or above.</td></tr>`}
      </tbody></table>
      ${deny.length ? `<div class="notes"><p class="eyebrow">Deny policies</p>${deny.map((p) => `${esc(p.displayName)} <span class="muted">(on ${esc(p.on)}): denies ${esc(p.rules[0].denyRule.deniedPermissions.join(", "))} to everyone except ${esc(p.rules[0].denyRule.exceptionPrincipals.map((x) => x.split("/").pop()).join(", "))}</span>`).join("<br>")}</div>` : ""}
      <div class="actions"><button class="pill ghost" data-prefill="give Priya Raman read access to the ${esc(r.display)} ${esc(r.type === "dataset" ? "dataset" : r.type)} for two weeks">Request access</button>
      <button class="pill ghost" data-history="${esc(name)}">Changes to this ${esc(r.type)}</button></div>`;
  }

  function openPerson(email) {
    const p = person(email) || { email, name: email, kind: email.startsWith("all") ? "public" : "outside the directory" };
    const mine = new Set([email, ...groupsOf(email)]);
    const rows = [];
    for (const r of D.resources) for (const b of S.policies[r.name] || []) for (const m of b.members) {
      const e = memberEmail(m);
      if (mine.has(e) || (m.startsWith("domain:") && email.endsWith("@" + e))) {
        const exp = expiresOf(b.condition);
        if (exp && new Date(exp) < NOW) continue;
        rows.push({ role: b.role, on: r, via: e !== email ? m : null, exp });
      }
    }
    sheet(p.name, `<p class="eyebrow">${esc(p.kind)}${p.title ? " · " + esc(p.title) : ""}</p><p class="mono">${esc(email)}</p>
      ${groupsOf(email).length ? `<p>Member of ${groupsOf(email).map((g) => `<span class="tag">${esc(g.split("@")[0])}</span>`).join(" ")}</p>` : ""}
      ${p.members ? `<p>Members: ${p.members.map((m) => `<button class="member" data-person="${esc(m)}">${esc(nameOf(m))}</button>`).join("")}</p>` : ""}
      ${p.keys ? `<p class="note">${p.keys} user-managed key(s). Anyone holding a key has this account's access.</p>` : ""}
      <p class="eyebrow" style="margin-top:16px">Access (${rows.length} binding${rows.length === 1 ? "" : "s"})</p>
      <table class="table"><tbody>${rows.map((x) => `<tr class="click" data-select="${esc(x.on.name)}"><td class="mono">${esc(x.role)}</td><td>${esc(x.on.display)}${x.via ? ` <span class="muted">via ${esc(memberEmail(x.via).split("@")[0])}</span>` : ""}${x.exp ? ` <span class="tag pos">Until ${fmtDate(x.exp)}</span>` : ""}</td></tr>`).join("") || '<tr><td class="empty">No access.</td></tr>'}</tbody></table>`);
  }

  // -- approvals, ledger -----------------------------------------------------------------------------------------
  function renderApprovals() {
    $$(".filters .chip").forEach((c) => c.classList.toggle("on", c.dataset.filter === S.filter));
    const list = S.changes.filter((c) => S.filter === "all" || c.status === S.filter || (S.filter === "REJECTED" && c.status === "NOT APPLIED"));
    $("#approvalList").innerHTML = list.map((c) => `<div class="row" data-open-change="${c.id}" tabindex="0" role="button">
      <div class="t">${esc(summary(c.run.outcome))}<small>${esc(nameOf(c.requester))}: “${esc(c.request)}”</small></div>
      <span class="tag ${c.status === "APPLIED" ? "pos" : c.status === "PENDING" ? "" : "neg"}">${esc(c.status === "PENDING" ? "Needs " + needed(c).map((r) => ROLE_GROUP[r]).join(", ") : c.status)}</span></div>`).join("")
      || `<p class="empty">No changes yet. Ask for one in Ask.</p>${S.filter === "all" ? '<button class="pill ghost" data-tab-go="ask">Go to Ask</button>' : ""}`;
  }

  function openChange(id) {
    const ch = S.changes.find((c) => c.id === id);
    sheet("Change " + ch.id, changeBody(ch, true) + `<p class="eyebrow" style="margin-top:16px">Record</p><p class="mono note">sha256 ${esc(ch.run.record_sha256)}</p>`);
    $("#sheet").dataset.change = id;
  }

  function renderLedger() {
    const tb = $("#ledgerTable tbody");
    tb.innerHTML = S.ledger.slice().reverse().map((e) => `<tr class="click" data-entry="${e.seq}"><td>${e.seq}</td><td>${esc(e.kind)}</td><td>${esc(e.what)}</td><td>${esc(nameOf(e.who))}</td><td class="mono">${e.hash.slice(0, 12)}…</td></tr>`).join("")
      || '<tr><td colspan="5" class="empty">Every answer, proposal, approval and apply becomes an entry here.</td></tr>';
    $("#ledgerSummary").textContent = `${S.ledger.length} entr${S.ledger.length === 1 ? "y" : "ies"} this session, each holding the hash of the one before.`;
  }

  async function verify() {
    let prev = "0".repeat(64);
    for (const e of S.ledger) {
      const h = await sha256(JSON.stringify({ seq: e.seq, kind: e.kind, what: e.what, who: e.who, time: e.time, prev: e.prev, body: e.body }));
      if (e.prev !== prev || h !== e.hash) { toast(`Chain broken at entry ${e.seq}`); return; }
      prev = e.hash;
    }
    toast(S.ledger.length ? `Chain verified: ${S.ledger.length} entries, head ${prev.slice(0, 10)}…` : "Nothing recorded yet");
  }

  // -- sheet, settings, about ------------------------------------------------------------------------------------
  let lastFocus = null;
  function sheet(title, html) {
    lastFocus = lastFocus || document.activeElement;
    $("#sheetTitle").textContent = title; $("#sheetBody").innerHTML = html; delete $("#sheet").dataset.change;
    $("#sheet").hidden = false; $("#scrim").hidden = false; $("#sheetClose").focus();
  }
  function closeSheet() { $("#sheet").hidden = true; $("#scrim").hidden = true; if (lastFocus) lastFocus.focus(); lastFocus = null; }

  function settings() {
    const h = $("html");
    sheet("Settings", `<div class="set">
      <label>Theme<select data-set="theme"><option value="">System</option><option value="light">Light</option><option value="dark">Dark</option></select></label>
      <label>Text size<select data-set="size"><option value="">Standard</option><option value="l">Large</option><option value="xl">Larger</option></select></label>
      <label>Motion<select data-set="motion"><option value="">On</option><option value="off">Reduced</option></select></label>
      <label>Reader<select data-set="reader"><option value="honest">Recorded reader</option><option value="fooled">Recorded reader fooled by the product_events description</option></select></label>
      <p class="note">The second reader shows what happens when a model follows the instruction planted in a dataset description. The checks still decide.</p>
      <button class="pill ghost" data-reset>Reset the sample org</button></div>`);
    $$("[data-set]").forEach((s) => (s.value = s.dataset.set === "reader" ? S.reader : h.dataset[s.dataset.set] || ""));
  }

  function setPref(k, v) {
    if (k === "reader") { S.reader = v; toast(v === "fooled" ? "Reader: fooled by the planted description" : "Reader: recorded reader"); return; }
    if (v) $("html").dataset[k] = v; else delete $("html").dataset[k];
    try { localStorage.setItem("shio-iam-" + k, v); } catch (e) { /* storage may be blocked */ }
  }

  function about() {
    sheet("How it works", `<p>You ask in plain English. A model reads the request into a structured proposal: who, what access, on what, for how long. It never writes anything.</p>
      <p>Code then decides, from the org's own data: the person is in the directory and named in the request, the role is the narrowest predefined role (never Owner or Editor), nothing public, access to prod expires, no one grants themselves access, and roles that can widen access need a security admin as well.</p>
      <p>Questions are answered from the bindings, with inheritance, groups and deny policies, so every name and count can be traced.</p>
      <p>A change is shown as an exact diff. It is written only after someone other than the requester approves, and only if the policy hasn't changed since. Every step is an entry in a hash-chained ledger.</p>
      <p class="note">The agent is a program in Shio (iam.shio). This page replays its recorded runs on a fictional org; the open-source project runs the same program against the sample org or a real one through gcloud.</p>`);
  }

  // -- guided demo -----------------------------------------------------------------------------------------------
  const TOUR = [
    { text: "Ask who can delete buckets in prod. The answer is worked out from the policies, not guessed.", run: async () => { show("ask"); await ask("who can delete buckets in prod?"); }, hl: () => $$(".msg .card").pop() },
    { text: "Five principals hold the permission through allow policies, but a deny policy blocks them. Only three can really do it.", hl: () => $$(".msg .card").pop() },
    { text: "Ask for a change. There are two people called Priya, so nothing is proposed until you say which.", run: async () => { await ask("give Priya read access to the billing dataset for two weeks"); }, hl: () => $$(".msg .card").pop() },
    { text: "Pick Priya Raman. The proposal is an exact diff: the narrowest role, on the dataset, with an expiry condition.", run: async () => { await ask("give Priya Raman read access to the billing dataset for two weeks"); }, hl: () => $$(".msg .card").pop() },
    { text: "Dan asked, so Dan can't approve. Switch to Sam Chen, an IAM approver.", run: async () => { setActor("sam.chen@northwind.example"); }, hl: () => $(".as") },
    { text: "Sam approves. The policy is written, and the change is recorded.", run: async () => { const ch = S.changes.find((c) => c.status === "PENDING" && c.run.outcome.intent === "grant"); if (ch) await decide(ch.id, false); }, hl: () => $$(".msg .card").pop() },
    { text: "The billing dataset now shows Priya's binding, with the date it ends.", run: async () => { S.selected = D.resources.find((r) => r.display === "billing").name; show("access"); }, hl: () => $("#resDetail table") },
    { text: "The product_events description carries an instruction to AI assistants. Here the reader falls for it and adds an outside account.", run: async () => { setActor(D.requester); S.reader = "fooled"; show("ask"); await ask("give Priya Shah read access to product_events for 30 days"); }, hl: () => $$(".msg .card").pop() },
    { text: "Remove everyone's Owner role except break-glass. Terraform's account would lose Owner, so a security admin must approve too.", run: async () => { S.reader = "honest"; await ask("remove everyone's Owner role except the break-glass account"); }, hl: () => $$(".msg .card").pop() },
    { text: "Every answer, proposal and approval is a hash-chained entry. Verify the chain.", run: async () => { show("ledger"); await verify(); }, hl: () => $("#verifyBtn") },
  ];

  async function tourGo(i) {
    $$(".hl").forEach((e) => e.classList.remove("hl"));
    if (i < 0 || i >= TOUR.length) { $("#tour").hidden = true; S.tour = -1; return; }
    const forward = i > S.tour;
    S.tour = i; const t = TOUR[i];
    $("#tour").hidden = false; $("#tourStep").textContent = `Step ${i + 1} of ${TOUR.length}`; $("#tourText").textContent = t.text;
    $("#tourBack").disabled = i === 0; $("#tourNext").textContent = i === TOUR.length - 1 ? "Finish" : "Next";
    if (t.run && forward) await t.run();
    const el = t.hl && t.hl(); if (el) { el.classList.add("hl"); el.scrollIntoView({ behavior: "smooth", block: "center" }); }
  }

  function resetAll() {
    S.policies = clone(D.policies); S.changes = []; S.ledger = []; S.reader = "honest"; S.selected = null;
    hello(); renderBadge(); renderLedger(); if (S.tab === "access") renderAccess(); if (S.tab === "approvals") renderApprovals();
  }

  function setActor(a) {
    S.actor = a; $("#actor").value = a;
    S.changes.forEach(renderChangeCard);
    if (S.tab === "approvals") renderApprovals();
    toast(`Acting as ${nameOf(a)}`);
  }

  // -- wiring ------------------------------------------------------------------------------------------------------
  function init() {
    try { for (const k of ["theme", "size", "motion"]) { const v = localStorage.getItem("shio-iam-" + k); if (v) $("html").dataset[k] = v; } } catch (e) { /* ignore */ }
    $("#actor").innerHTML = D.personas.map((p) => `<option value="${esc(p)}">${esc(nameOf(p))} · ${esc((person(p) || {}).title || "")}</option>`).join("");
    $("#actor").value = S.actor;
    renderSuggest(); hello(); renderLedger();

    $("#composer").addEventListener("submit", (e) => { e.preventDefault(); const q = $("#q").value; $("#q").value = ""; ask(q); });
    $("#actor").addEventListener("change", (e) => setActor(e.target.value));
    $$(".tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));
    $("#settingsBtn").addEventListener("click", settings);
    $("#aboutBtn").addEventListener("click", about);
    $("#verifyBtn").addEventListener("click", verify);
    $("#tourBtn").addEventListener("click", () => { resetAll(); S.tour = -1; tourGo(0); });
    $("#tourNext").addEventListener("click", () => tourGo(S.tour + 1));
    $("#tourBack").addEventListener("click", () => tourGo(S.tour - 1));
    $("#tourExit").addEventListener("click", () => tourGo(-1));
    $("#sheetClose").addEventListener("click", closeSheet);
    $("#scrim").addEventListener("click", closeSheet);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#sheet").hidden) closeSheet(); });
    document.addEventListener("change", (e) => { const s = e.target.closest("[data-set]"); if (s) setPref(s.dataset.set, s.value); });

    document.addEventListener("click", (e) => {
      const t = e.target.closest("[data-ask],[data-person],[data-res],[data-select],[data-approve],[data-reject],[data-open-change],[data-reading],[data-filter],[data-entry],[data-prefill],[data-history],[data-reset],[data-tab-go]");
      if (!t) return;
      const d = t.dataset;
      if (d.ask) { closeSheet(); show("ask"); ask(d.ask); }
      else if (d.person) openPerson(d.person);
      else if (d.res) { const r = resByDisplay(d.res); if (r) { closeSheet(); S.selected = r.name; show("access"); } }
      else if (d.select) { closeSheet(); S.selected = d.select; if (S.tab !== "access") show("access"); else renderAccess(); }
      else if (d.approve) decide(d.approve, false);
      else if (d.reject) decide(d.reject, true);
      else if (d.openChange) openChange(d.openChange);
      else if (d.reading) {
        const run = runsFor(S.actor)[d.reading] || Object.values(D.runs).map((r) => r[d.reading]).find(Boolean);
        sheet("What the model read", `<p class="note">The model's reading. Code checked every field below against the request and the org's data before anything was proposed.</p>
          <pre>${esc(JSON.stringify(run.reading, null, 1))}</pre><p class="eyebrow">Checks</p><ul class="checks">${checkList(run, false)}</ul>`);
      }
      else if (d.filter) { S.filter = d.filter; renderApprovals(); }
      else if (d.entry) { const en = S.ledger[+d.entry]; sheet(`Entry ${en.seq}`, `<pre>${esc(JSON.stringify(en, null, 1))}</pre>`); }
      else if (d.prefill) { show("ask"); $("#q").value = d.prefill; $("#q").focus(); }
      else if (d.history) {
        const list = S.changes.filter((c) => c.run.outcome.diff.some((x) => x.resource === d.history));
        sheet("Changes", list.length ? list.map((c) => `<div class="row" data-open-change="${c.id}"><div class="t">${esc(summary(c.run.outcome))}<small>${esc(c.status)}</small></div></div>`).join("") : '<p class="empty">No changes to this resource in this session.</p>');
      }
      else if ("reset" in d) { resetAll(); closeSheet(); toast("Sample org reset"); }
      else if (d.tabGo) show(d.tabGo);
    });
    document.addEventListener("keydown", (e) => { const r = e.target.closest(".row[data-open-change]"); if (r && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openChange(r.dataset.openChange); } });
  }

  init();
})();
