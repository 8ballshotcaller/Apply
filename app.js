/* ============================================================
   JOB HUB — client-side only. No backend, no server storage.
   Everything lives encrypted in this browser's localStorage.
   ============================================================ */

const STORAGE_KEY = "jobhub_vault_v1";
const enc = new TextEncoder();
const dec = new TextDecoder();

let cryptoKey = null;   // derived AES-GCM key, held in memory only while unlocked
let state = null;       // decrypted app state, held in memory only while unlocked

/* ---------------- crypto helpers ---------------- */

async function deriveKey(password, saltBytes) {
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 250000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function fromB64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }

async function encryptJSON(obj, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { iv: b64(iv), data: b64(cipher) };
}

async function decryptJSON(payload, key) {
  const iv = fromB64(payload.iv);
  const cipher = fromB64(payload.data);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return JSON.parse(dec.decode(plain));
}

function defaultState() {
  return {
    profile: { fullName: "", email: "", phone: "", location: "", linkedIn: "", portfolio: "", resume: "", summary: "" },
    answers: [],   // { q, a }
    sources: [],   // { type: 'greenhouse'|'lever'|'adzuna'|'jooble', token, appId, appKey }
    jobs: [],      // tracked jobs: { id, title, company, location, url, status, source, addedAt, notes }
    criteria: { keywords: "", locations: "" }
  };
}

/* ---------------- vault load/save ---------------- */

function getVaultRaw() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

async function saveVault() {
  if (!cryptoKey) return;
  const vault = getVaultRaw();
  const payload = await encryptJSON(state, cryptoKey);
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ salt: vault.salt, check: vault.check, ...payload }));
}

/* ---------------- unlock flow ---------------- */

const lockScreen = document.getElementById("lockScreen");
const appRoot = document.getElementById("app");
const pwInput = document.getElementById("pwInput");
const pwInput2 = document.getElementById("pwInput2");
const lockError = document.getElementById("lockError");
const lockTitle = document.getElementById("lockTitle");
const lockSub = document.getElementById("lockSub");

function isFirstRun() { return !getVaultRaw(); }

function refreshLockScreenMode() {
  if (isFirstRun()) {
    lockTitle.textContent = "Create your Job Hub password";
    lockSub.textContent = "This encrypts everything below. There is no recovery — write it down somewhere safe.";
    pwInput2.classList.remove("hidden");
    pwInput.setAttribute("autocomplete", "new-password");
  } else {
    lockTitle.textContent = "Unlock Job Hub";
    lockSub.textContent = "Enter your password to decrypt your data.";
    pwInput2.classList.add("hidden");
    pwInput.setAttribute("autocomplete", "current-password");
  }
}
refreshLockScreenMode();

document.getElementById("unlockBtn").addEventListener("click", handleUnlock);
pwInput.addEventListener("keydown", e => { if (e.key === "Enter") handleUnlock(); });
pwInput2.addEventListener("keydown", e => { if (e.key === "Enter") handleUnlock(); });

async function handleUnlock() {
  lockError.classList.add("hidden");
  const pw = pwInput.value;
  if (!pw || pw.length < 6) {
    return showLockError("Password must be at least 6 characters.");
  }

  if (isFirstRun()) {
    if (pw !== pwInput2.value) return showLockError("Passwords don't match.");
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(pw, salt);
    const check = await encryptJSON({ ok: true }, key);
    cryptoKey = key;
    state = defaultState();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ salt: b64(salt), check }));
    await saveVault();
    enterApp();
  } else {
    const vault = getVaultRaw();
    const salt = fromB64(vault.salt);
    const key = await deriveKey(pw, salt);
    try {
      await decryptJSON(vault.check, key); // verify password
      const loaded = await decryptJSON({ iv: vault.iv, data: vault.data }, key);
      cryptoKey = key;
      state = loaded;
      enterApp();
    } catch (e) {
      showLockError("Wrong password.");
    }
  }
}

function showLockError(msg) {
  lockError.textContent = msg;
  lockError.classList.remove("hidden");
}

document.getElementById("wipeLink").addEventListener("click", (e) => {
  e.preventDefault();
  if (confirm("This permanently deletes all encrypted data in this browser. Continue?")) {
    localStorage.removeItem(STORAGE_KEY);
    location.reload();
  }
});

document.getElementById("lockBtn").addEventListener("click", () => {
  cryptoKey = null;
  state = null;
  appRoot.classList.add("hidden");
  lockScreen.classList.remove("hidden");
  pwInput.value = ""; pwInput2.value = "";
  refreshLockScreenMode();
});

document.getElementById("wipeBtn").addEventListener("click", () => {
  if (confirm("This permanently deletes ALL data (profile, answers, tracker, sources). Are you sure?")) {
    localStorage.removeItem(STORAGE_KEY);
    location.reload();
  }
});

function enterApp() {
  lockScreen.classList.add("hidden");
  appRoot.classList.remove("hidden");
  renderProfile();
  renderAnswers();
  renderSources();
  renderTracker();
  document.getElementById("critKeywords").value = state.criteria.keywords || "";
  document.getElementById("critLocations").value = state.criteria.locations || "";
}

/* ---------------- tabs ---------------- */

document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.add("hidden"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.remove("hidden");
  });
});
document.querySelector(".tab-btn[data-tab='find']").classList.add("active");

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2200);
}

/* ---------------- profile ---------------- */

function renderProfile() {
  const p = state.profile;
  document.getElementById("pFullName").value = p.fullName || "";
  document.getElementById("pEmail").value = p.email || "";
  document.getElementById("pPhone").value = p.phone || "";
  document.getElementById("pLocation").value = p.location || "";
  document.getElementById("pLinkedIn").value = p.linkedIn || "";
  document.getElementById("pPortfolio").value = p.portfolio || "";
  document.getElementById("pResume").value = p.resume || "";
  document.getElementById("pSummary").value = p.summary || "";
}

document.getElementById("saveProfileBtn").addEventListener("click", async () => {
  state.profile = {
    fullName: document.getElementById("pFullName").value.trim(),
    email: document.getElementById("pEmail").value.trim(),
    phone: document.getElementById("pPhone").value.trim(),
    location: document.getElementById("pLocation").value.trim(),
    linkedIn: document.getElementById("pLinkedIn").value.trim(),
    portfolio: document.getElementById("pPortfolio").value.trim(),
    resume: document.getElementById("pResume").value,
    summary: document.getElementById("pSummary").value.trim()
  };
  await saveVault();
  document.getElementById("profileSaved").textContent = "Saved ✓";
  setTimeout(() => document.getElementById("profileSaved").textContent = "", 1500);
});

/* ---------------- answer bank ---------------- */

function renderAnswers() {
  const list = document.getElementById("qaList");
  if (!state.answers.length) {
    list.innerHTML = `<div class="empty">No answers saved yet.</div>`;
    return;
  }
  list.innerHTML = state.answers.map((qa, i) => `
    <div class="qa-item">
      <div class="q">${escapeHtml(qa.q)}</div>
      <div class="a">${escapeHtml(qa.a)}</div>
      <div class="flexbtns">
        <button class="ghost" data-edit="${i}">Edit</button>
        <button class="ghost" data-del="${i}">Delete</button>
      </div>
    </div>
  `).join("");
  list.querySelectorAll("[data-edit]").forEach(b => b.addEventListener("click", () => {
    const qa = state.answers[+b.dataset.edit];
    document.getElementById("qaQuestion").value = qa.q;
    document.getElementById("qaAnswer").value = qa.a;
  }));
  list.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
    state.answers.splice(+b.dataset.del, 1);
    await saveVault();
    renderAnswers();
  }));
}

document.getElementById("addQaBtn").addEventListener("click", async () => {
  const q = document.getElementById("qaQuestion").value.trim();
  const a = document.getElementById("qaAnswer").value.trim();
  if (!q || !a) return toast("Enter both a question and an answer.");
  const existing = state.answers.findIndex(x => x.q.toLowerCase() === q.toLowerCase());
  if (existing >= 0) state.answers[existing].a = a;
  else state.answers.push({ q, a });
  await saveVault();
  document.getElementById("qaQuestion").value = "";
  document.getElementById("qaAnswer").value = "";
  renderAnswers();
  toast("Saved to answer bank.");
});

/* ---------------- sources ---------------- */

function renderSources() {
  const list = document.getElementById("srcList");
  if (!state.sources.length) {
    list.innerHTML = `<div class="empty">None added yet.</div>`;
    return;
  }
  list.innerHTML = state.sources.map((s, i) => `
    <span class="chip">${s.type}: ${escapeHtml(s.token || s.label || "")}
      <button data-rm="${i}">✕</button>
    </span>
  `).join("");
  list.querySelectorAll("[data-rm]").forEach(b => b.addEventListener("click", async () => {
    state.sources.splice(+b.dataset.rm, 1);
    await saveVault();
    renderSources();
  }));
}

document.getElementById("addSrcBtn").addEventListener("click", async () => {
  const type = document.getElementById("srcType").value;
  const token = document.getElementById("srcToken").value.trim();
  if (!token) return toast("Enter a company token.");
  state.sources.push({ type, token });
  await saveVault();
  document.getElementById("srcToken").value = "";
  renderSources();
});

document.getElementById("showManualEntry").addEventListener("click", () => {
  document.getElementById("manualEntryForm").classList.toggle("hidden");
});

document.getElementById("manSaveBtn").addEventListener("click", async () => {
  const job = {
    id: "manual-" + Date.now(),
    title: document.getElementById("manTitle").value.trim(),
    company: document.getElementById("manCompany").value.trim(),
    location: document.getElementById("manLocation").value.trim(),
    url: document.getElementById("manUrl").value.trim(),
    source: "manual",
    status: "saved",
    addedAt: Date.now(),
    notes: ""
  };
  if (!job.title || !job.url) return toast("Title and URL are required.");
  state.jobs.push(job);
  await saveVault();
  ["manTitle","manCompany","manLocation","manUrl"].forEach(id => document.getElementById(id).value = "");
  renderTracker();
  toast("Added to tracker.");
});

/* ---------------- job fetching ---------------- */
/* All sources here are free, public, CORS-friendly, and do not require
   scraping or violating any platform's terms of service. */

async function fetchGreenhouse(token) {
  const res = await fetch(`https://boards-api.greenhouse.io/v1/boards/${encodeURIComponent(token)}/jobs?content=true`);
  if (!res.ok) throw new Error(`Greenhouse (${token}) failed: ${res.status}`);
  const data = await res.json();
  return (data.jobs || []).map(j => ({
    id: `gh-${j.id}`,
    title: j.title,
    company: token,
    location: j.location?.name || "",
    url: j.absolute_url,
    source: "greenhouse"
  }));
}

async function fetchLever(token) {
  const res = await fetch(`https://api.lever.co/v0/postings/${encodeURIComponent(token)}?mode=json`);
  if (!res.ok) throw new Error(`Lever (${token}) failed: ${res.status}`);
  const data = await res.json();
  return (data || []).map(j => ({
    id: `lv-${j.id}`,
    title: j.text,
    company: token,
    location: j.categories?.location || "",
    url: j.hostedUrl,
    source: "lever"
  }));
}

async function fetchRemoteOK(keyword) {
  const res = await fetch(`https://remoteok.com/api?tags=${encodeURIComponent(keyword)}`);
  if (!res.ok) throw new Error(`RemoteOK failed: ${res.status}`);
  const data = await res.json();
  return (data || []).filter(j => j.id).map(j => ({
    id: `rok-${j.id}`,
    title: j.position,
    company: j.company,
    location: j.location || "Remote",
    url: j.url,
    source: "remoteok"
  }));
}

async function fetchRemotive(keyword) {
  const res = await fetch(`https://remotive.com/api/remote-jobs?search=${encodeURIComponent(keyword)}`);
  if (!res.ok) throw new Error(`Remotive failed: ${res.status}`);
  const data = await res.json();
  return (data.jobs || []).map(j => ({
    id: `rmv-${j.id}`,
    title: j.title,
    company: j.company_name,
    location: j.candidate_required_location || "Remote",
    url: j.url,
    source: "remotive"
  }));
}

async function fetchAdzuna(src, keyword, location) {
  // Adzuna aggregates listings from many boards (including ones LinkedIn/Indeed also carry).
  // Free API key: register at https://developer.adzuna.com/
  const url = `https://api.adzuna.com/v1/api/jobs/${src.country || "us"}/search/1?app_id=${src.appId}&app_key=${src.appKey}&what=${encodeURIComponent(keyword)}&where=${encodeURIComponent(location)}&content-type=application/json`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Adzuna failed: ${res.status}`);
  const data = await res.json();
  return (data.results || []).map(j => ({
    id: `adz-${j.id}`,
    title: j.title,
    company: j.company?.display_name || "",
    location: j.location?.display_name || "",
    url: j.redirect_url,
    source: "adzuna"
  }));
}

async function runSearch() {
  const keywords = document.getElementById("critKeywords").value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const locations = document.getElementById("critLocations").value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  state.criteria = { keywords: document.getElementById("critKeywords").value, locations: document.getElementById("critLocations").value };
  await saveVault();

  const statusEl = document.getElementById("searchStatus");
  statusEl.textContent = "Searching…";
  const resultsList = document.getElementById("resultsList");
  resultsList.innerHTML = "";

  let allJobs = [];
  const errors = [];

  for (const src of state.sources) {
    try {
      if (src.type === "greenhouse") allJobs.push(...await fetchGreenhouse(src.token));
      else if (src.type === "lever") allJobs.push(...await fetchLever(src.token));
      else if (src.type === "adzuna") allJobs.push(...await fetchAdzuna(src, keywords[0] || "", locations[0] || ""));
    } catch (e) {
      errors.push(e.message);
    }
  }

  // Broad aggregators — searched once using the first keyword/location for simplicity.
  try { allJobs.push(...await fetchRemoteOK(keywords[0] || "")); } catch (e) { errors.push(e.message); }
  try { allJobs.push(...await fetchRemotive(keywords[0] || "")); } catch (e) { errors.push(e.message); }

  // Filter by keywords/locations if provided
  const filtered = allJobs.filter(j => {
    const titleMatch = !keywords.length || keywords.some(k => j.title.toLowerCase().includes(k));
    const locMatch = !locations.length || locations.some(l =>
      j.location.toLowerCase().includes(l) || (l === "remote" && /remote/i.test(j.location))
    );
    return titleMatch && locMatch;
  });

  statusEl.textContent = `${filtered.length} matches` + (errors.length ? ` (${errors.length} source error${errors.length > 1 ? "s" : ""})` : "");

  if (!filtered.length) {
    resultsList.innerHTML = `<div class="empty">No matches. Try broader keywords, add more companies in Sources, or check the Sources tab for LinkedIn/Indeed manual-add.</div>`;
    return;
  }

  resultsList.innerHTML = filtered.slice(0, 100).map((j, i) => `
    <div class="job-card">
      <div class="title">${escapeHtml(j.title)}</div>
      <div class="meta">${escapeHtml(j.company)} · ${escapeHtml(j.location)} · via ${j.source}</div>
      <div class="actions">
        <a href="${j.url}" target="_blank" rel="noopener"><button class="secondary">View listing</button></a>
        <button data-save="${i}">Save to tracker</button>
        <button class="ghost" data-prep="${i}">Prep sheet</button>
      </div>
    </div>
  `).join("");

  resultsList.querySelectorAll("[data-save]").forEach(b => b.addEventListener("click", async () => {
    const j = filtered[+b.dataset.save];
    if (state.jobs.some(x => x.url === j.url)) return toast("Already in tracker.");
    state.jobs.push({ ...j, status: "saved", addedAt: Date.now(), notes: "" });
    await saveVault();
    renderTracker();
    toast("Saved to tracker.");
  }));
  resultsList.querySelectorAll("[data-prep]").forEach(b => b.addEventListener("click", () => {
    showPrepSheet(filtered[+b.dataset.prep]);
  }));
}

document.getElementById("runSearchBtn").addEventListener("click", () => {
  runSearch().catch(e => toast("Search error: " + e.message));
});

/* ---------------- tracker ---------------- */

const STATUS_LABELS = { saved: "Saved", applied: "Applied", interview: "Interview", offer: "Offer", rejected: "Rejected" };

function renderTracker() {
  const list = document.getElementById("trackerList");
  if (!state.jobs.length) {
    list.innerHTML = `<div class="empty">Nothing saved yet. Save jobs from the Find Jobs tab.</div>`;
    return;
  }
  const sorted = [...state.jobs].sort((a, b) => b.addedAt - a.addedAt);
  list.innerHTML = sorted.map(j => `
    <div class="job-card">
      <div class="title">${escapeHtml(j.title)}
        <span class="status-badge status-${j.status}">${STATUS_LABELS[j.status]}</span>
      </div>
      <div class="meta">${escapeHtml(j.company || "")} · ${escapeHtml(j.location || "")} · via ${j.source}</div>
      <div class="actions">
        <a href="${j.url}" target="_blank" rel="noopener"><button class="secondary">Open listing</button></a>
        <button class="ghost" data-prep-id="${j.id}">Prep sheet</button>
        <select data-status-id="${j.id}">
          ${Object.entries(STATUS_LABELS).map(([k, v]) => `<option value="${k}" ${k===j.status?"selected":""}>${v}</option>`).join("")}
        </select>
        <button class="ghost" data-del-id="${j.id}">Remove</button>
      </div>
    </div>
  `).join("");

  list.querySelectorAll("[data-status-id]").forEach(sel => sel.addEventListener("change", async () => {
    const job = state.jobs.find(j => j.id === sel.dataset.statusId);
    job.status = sel.value;
    await saveVault();
    renderTracker();
  }));
  list.querySelectorAll("[data-del-id]").forEach(b => b.addEventListener("click", async () => {
    state.jobs = state.jobs.filter(j => j.id !== b.dataset.delId);
    await saveVault();
    renderTracker();
  }));
  list.querySelectorAll("[data-prep-id]").forEach(b => b.addEventListener("click", () => {
    showPrepSheet(state.jobs.find(j => j.id === b.dataset.prepId));
  }));
}

/* ---------------- prep sheet ---------------- */

function showPrepSheet(job) {
  const p = state.profile;
  const lines = [
    `PREP SHEET — ${job.title} @ ${job.company}`,
    `Listing: ${job.url}`,
    ``,
    `--- Contact info ---`,
    `Name: ${p.fullName}`,
    `Email: ${p.email}`,
    `Phone: ${p.phone}`,
    `Location: ${p.location}`,
    `LinkedIn: ${p.linkedIn}`,
    `Portfolio: ${p.portfolio}`,
    ``,
    `--- Summary ---`,
    p.summary || "(none saved — add one in My Profile)",
    ``,
    `--- Saved answers to common questions ---`,
    ...(state.answers.length
      ? state.answers.map(qa => `Q: ${qa.q}\nA: ${qa.a}`)
      : ["(no saved answers yet — add some in Answer Bank)"]),
  ].join("\n");

  const win = window.open("", "_blank");
  win.document.write(`<pre style="white-space:pre-wrap;font-family:monospace;padding:20px;max-width:640px;margin:auto;">${escapeHtml(lines)}</pre>
    <div style="text-align:center;"><button onclick="navigator.clipboard.writeText(document.querySelector('pre').innerText);this.textContent='Copied!'" style="padding:10px 18px;">Copy to clipboard</button></div>`);
}

/* ---------------- export / import ---------------- */

document.getElementById("exportBtn").addEventListener("click", () => {
  const vault = getVaultRaw();
  const blob = new Blob([JSON.stringify(vault)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "jobhub-backup.json";
  a.click();
});

document.getElementById("importBtn").addEventListener("click", () => document.getElementById("importFile").click());
document.getElementById("importFile").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(reader.result);
      if (!parsed.salt || !parsed.data) throw new Error("bad file");
      localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
      toast("Imported. Reloading…");
      setTimeout(() => location.reload(), 800);
    } catch {
      toast("That doesn't look like a valid backup file.");
    }
  };
  reader.readAsText(file);
});

/* ---------------- utils ---------------- */

function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
