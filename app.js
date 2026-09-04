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
    jobs: [],      // tracked jobs: { id, title, company, location, url, status, source, addedAt, notes, description, aiAnswers }
    outreach: [],  // { id, jobId, contactRole, searchTerms, message, status, note }
    companyPrefs: {}, // { "company name lowercased": "yes" | "no" }
    criteria: { keywords: "", locations: "" },
    settings: { anthropicApiKey: "", adzunaAppId: "", adzunaAppKey: "", joobleKey: "" }
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

function isFirstRun() { return !getVaultRaw(); }

function refreshLockScreenMode() {
  lockTitle.textContent = "Unlock";
  if (isFirstRun()) {
    pwInput.classList.remove("hidden");
    pwInput2.classList.remove("hidden");
    pwInput.setAttribute("autocomplete", "new-password");
    pwInput.placeholder = "New password";
    pwInput2.placeholder = "Confirm password";
  } else {
    pwInput2.classList.add("hidden");
    pwInput.setAttribute("autocomplete", "current-password");
    pwInput.placeholder = "Password";
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
  state.settings = state.settings || {};
  state.outreach = state.outreach || [];
  state.companyPrefs = state.companyPrefs || {};
  state.settings.anthropicApiKey = state.settings.anthropicApiKey || "";
  state.settings.adzunaAppId = state.settings.adzunaAppId || "";
  state.settings.adzunaAppKey = state.settings.adzunaAppKey || "";
  state.settings.joobleKey = state.settings.joobleKey || "";
  lockScreen.classList.add("hidden");
  appRoot.classList.remove("hidden");
  renderProfile();
  renderAnswers();
  renderSources();
  renderTracker();
  renderOutreachLog();
  populateOutreachJobSelect();
  document.getElementById("critKeywords").value = state.criteria.keywords || "";
  document.getElementById("critLocations").value = state.criteria.locations || "";
  document.getElementById("apiKeyInput").value = state.settings.anthropicApiKey || "";
  document.getElementById("adzunaAppId").value = state.settings.adzunaAppId || "";
  document.getElementById("adzunaAppKey").value = state.settings.adzunaAppKey || "";
  document.getElementById("joobleKey").value = state.settings.joobleKey || "";
  loadAutoDigest();
}

document.getElementById("saveSearchKeysBtn").addEventListener("click", async () => {
  state.settings.adzunaAppId = document.getElementById("adzunaAppId").value.trim();
  state.settings.adzunaAppKey = document.getElementById("adzunaAppKey").value.trim();
  state.settings.joobleKey = document.getElementById("joobleKey").value.trim();
  await saveVault();
  const s = document.getElementById("searchKeysStatus");
  s.textContent = "Saved ✓";
  setTimeout(() => s.textContent = "", 1500);
});

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

// Resume file upload → extract text client-side (nothing uploaded anywhere)
if (window.pdfjsLib) {
  pdfjsLib.GlobalWorkerOptions.workerSrc = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";
}

document.getElementById("pResumeFile").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const statusEl = document.getElementById("resumeParseStatus");
  statusEl.textContent = "Reading…";
  try {
    const ext = file.name.toLowerCase().split(".").pop();
    let text = "";
    if (ext === "pdf") {
      const buf = await file.arrayBuffer();
      const pdf = await pdfjsLib.getDocument({ data: buf }).promise;
      const pages = [];
      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        pages.push(content.items.map(it => it.str).join(" "));
      }
      text = pages.join("\n\n");
    } else if (ext === "docx") {
      const buf = await file.arrayBuffer();
      const result = await mammoth.extractRawText({ arrayBuffer: buf });
      text = result.value;
    } else {
      statusEl.textContent = "Only .pdf and .docx are supported.";
      return;
    }
    document.getElementById("pResume").value = text.trim();
    statusEl.textContent = `Extracted from ${file.name} — review below, then Save.`;
  } catch (err) {
    statusEl.textContent = "Couldn't read that file — try pasting the text manually.";
    console.error(err);
  }
});

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
  const suggestions = [
    "Are you legally authorized to work in the United States?",
    "Will you now or in the future require visa sponsorship?",
    "What are your salary expectations?",
    "What is your notice period / earliest start date?",
    "Are you willing to relocate?",
    "How many years of experience do you have in this field?",
    "Do you have a college degree? What did you study?",
    "Are you open to remote / hybrid / onsite work?"
  ];
  const sugEl = document.getElementById("qaSuggestions");
  if (sugEl) {
    sugEl.innerHTML = suggestions
      .filter(s => !state.answers.some(a => a.q === s))
      .map(s => `<span class="chip" data-suggest="${escapeHtml(s)}" style="cursor:pointer;">+ ${escapeHtml(s)}</span>`).join("");
    sugEl.querySelectorAll("[data-suggest]").forEach(el => el.addEventListener("click", () => {
      document.getElementById("qaQuestion").value = el.dataset.suggest;
      document.getElementById("qaAnswer").focus();
    }));
  }

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
    description: document.getElementById("manDescription").value.trim(),
    source: "manual",
    status: "saved",
    addedAt: Date.now(),
    notes: ""
  };
  if (!job.title || !job.url) return toast("Title and URL are required.");
  state.jobs.push(job);
  await saveVault();
  ["manTitle","manCompany","manLocation","manUrl","manDescription"].forEach(id => document.getElementById(id).value = "");
  renderTracker();
  toast("Added to tracker.");
});

/* ---------------- job fetching ---------------- */
/* All sources here are free, public, CORS-friendly, and do not require
   scraping or violating any platform's terms of service. */

function stripHtml(html) {
  return String(html || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

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
    description: stripHtml(j.content),
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
    description: j.descriptionPlain || stripHtml(j.description),
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
    description: stripHtml(j.description),
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
    description: stripHtml(j.description),
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
  statusEl.innerHTML = "Searching...";

  let allJobs = [];
  const errors = [];

  for (const src of state.sources) {
    try {
      if (src.type === "greenhouse") allJobs.push(...await fetchGreenhouse(src.token));
      else if (src.type === "lever") allJobs.push(...await fetchLever(src.token));
    } catch (e) { errors.push({ source: src.token + " (" + src.type + ")", message: e.message }); }
  }

  try { allJobs.push(...await fetchRemoteOK(keywords[0] || "")); }
  catch (e) { errors.push({ source: "RemoteOK", message: e.message }); }

  try { allJobs.push(...await fetchRemotive(keywords[0] || "")); }
  catch (e) { errors.push({ source: "Remotive", message: e.message }); }

  if (state.settings.adzunaAppId && state.settings.adzunaAppKey) {
    try {
      allJobs.push(...await fetchAdzuna(
        { appId: state.settings.adzunaAppId, appKey: state.settings.adzunaAppKey },
        keywords[0] || "", locations[0] || ""
      ));
    } catch (e) { errors.push({ source: "Adzuna", message: e.message }); }
  }

  let filtered = filterJobs(allJobs, keywords, locations);
  filtered = applyMatchScores(filtered);
  lastAllJobs = filtered;

  renderSearchStatus(filtered.length, errors);
  renderCompanyList(filtered);
  renderResultsList(excludeDoNotContact(filtered));
}

function renderSearchStatus(count, errors) {
  const statusEl = document.getElementById("searchStatus");
  let html = count + " matches";
  if (errors.length) {
    html += "<br><span style=\"color:var(--bad);\">" +
      errors.map(e => escapeHtml(e.source) + ": " + escapeHtml(e.message)).join("<br>") +
      "</span>";
  }
  statusEl.innerHTML = html;
}

function filterJobs(jobs, keywords, locations) {
  return jobs.filter(j => {
    const titleMatch = !keywords.length || keywords.some(k => j.title.toLowerCase().includes(k));
    const locMatch = !locations.length || locations.some(l =>
      j.location.toLowerCase().includes(l) || (l === "remote" && /remote/i.test(j.location))
    );
    return titleMatch && locMatch;
  });
}

/* ---------------- match scoring (client-side heuristic, no API cost) ---------------- */

function computeMatchScore(job, resumeWordSet) {
  if (!resumeWordSet || !resumeWordSet.size) return null;
  const text = (job.title + " " + (job.description || "")).toLowerCase();
  const jobWords = Array.from(new Set(text.split(/[^a-z0-9+]+/).filter(w => w.length > 3)));
  if (!jobWords.length) return null;
  const hits = jobWords.filter(w => resumeWordSet.has(w)).length;
  return Math.round((hits / jobWords.length) * 100);
}

function applyMatchScores(jobs) {
  const resume = (state.profile.resume || "").toLowerCase();
  const resumeWordSet = resume.length
    ? new Set(resume.split(/[^a-z0-9+]+/).filter(w => w.length > 3))
    : null;
  const scored = jobs.map(j => ({ ...j, matchScore: computeMatchScore(j, resumeWordSet) }));
  const minMatchEl = document.getElementById("critMinMatch");
  const minMatch = minMatchEl ? (+minMatchEl.value || 0) : 0;
  const withScores = scored.filter(j => j.matchScore === null || j.matchScore >= minMatch);
  withScores.sort((a, b) => (b.matchScore ?? -1) - (a.matchScore ?? -1));
  return withScores;
}

function matchBadge(score) {
  if (score === null || score === undefined) return "";
  let cls = "status-rejected";
  if (score >= 60) cls = "status-offer";
  else if (score >= 35) cls = "status-interview";
  return "<span class=\"status-badge " + cls + "\">" + score + "% match</span>";
}

/* ---------------- companies list (yes / do-not-contact) ---------------- */

let lastAllJobs = [];

function excludeDoNotContact(jobs) {
  return jobs.filter(j => state.companyPrefs[(j.company || "").toLowerCase()] !== "no");
}

function renderCompanyList(jobs) {
  const el = document.getElementById("companyList");
  const counts = {};
  jobs.forEach(j => {
    const key = (j.company || "Unknown").trim();
    if (!key) return;
    counts[key] = (counts[key] || 0) + 1;
  });
  const companies = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 30);

  if (!companies.length) {
    el.innerHTML = '<div class="empty">Run a search to see companies here.</div>';
    return;
  }

  el.innerHTML = companies.map(([name, count]) => {
    const key = name.toLowerCase();
    const pref = state.companyPrefs[key];
    return `
      <div class="chip" style="display:flex;align-items:center;gap:8px;">
        <span>${escapeHtml(name)} (${count})</span>
        <button data-co-yes="${escapeHtml(key)}" class="ghost" style="padding:2px 8px;font-size:11px;${pref === "yes" ? "color:var(--good);" : ""}">Yes</button>
        <button data-co-no="${escapeHtml(key)}" class="ghost" style="padding:2px 8px;font-size:11px;${pref === "no" ? "color:var(--bad);" : ""}">Do not contact</button>
      </div>
    `;
  }).join("");

  el.querySelectorAll("[data-co-yes]").forEach(b => b.addEventListener("click", async () => {
    state.companyPrefs[b.dataset.coYes] = "yes";
    await saveVault();
    renderCompanyList(lastAllJobs);
    renderResultsList(excludeDoNotContact(lastAllJobs));
  }));
  el.querySelectorAll("[data-co-no]").forEach(b => b.addEventListener("click", async () => {
    state.companyPrefs[b.dataset.coNo] = "no";
    await saveVault();
    renderCompanyList(lastAllJobs);
    renderResultsList(excludeDoNotContact(lastAllJobs));
  }));
}

function renderResultsList(filtered) {
  const resultsList = document.getElementById("resultsList");
  if (!filtered.length) {
    resultsList.innerHTML = '<div class="empty">No matches. Try broader keywords, or check the error details above the search button.</div>';
    return;
  }

  resultsList.innerHTML = filtered.slice(0, 100).map((j, i) => `
    <div class="job-card">
      <div class="title">${escapeHtml(j.title)} ${matchBadge(j.matchScore)}</div>
      <div class="meta">${escapeHtml(j.company)} \u00b7 ${escapeHtml(j.location)} \u00b7 via ${j.source}</div>
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

/* ---------------- daily auto-digest (from GitHub Actions, if set up) ---------------- */

async function loadAutoDigest() {
  const noteEl = document.getElementById("autoDigestNote");
  try {
    const res = await fetch("data/jobs.json?t=" + Date.now());
    if (!res.ok) throw new Error("no digest yet");
    const data = await res.json();
    const keywords = (state.criteria.keywords || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    const locations = (state.criteria.locations || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
    let filtered = filterJobs(data.jobs || [], keywords, locations);
    filtered = applyMatchScores(filtered);
    lastAllJobs = filtered;
    const when = new Date(data.updatedAt).toLocaleString();
    noteEl.textContent = "Auto-updated " + when + " \u2014 " + filtered.length + " matches.";
    renderCompanyList(filtered);
    renderResultsList(excludeDoNotContact(filtered));
  } catch (e) {
    noteEl.textContent = "No auto-digest yet (optional, see Settings) \u2014 tap Search now for a live search.";
  }
}
/* ---------------- tracker ---------------- */

const STATUS_LABELS = { saved: "Saved", applied: "Applied", interview: "Interview", offer: "Offer", rejected: "Rejected" };

function renderTracker() {
  const list = document.getElementById("trackerList");
  if (!state.jobs.length) {
    list.innerHTML = `<div class="empty">Nothing saved yet. Save jobs from the Find Jobs tab.</div>`;
    populateOutreachJobSelect();
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
        <button class="ghost" data-ai-id="${j.id}">AI-draft answers</button>
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
  list.querySelectorAll("[data-ai-id]").forEach(b => b.addEventListener("click", () => {
    openAiModal(state.jobs.find(j => j.id === b.dataset.aiId));
  }));
  populateOutreachJobSelect();
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
    ...(job.aiAnswers ? [
      ``,
      `--- Tailored answers for this job (AI-drafted, your edits) ---`,
      `Q: Why do you want to work here?\nA: ${job.aiAnswers.why_company}`,
      `Q: Why are you a good fit for this role?\nA: ${job.aiAnswers.why_fit}`,
      `Q: What relevant experience do you have?\nA: ${job.aiAnswers.experience}`,
    ] : []),
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

/* ---------------- AI-drafted answers ---------------- */

let aiModalJobId = null;

async function openAiModal(job) {
  if (!job) return;
  aiModalJobId = job.id;
  document.getElementById("aiModal").classList.remove("hidden");
  document.getElementById("aiModalTitle").textContent = `Tailored answers — ${job.title}`;
  document.getElementById("aiModalFields").innerHTML = "";
  document.getElementById("aiModalStatus").textContent = "";

  if (job.aiAnswers) {
    renderAiFields(job.aiAnswers);
  } else {
    await generateAiAnswers(job);
  }
}

function renderAiFields(answers) {
  document.getElementById("aiModalFields").innerHTML = `
    <label>Why do you want to work here?</label>
    <textarea id="aiWhyCompany" style="min-height:90px;">${escapeHtml(answers.why_company || "")}</textarea>
    <label>Why are you a good fit for this role?</label>
    <textarea id="aiWhyFit" style="min-height:90px;">${escapeHtml(answers.why_fit || "")}</textarea>
    <label>What relevant experience do you have?</label>
    <textarea id="aiExperience" style="min-height:90px;">${escapeHtml(answers.experience || "")}</textarea>
  `;
}

async function generateAiAnswers(job) {
  const apiKey = state.settings.anthropicApiKey;
  const statusEl = document.getElementById("aiModalStatus");
  if (!apiKey) {
    statusEl.textContent = "Add your Anthropic API key in Settings first.";
    return;
  }
  if (!state.profile.resume) {
    statusEl.textContent = "Add your resume in My Profile first.";
    return;
  }
  statusEl.textContent = "Drafting from your resume + this listing…";

  const prompt = `You are helping ${state.profile.fullName || "a job applicant"} write short, genuine, first-person answers to job application questions for one specific role. Sound like a real person who read the posting — specific, concrete, no generic filler, no corporate buzzwords, under 100 words each.

RESUME:
${state.profile.resume.slice(0, 6000)}

JOB:
Title: ${job.title}
Company: ${job.company}
Location: ${job.location}
Description: ${(job.description || "(no description available — write generally based on the title/company)").slice(0, 3000)}

Respond with ONLY a JSON object, no markdown fences, no extra text:
{"why_company": "...", "why_fit": "...", "experience": "..."}`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true"
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 700,
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`API error ${res.status}: ${errText.slice(0, 200)}`);
    }
    const data = await res.json();
    const text = data.content.map(b => b.text || "").join("").trim();
    const clean = text.replace(/^```json\s*/i, "").replace(/```$/, "").trim();
    const parsed = JSON.parse(clean);
    renderAiFields(parsed);
    statusEl.textContent = "Draft ready — edit anything before saving.";
  } catch (e) {
    statusEl.textContent = "Couldn't generate a draft: " + e.message;
  }
}

document.getElementById("aiRegenBtn").addEventListener("click", () => {
  const job = state.jobs.find(j => j.id === aiModalJobId);
  if (job) generateAiAnswers(job);
});

document.getElementById("aiSaveBtn").addEventListener("click", async () => {
  const job = state.jobs.find(j => j.id === aiModalJobId);
  if (!job) { toast("Save this job to your tracker first."); return; }
  job.aiAnswers = {
    why_company: document.getElementById("aiWhyCompany")?.value || "",
    why_fit: document.getElementById("aiWhyFit")?.value || "",
    experience: document.getElementById("aiExperience")?.value || ""
  };
  await saveVault();
  document.getElementById("aiModal").classList.add("hidden");
  toast("Saved to this job.");
});

document.getElementById("aiCloseBtn").addEventListener("click", () => {
  document.getElementById("aiModal").classList.add("hidden");
});

document.getElementById("saveApiKeyBtn").addEventListener("click", async () => {
  state.settings.anthropicApiKey = document.getElementById("apiKeyInput").value.trim();
  await saveVault();
  const s = document.getElementById("apiKeyStatus");
  s.textContent = "Saved ✓";
  setTimeout(() => s.textContent = "", 1500);
});

/* ---------------- LinkedIn outreach ---------------- */

function populateOutreachJobSelect() {
  const sel = document.getElementById("outreachJobSelect");
  if (!state.jobs.length) {
    sel.innerHTML = `<option value="">No tracked jobs yet — save one first</option>`;
    return;
  }
  sel.innerHTML = state.jobs
    .slice().sort((a, b) => b.addedAt - a.addedAt)
    .map(j => `<option value="${j.id}">${escapeHtml(j.title)} — ${escapeHtml(j.company || "")}</option>`)
    .join("");
}

async function generateOutreach(job) {
  const apiKey = state.settings.anthropicApiKey;
  const statusEl = document.getElementById("outreachStatus");
  if (!apiKey) { statusEl.textContent = "Add your Anthropic API key in Settings first."; return; }
  if (!state.profile.resume) { statusEl.textContent = "Add your resume in My Profile first."; return; }
  statusEl.textContent = "Thinking through who's worth reaching out to…";

  const prompt = `${state.profile.fullName || "A job applicant"} is applying to this role and wants to reach out on LinkedIn to someone at the company (since cold-applying alone often doesn't get a response).

RESUME:
${state.profile.resume.slice(0, 4000)}

JOB:
Title: ${job.title}
Company: ${job.company}
Description: ${(job.description || "(no description available)").slice(0, 2000)}

Respond with ONLY a JSON object, no markdown fences:
{
  "contact_roles": ["2-3 specific job titles at this company worth messaging, e.g. 'Engineering Manager, Platform Team' or 'Technical Recruiter'"],
  "search_terms": ["2-3 short phrases to paste into LinkedIn's people search bar to find them, e.g. '${job.company} engineering manager'"],
  "message": "A short (under 100 words), genuine-sounding LinkedIn connection note or InMail — mentions the specific role, one concrete relevant thing from the resume, and a light, low-pressure ask (a quick chat, or just flagging the application). No corporate buzzwords, no 'I hope this message finds you well.'"
}`;

  try {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true"
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 700,
        messages: [{ role: "user", content: prompt }]
      })
    });
    if (!res.ok) throw new Error(`API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const data = await res.json();
    const text = data.content.map(b => b.text || "").join("").trim();
    const clean = text.replace(/^```json\s*/i, "").replace(/```$/, "").trim();
    const parsed = JSON.parse(clean);
    renderOutreachFields(job, parsed);
    statusEl.textContent = "Draft ready — edit anything, then log it once you've found the actual person.";
  } catch (e) {
    statusEl.textContent = "Couldn't generate a suggestion: " + e.message;
  }
}

function renderOutreachFields(job, suggestion) {
  document.getElementById("outreachFields").innerHTML = `
    <label>Roles worth messaging</label>
    <div class="small" style="margin-bottom:8px;">${(suggestion.contact_roles || []).map(escapeHtml).join(" · ")}</div>
    <label>Paste these into LinkedIn's people search</label>
    <div style="margin-bottom:8px;">
      ${(suggestion.search_terms || []).map(t => `<span class="chip">${escapeHtml(t)}</span>`).join("")}
    </div>
    <label>Once you find them, note who (optional, for your own log)</label>
    <input id="outreachContact" placeholder="e.g. Jane Doe, Engineering Manager">
    <label>Message draft — edit freely</label>
    <textarea id="outreachMessage" style="min-height:120px;">${escapeHtml(suggestion.message || "")}</textarea>
    <button id="outreachSaveLogBtn">Log this outreach</button>
  `;
  document.getElementById("outreachSaveLogBtn").addEventListener("click", async () => {
    state.outreach.push({
      id: "out-" + Date.now(),
      jobId: job.id,
      jobTitle: job.title,
      company: job.company,
      contact: document.getElementById("outreachContact").value.trim(),
      message: document.getElementById("outreachMessage").value,
      status: "drafted",
      createdAt: Date.now()
    });
    await saveVault();
    renderOutreachLog();
    toast("Logged.");
  });
}

document.getElementById("genOutreachBtn").addEventListener("click", () => {
  const jobId = document.getElementById("outreachJobSelect").value;
  const job = state.jobs.find(j => j.id === jobId);
  if (!job) return toast("Save a job to your tracker first.");
  generateOutreach(job);
});

const OUTREACH_STATUS_LABELS = { drafted: "Drafted", sent: "Sent", replied: "Replied", no_response: "No response" };

function renderOutreachLog() {
  const list = document.getElementById("outreachLog");
  if (!state.outreach.length) {
    list.innerHTML = `<div class="empty">Nothing logged yet.</div>`;
    return;
  }
  const sorted = [...state.outreach].sort((a, b) => b.createdAt - a.createdAt);
  list.innerHTML = sorted.map(o => `
    <div class="job-card">
      <div class="title">${escapeHtml(o.jobTitle)} <span class="status-badge status-${o.status === "replied" ? "offer" : o.status === "sent" ? "applied" : o.status === "no_response" ? "rejected" : "saved"}">${OUTREACH_STATUS_LABELS[o.status]}</span></div>
      <div class="meta">${escapeHtml(o.company || "")}${o.contact ? " · " + escapeHtml(o.contact) : ""}</div>
      <div class="a" style="margin:6px 0;">${escapeHtml(o.message)}</div>
      <div class="actions">
        <select data-out-status="${o.id}">
          ${Object.entries(OUTREACH_STATUS_LABELS).map(([k, v]) => `<option value="${k}" ${k === o.status ? "selected" : ""}>${v}</option>`).join("")}
        </select>
        <button class="ghost" data-out-del="${o.id}">Remove</button>
      </div>
    </div>
  `).join("");

  list.querySelectorAll("[data-out-status]").forEach(sel => sel.addEventListener("change", async () => {
    const o = state.outreach.find(x => x.id === sel.dataset.outStatus);
    o.status = sel.value;
    await saveVault();
    renderOutreachLog();
  }));
  list.querySelectorAll("[data-out-del]").forEach(b => b.addEventListener("click", async () => {
    state.outreach = state.outreach.filter(o => o.id !== b.dataset.outDel);
    await saveVault();
    renderOutreachLog();
  }));
}

/* ---------------- change password ---------------- */

document.getElementById("changePwBtn").addEventListener("click", async () => {
  const p1 = document.getElementById("newPw1").value;
  const p2 = document.getElementById("newPw2").value;
  const statusEl = document.getElementById("changePwStatus");
  if (!p1 || p1.length < 6) return statusEl.textContent = "New password must be 6+ characters.";
  if (p1 !== p2) return statusEl.textContent = "Passwords don't match.";

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newKey = await deriveKey(p1, newSalt);
  const check = await encryptJSON({ ok: true }, newKey);
  const payload = await encryptJSON(state, newKey);
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ salt: b64(newSalt), check, ...payload }));
  cryptoKey = newKey;

  document.getElementById("newPw1").value = "";
  document.getElementById("newPw2").value = "";
  statusEl.textContent = "Password updated ✓ — your data is safe, nothing was lost.";
  setTimeout(() => statusEl.textContent = "", 3000);
});

/* ---------------- utils ---------------- */

/* ---------------- salary / start date rules ---------------- */
/* Deterministic answers to two questions that don't need AI judgment. */

function nextMonday(fromDate = new Date()) {
  const d = new Date(fromDate);
  const day = d.getDay(); // 0 = Sun, 1 = Mon, ... 6 = Sat
  const daysUntilNextMonday = ((8 - day) % 7) || 7; // always strictly the *next* Monday, even if today is Monday
  d.setDate(d.getDate() + daysUntilNextMonday);
  return d.toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" });
}

function guessTopSalaryFromText(text) {
  if (!text) return null;
  // Matches things like $95,000, $95k, $95,000 - $120,000, 95k-120k, etc.
  const matches = [...text.matchAll(/\$?\s?(\d{2,3}(?:,\d{3})?)\s?(k|,000)?/gi)];
  let top = null;
  for (const m of matches) {
    let num = parseFloat(m[1].replace(/,/g, ""));
    if (!num || num < 20) continue; // filter out noise (years, percentages, etc.)
    if (m[2] && m[2].toLowerCase() === "k") num *= 1000;
    else if (num < 1000) num *= 1000; // bare "95" near salary context is almost always "$95k"
    if (num > 15000 && num < 2000000) {
      if (top === null || num > top) top = num;
    }
  }
  return top ? `$${Math.round(top).toLocaleString()}` : null;
}

function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
