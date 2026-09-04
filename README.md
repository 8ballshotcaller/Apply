# Job Hub

A private, password-protected job search + application tracker you host yourself for free on GitHub Pages.

## What it does
- **Password-locked vault** — your profile, resume text, saved answers, and tracker are encrypted in your browser (AES-GCM, key derived from your password via PBKDF2) and stored only in that browser's local storage. Nothing is on a server.
- **Fill once, reuse everywhere** — resume text, contact info, and answers to common application questions ("Why do you want to work here?", "Are you authorized to work in the US?", etc.) are saved once and pulled into a **Prep Sheet** for any job you look at.
- **Job search** across:
  - **Greenhouse** and **Lever** boards for specific companies you add (both have free, public, no-key-required job APIs)
  - **RemoteOK** and **Remotive** (free public remote-job aggregator APIs)
  - **Adzuna** (optional — free API key, aggregates a huge range of boards)
- **Tracker** — saved → applied → interview → offer/rejected, with notes.

## What it deliberately does NOT do
- It does not scrape or auto-submit on **LinkedIn or Indeed**. Neither offers a public API for this anymore (Indeed shut down its Publisher API in 2023–24), and both explicitly prohibit automated scraping/applying in their terms — real risk of account bans and, in LinkedIn's case, has led to actual legal action against scraping tools.
- For jobs you find on LinkedIn/Indeed/a company's own careers page, use **Sources → "Add a manually-found job"**: paste the title/company/link, and the Prep Sheet still gives you your ready-to-paste answers. You click submit on the real site yourself.
- It does not try to disguise applications as anything other than what they are: you, applying, with your own saved answers in front of you. There's no way to make a submission "invisible" to an employer's hiring software, and a tool that tried would just be lying to the company on your behalf — not something worth the risk to your reputation or your applications.

## Setup (5 minutes)

1. Create a new **public or private** GitHub repo.
2. Add `index.html` and `app.js` from this project to the repo root.
3. Go to **Settings → Pages**, set source to your default branch, root folder. Save.
4. Wait ~1 minute, then visit the URL GitHub gives you (`https://yourusername.github.io/reponame/`).
5. First visit: set a password. **Write it down somewhere safe — there is no recovery.** If you lose it, use "Wipe all data" and start over.

> If your repo is public, anyone with the link can reach the *login screen* — but without your password they cannot decrypt anything. If you want extra peace of mind, make the repo **private** and enable GitHub Pages for private repos (available on GitHub Pro/Team/Enterprise), or just keep the URL to yourself.

## Adding companies (Greenhouse / Lever)

Open a company's careers page:
- `boards.greenhouse.io/COMPANYNAME` → token is `companyname`
- `jobs.lever.co/COMPANYNAME` → token is `companyname`

Add that token in the **Sources** tab.

## Adding Adzuna (optional, broadens coverage a lot)

1. Register free at https://developer.adzuna.com/
2. You'll get an `app_id` and `app_key`.
3. (Not wired to the UI form yet — see `app.js` → `fetchAdzuna`, add a small form in Sources if you want this, or ask your dev tool of choice to wire it up; the fetch function is ready to go.)

## Security notes
- Encryption key is derived from your password and never stored anywhere.
- Data never leaves your browser except the read-only calls to the job-board APIs above (those only send your search keywords, not your resume or answers).
- Use **Settings → Export encrypted backup** occasionally — it's still encrypted, safe to store in Drive/Dropbox, and lets you restore on another device (Import) or after clearing browser data.
- This is client-side security, not military-grade — anyone with your password (or unrestricted access to your unlocked browser tab) can see everything. Treat the password like any other important password.

## Limitations to know about
- Greenhouse/Lever only surface jobs at companies that use those ATSs — add every company you're targeting individually for the most complete coverage.
- RemoteOK/Remotive skew toward remote/tech roles.
- No tool can guarantee "no auto-reject" — that depends entirely on how well your resume/answers match each posting, not on anything technical.
