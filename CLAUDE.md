# Project memory — Resume-Database

**This file is the locked baseline as of 2026-05-20.** Any AI agent (Claude or
otherwise) opening this repo must read this file before making code changes.
The goal of this document is to keep the visual structure, security model,
and route surface stable while still allowing new features to be added — new
work must **blend in** with the existing patterns, not restructure them.

> **Snapshot tag:** `stable-2026-05-20` points at the commit that defines the
> "as of today" baseline. Use `git diff stable-2026-05-20...HEAD` to see
> everything that has changed since then.

> **Lock enforcement:** the baseline is enforced by three things working
> together — this file (rules), `scripts/verify-baseline.py` (machine check
> of those rules), and `.git/hooks/pre-commit` (refuses commits that
> violate the rules). One-time install of the hook after cloning:
>
> ```bash
> sh scripts/install-hooks.sh
> ```
>
> Deploy with the safe wrapper instead of `git push` directly:
>
> ```bash
> sh scripts/safe-deploy.sh
> ```
>
> Intentional baseline changes require updating **both** this file AND
> `scripts/verify-baseline.py` in the same commit. Bypass paths:
> `git commit --no-verify` (WIP only), `FORCE=1 sh scripts/safe-deploy.sh`
> (deploy only after the baseline update).

---

## 1. What this app is

A Flask-based applicant tracking + staff directory for TransCrypts.

- **Hosting:** Render.com (web service auto-deploys on push to `main`)
- **Database:** Supabase Postgres in production, SQLite for local dev
  (selected by `DATABASE_URL` env var; see `db.py`)
- **File storage:** Supabase Storage in production, local `uploads/` for dev
  (`storage.py`)
- **Domain:** none — accessed via `resume-database-ocwa.onrender.com`

The repo is at https://github.com/SyedHZRizvi/Resume-Database.

---

## 2. Hard rules — do NOT change without explicit user request

These are the things that "lock the state". Do not touch them unless the user
asks for that specific change by name.

### 2.1 Visual structure (the navbar pattern)

Every page that has a top navbar uses this exact pattern:

- Bootstrap 5.3.2 + Bootstrap Icons 1.11.3 (loaded via jsdelivr CDN)
- `<nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">`
- Brand on the left: TransCrypts logo (the `tc-logo` block — never modify)
- All actions on the right are **icon-only square buttons** using the class
  `tc-nav-icon` (see `static/css/style.css`). They use the Bootstrap variants
  `btn-outline-light`, `btn-light`, `btn-home`, or `btn-danger`. Text labels
  live in `data-bs-toggle="tooltip"` + `title="…"`.
- Tooltips are styled with `customClass: 'tc-tooltip'` and auto-placed to
  the **side** of the button (right if the button is in the left half of
  the viewport, left if it's in the right half). Do not move them below or
  above — the macOS pointer-hand obscures bottom-placed tooltips.
- The "Super Admin" / role-name badge has been **deliberately removed** from
  every navbar. Show only `session.full_name` next to the user icon. Do
  not re-add the role badge to any navbar.

When adding a new button to the navbar:
- Use `class="btn btn-outline-light tc-nav-icon" data-bs-toggle="tooltip"
  data-bs-placement="bottom" title="What it does"` and an `<i class="bi
  bi-…"></i>` child.
- Match the icon to the action; pick from Bootstrap Icons.
- Place it according to permission gates that already exist
  (`{% if can_audit %}`, `{% if can_users %}`, `{% if can_add %}`, etc.).

### 2.2 Security baseline — do not weaken any of these

1. **RLS enabled** on all 6 public tables (applicants, users, audit_log,
   interviews, staff, indeed_poll_status). The migration runs in
   `init_db()` and is idempotent.
2. **CSRF protection** is on every state-changing route via `flask-wtf`'s
   `CSRFProtect`. **Every `<form method="POST">` must contain
   `{{ csrf_token() }}`** as a hidden input. Every `fetch()` call to a
   same-origin POST route must send the `X-CSRFToken` header — the
   `csrf-shim` script in each template handles this automatically via the
   `<meta name="csrf-token">` tag. Don't remove either.
   - Exceptions (CSRF-exempt): `/api/careers/apply`, `/api/indeed/import`.
     These are public, API-key authenticated. Use `@csrf.exempt`.
3. **Rate limit on `/login`:** 10/min and 100/hour per IP. Don't remove the
   `@limiter.limit('10/minute;100/hour', methods=['POST'])` decorator.
4. **Generic login error:** every failure path (unknown user, locked,
   wrong password) must return the same `_GENERIC_LOGIN_ERROR` string. Do
   not re-introduce username enumeration or "N attempts remaining"
   messages — those leak valid usernames.
5. **Default admin creation** is gated on `os.environ.get('ALLOW_DEFAULT_ADMIN')
   == '1'` when `DATABASE_URL` is set. Don't loosen this. New deployments
   must provision their first admin manually.
6. **Session cookies:** `HttpOnly`, `SameSite=Lax`, and `Secure` in prod.
   Don't drop any of these flags.
7. **Security headers** on every response (`Strict-Transport-Security`,
   `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: same-origin`, `Permissions-Policy` locks
   geo/mic/camera). Set in the `_add_security_and_cors_headers` after-
   request hook. Don't remove any.
8. **CORS** is scoped to `/api/careers/` and `/api/indeed/` only. Don't
   widen it.
9. **Audit-log Postgres trigger** (`audit_log_no_update`) prevents
   `UPDATE` and `DELETE` on `audit_log`. Don't remove the trigger from
   `init_db()`. If a future feature seems to need to modify a past
   audit row, the right answer is to insert a new corrective row instead.
10. **Resume serving** — HR needs to PREVIEW resumes in the browser, so
    PDFs and images (extensions in `RESUME_INLINE_EXTENSIONS`) render
    INLINE by default. DOC/DOCX (which the browser cannot render anyway)
    still force a download. Any caller can append `?download=1` to force
    the download path for any format. Staff documents (contracts/IDs/
    visas) remain forced-download regardless of format — see §2.5.
11. **Human-saved applicant names are sacred** — the
    `_auto_reanalyze_on_startup()` background task may NEVER overwrite a
    non-empty applicant name with whatever the AI re-parse returns. It
    only overwrites when the stored value is empty or one of the
    placeholder strings (`'Please Edit Name'`, `'Unknown'`, `'N/A'`,
    `'-'`). Previously the task tested the existing name with
    `_looks_like_name()` and replaced any single-word name like "Saha"
    or "Madonna" with a section heading like "Client Relationship
    Management" extracted by Claude. The human edit wins — full stop.
12. **Misparsed applicant names auto-repair on startup** — alongside
    the auto-reanalyze, `_cleanup_misparsed_applicant_names()` runs as
    a one-shot startup task. It detects stored names that fail
    `_looks_like_real_name()` (the strict job-title / section-heading
    blacklist) and either rescues them by re-extracting from
    `parsed_text` via `_extract_name_from_resume_text()`, or flags
    them as `'Please Edit Name'` if no plausible alternative is found.
    Idempotent: a row whose name already passes the validator is
    never touched.

    The extractor uses **email-token matching** as its primary signal:
    if the candidate's email is `aneesh.saha@…`, then a candidate
    line "ANEESH SAHA" matches and "CORE AREAS" does not. Each
    matching token is worth +5; Title Case is +2; top-of-resume
    position is +1; multi-word ALL CAPS lines get -3. The winning
    line must have a strictly positive score — otherwise the record
    is flagged for manual review. This is the layer that defends
    against section headings that happen to satisfy the simple
    "looks like a name" word-token rules.

### 2.3 Role / permission model

Defined in `app.py` near the top:

```
CAN_VIEW     = super_admin, hr_manager, recruiter, hiring_manager, viewer
CAN_ADD      = super_admin, hr_manager, recruiter
CAN_EDIT     = super_admin, hr_manager, recruiter
CAN_NOTES    = super_admin, hr_manager, recruiter, hiring_manager
CAN_DELETE   = super_admin, hr_manager
CAN_DOWNLOAD = super_admin, hr_manager, recruiter, hiring_manager
CAN_AUDIT    = super_admin, hr_manager
CAN_STAFF    = super_admin, hr_manager
CAN_USERS    = super_admin
CAN_SHUTDOWN = super_admin
```

New routes must use `@role_required(*CAN_…)` matching the right group.
Never `@app.route` without a role decorator unless the route is a public
API like `/api/careers/apply`.

### 2.4 Staff directory schema

The `staff` table now has these columns (post-2026-05-21):

```
id, name, email, designation, department,
company_property,         -- comma-separated text, rendered as tc-property-badge chips
notes,                    -- free text, HR-only (CAN_STAFF)
start_date,               -- ISO yyyy-mm-dd, joining date
employment_status,        -- enum: 'Active' | 'On Leave' | 'Exited'  (default 'Active')
manager_id,               -- INTEGER, FK to staff.id (self-reference); NULL allowed
date_of_birth,            -- ISO yyyy-mm-dd, HR-only PII
emergency_contact_name,   -- free text, HR-only PII
emergency_contact_phone,  -- free text, HR-only PII
created_at
```

The Add Staff form and the Edit modal both show quick-pick chips
(`tc-property-chips` + `tc-chip`) for common items: Access Card, Laptop,
Mouse, Keyboard, Phone, Headset, Monitor, Charger. Clicking a chip toggles
the item in the comma-separated `company_property` input. Free-text
additions are also supported. Do not remove the chip UI; if you add a new
common item, add it as another chip in **both** the add form and the edit
modal so they stay in sync.

**Sensitive / PII fields** — `notes`, `date_of_birth`,
`emergency_contact_name`, `emergency_contact_phone` — are rendered only
when `can_staff` is truthy. The `start_date`, `employment_status` and
`manager_id` columns are NOT sensitive and may be shown to anyone with
`CAN_VIEW` access.

**Employment status** is a controlled enum. The list lives in two places
that must stay in sync:
  • `EMPLOYMENT_STATUS_VALUES = ('Active', 'On Leave', 'Exited')` in app.py
  • The `<select>` in the Add Staff form **and** the Edit modal in
    templates/staff.html (rendered from `employment_status_values` passed
    via the staff_list route context).
The colored status badges in the directory table use the CSS classes
`.tc-status-active`, `.tc-status-on-leave`, `.tc-status-exited` (in
static/css/style.css). Adding a new status requires updating the enum,
the form select, AND a new `.tc-status-<slug>` CSS rule.

**Manager (self-reference)** — `manager_id` may not equal the row's own
`id`. The backend route `_validate_manager_id()` enforces this; the
frontend `openEdit()` hides the self-option from the dropdown so HR can't
even select it. When a staff row is deleted, any other row that listed
that person as `manager_id` is automatically NULLed out by `staff_delete`
to prevent dangling references.

### 2.5 Staff documents (contracts / IDs / visas)

A separate `staff_documents` table holds HR file uploads per staff
member. Sensitive — every route is `@role_required(*CAN_STAFF)`:

```
staff_documents:
  id, staff_id (FK → staff.id),
  category,          -- enum from STAFF_DOC_CATEGORIES (default 'Other')
  original_name,     -- as uploaded
  stored_filename,   -- 'staff-docs/<staff_id>/<timestamp>_<safe>.ext'
  content_type, size_bytes,
  expiry_date,       -- optional ISO yyyy-mm-dd; drives the modal's
                     -- expired/expiring-soon colour badges
  uploaded_by, uploaded_at
```

Files are stored via the shared `storage.py` module — same Supabase
bucket as resumes, but under the path prefix `staff-docs/<staff_id>/`.
Local-dev backend uses the same `uploads/` directory.

**Categories** — `STAFF_DOC_CATEGORIES = ('Contract', 'ID', 'Visa',
'Passport', 'Tax Form', 'Certificate', 'NDA', 'Other')`. The list is
rendered as a single-select chip group (reuses `.tc-chip` styling with
a hidden input). Adding a category requires updating the constant in
app.py AND the icon-mapping in templates/staff.html.

**Download must be Content-Disposition: attachment** — the verifier
asserts this for both the local backend (`Response` with
`Content-Disposition: attachment`) and the Supabase backend (signed URL
with `download=1`). The same rule that protects resumes from inline
HTML-as-PDF execution applies here.

**Cascade on staff deletion** — `staff_delete` calls
`_purge_staff_documents(conn, staff_id)` before removing the row. It
best-effort deletes every file from storage and removes the rows. If a
storage deletion fails, the file becomes an orphan (logged), but the DB
stays consistent.

### 2.6 Office supplies inventory

A lightweight HR/ops tool for tracking office consumables (paper, toner,
coffee, sanitiser, etc.). Lives in two tables:

```
supplies:
  id, name, category, unit, current_qty, reorder_threshold,
  preferred_vendor, last_restocked_at, notes,
  active        -- 1 = visible in the list, 0 = soft-deleted
  created_at

supply_movements:
  id, supply_id (FK → supplies.id),
  delta          -- signed integer (negative for Consumed, positive for Restock)
  reason         -- enum from SUPPLY_MOVEMENT_REASONS (default 'Adjustment')
  note           -- free text
  staff_username -- who made the change
  created_at
```

**Categories** — `SUPPLY_CATEGORIES = ('Stationery', 'Pantry', 'Cleaning',
'IT', 'Other')`. **Reasons** — `SUPPLY_MOVEMENT_REASONS = ('Restock',
'Consumed', 'Adjustment')`. Both enums are rendered as single-select
chip groups in templates/supplies.html and **must stay in sync** — adding
a new category requires updating the tuple in app.py AND adding a chip
with a matching icon in the template (Add card, filter bar, AND Edit
modal). Adding a new reason requires updating the tuple AND a chip in
the Adjust modal AND a matching `.tc-move-<slug>` colour rule.

**Role gate** — every route (`/supplies`, `/supplies/add`,
`/supplies/<id>/edit`, `/supplies/<id>/adjust`, `/supplies/<id>/delete`,
`/supplies/<id>/history`) is `@role_required(*CAN_STAFF)`. The page is
not visible to recruiters / viewers / hiring managers.

**Navbar entry** — a `bi-boxes` icon button on the home dashboard
(templates/index.html), placed between Staff Directory and Audit Log,
gated by `{% if can_staff %}`. (The `can_staff` flag is exposed by the
global context processor — added alongside this feature.) Sub-pages
have a Home icon and Sign Out icon following the staff.html pattern;
no other navbars carry the supplies entry.

**Soft-delete** — `/supplies/<id>/delete` flips `active=0` and never
issues a SQL `DELETE`. This keeps every historical `supply_movements`
row interpretable and preserves the audit trail. There is no "restore"
UI today — once soft-deleted the row is hidden from the list.

**Low-stock cue** — when `current_qty <= reorder_threshold` the row
shows a red pill (`.tc-stock-low`) with the warning icon, and these
rows sort first in the table. Otherwise it shows the muted green
`.tc-stock-ok` indicator. The list page header also surfaces a count
of low-stock items.

**Sign rules in /adjust** — Consumed always stores a negative delta,
Restock always stores a positive delta, Adjustment keeps whatever sign
the user typed. The route normalises this server-side so a tampered
form cannot, for example, register a "Consumed +5" that increases
stock. `current_qty` is clamped at zero (never negative).

**Restock side-effect** — when `reason == 'Restock'` the route updates
`supplies.last_restocked_at` to the current local timestamp. The Add
form also records an opening-stock Restock movement on day one when the
starting quantity is non-zero.

### 2.7 AI bundle — skills auto-tag, interview Q&A, semantic dedup

Three related AI-powered features that share the Anthropic client and the
`applicants` table. Implemented together; treat them as one slice.

**Applicant columns (added 2026-05-21):**

```
applicants.skills_tags           -- JSON-encoded list of normalised skill
                                 -- chips (5–15 short strings). Empty string
                                 -- when no tags are known. Rendered as
                                 -- .tc-skill-chip pills on view_resume.html
                                 -- and powers the "Filter by AI skill chip"
                                 -- live input on the applicants list.
applicants.identity_fingerprint  -- Normalised "name|specialty|education|year"
                                 -- token built by _build_identity_fingerprint().
                                 -- Compared pairwise via difflib.SequenceMatcher
                                 -- on the dedup page (Feature 3). Empty
                                 -- string when the row hasn't been backfilled
                                 -- yet — the dedup page lazily backfills
                                 -- every visit.
```

**PARSE_PROMPT contract addition** — the JSON schema sent to Claude now
includes a `skills_array` key alongside the existing legacy keys (name,
email, phone, specialty, years_experience, highest_education, skills, notes,
linkedin_url, github_url). `skills_array` is a JSON array of 5–15 short tags
(e.g. `["Python", "PostgreSQL", "Team Lead"]`). The /parse-resume route
normalises this server-side (trim, dedupe case-insensitively, cap at 20)
and surfaces both `skills_array` (list) AND `skills_tags` (JSON string) in
the response. The add/edit forms keep both in sync via a hidden input;
server falls back to splitting the comma-separated `skills` field when the
hidden input is missing or malformed.

**`/api/ai/interview-questions` route (Feature 2):**
  • Method: POST, JSON body `{applicant_id, position_override?}`.
  • Role gate: `@role_required(*CAN_NOTES)` — same group that records
    interviews (super_admin, hr_manager, recruiter, hiring_manager).
  • Rate limit: `@limiter.limit('20/hour;100/day')` to cap Anthropic spend
    per signed-in user. **Do not relax** — the AI charge per call is real
    money.
  • NOT @csrf.exempt — the existing csrf-shim sends the X-CSRFToken header.
  • Validates the model response: must be a JSON object with a `questions`
    list of 5–15 strings; anything else returns
    `{ok:false, message:"AI response was unparseable, please try again"}`.
  • Logged via `log_action('AI INTERVIEW QUESTIONS', ...)` so spend is
    auditable.

**Semantic dedup approach (Feature 3)** — intentionally heuristic, NOT an
ML/embeddings approach. Keep it that way:
  • `_build_identity_fingerprint(name, specialty, notes, highest_education)`
    returns a lowercased, alphanumeric-only `"name|specialty|education|year"`
    token. Year hint is the first 4-digit 19xx/20xx in `notes`.
  • `_find_semantic_dupes()` walks every applicant pairwise and surfaces
    pairs with `difflib.SequenceMatcher.ratio() >= 0.85`. Excludes IDs
    already flagged by the existing hash-based detection. Capped at top
    50 clusters by score so the page stays fast even on a large pool.
  • Persistent dismissals live in the new `duplicate_dismissals` table
    `(id, applicant_a, applicant_b, dismissed_by, dismissed_at)` with a
    UNIQUE index on `(applicant_a, applicant_b)` — pairs are always
    stored low-id-first so a swap doesn't break dedup.
  • The dismiss form posts to `/admin/dismiss-semantic-dup` which is
    `@role_required(*CAN_USERS)` (same gate as the dedup page itself).
  • Threshold and cluster cap live as module-level constants:
    `_SEMANTIC_DEDUP_THRESHOLD = 0.85` and `_SEMANTIC_DEDUP_MAX_CLUSTERS = 50`.

**No new dependencies** — `difflib` is stdlib. The Anthropic client is the
same one /parse-resume already uses. Do not add `sklearn`, embeddings,
vector databases, or any other ML stack for this feature.

---

## 3. Design tokens — match these when adding new UI

| Token | Value | Where |
|-------|-------|-------|
| Primary green | `#6DC49A` | brand, success buttons, active chips |
| Dark slate (tooltips, headings) | `#1f2937` | `.tc-tooltip` |
| Property-badge bg / border | `#ecfdf5` / `#d1fae5` | `.tc-property-badge` |
| Chip border idle / hover | `#cbd5e1` / `#6DC49A` | `.tc-chip` |
| Card | `card border-0 shadow-sm` | every content card |
| Table | `table table-hover align-middle` | every list table |
| Modal | `modal-dialog modal-dialog-centered` | every modal |
| Form sizing on dense pages | `form-control-sm` | add-staff form |
| Form sizing in modals | `form-control` (regular) | edit modals |

Use Bootstrap Icons (`bi bi-…`) for everything. Don't pull in Font Awesome
or another icon set.

Spacing between navbar icon buttons: `margin-left: 6px` on `.tc-nav-icon`
plus the parent's `gap-2`. Don't change either without a deliberate UX
reason.

---

## 4. How to add a new feature without breaking the lock

1. **Database changes** go in `init_db()` in `app.py` using `ALTER TABLE
   IF NOT EXISTS`-style idempotent patterns (wrap each ALTER in
   `try/except`). Never edit the existing `CREATE TABLE` blocks — only
   add ALTER migrations after them so existing deployments upgrade
   smoothly.
2. **New routes** use `@role_required(*CAN_…)` and the existing form
   patterns. Every form needs `{{ csrf_token() }}`.
3. **New columns in an existing table view** go at the *end* of the table
   header/body rows so existing column order doesn't shift unless asked.
4. **New navbar buttons** go between existing buttons following the same
   icon-only + tooltip pattern. Don't add text-label buttons to the nav.
5. **New pages** must follow the navbar pattern from §2.1 and include the
   CSRF meta tag + fetch shim + tooltip-init script at the bottom (copy
   from any existing template).
6. **Run the baseline verifier before pushing.** Any drift from the
   invariants in this file (CSRF on every form, RLS migration intact,
   navbar still icon-only, security headers still emitted, no
   reintroduced enumeration messages, etc.) is caught here:
   ```bash
   python3 scripts/verify-baseline.py
   ```
   Exit code 0 → safe to push. Non-zero → the script tells you exactly
   which rule drifted and what file/string it was looking for. If the
   change is intentional (the user asked for it), update **both** this
   file (CLAUDE.md) AND the check in `scripts/verify-baseline.py` in
   the same commit, then re-run until it passes.
7. **Syntax sanity check** (optional, faster):
   ```bash
   python3 -c "
   import jinja2, os
   env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'), autoescape=True)
   for n in sorted(os.listdir('templates')):
       if n.endswith('.html'): env.parse(open(f'templates/{n}').read())
   import py_compile; py_compile.compile('app.py', doraise=True)
   print('OK')
   "
   ```
8. **Deploy verification:** after `git push origin main`, poll the live
   site (`https://resume-database-ocwa.onrender.com`) for ~90 seconds.
   The deploy is live when newly added CSS/HTML appears.

---

## 5. Things explicitly NOT to do unless asked

- Don't add a custom domain or Cloudflare proxy (user has explicitly
  said no domain for now).
- Don't migrate hosting away from Render — the user evaluated
  Cloudflare and chose to stay.
- Don't rewrite the app in another language or framework.
- Don't add new dependencies unless the feature requires it; the
  `requirements.txt` is intentionally lean.
- Don't introduce a base template / Jinja inheritance refactor.
  Templates currently each have their own `<html>` shell — that's the
  intentional baseline. New templates copy the pattern.
- Don't add tracking, analytics, or third-party scripts.
- Don't change the green-on-white brand palette.

---

## 6. Glossary of TransCrypts-specific terms

- **Applicant** — a job candidate whose resume is in the DB (table:
  `applicants`).
- **Staff** — internal employees of TransCrypts, used as interviewer
  autocomplete and now also for offboarding property tracking (table:
  `staff`).
- **Indeed inbox** — incoming candidate emails from Indeed that are
  auto-polled and converted to applicant rows.
- **Indeed bookmarklet** — a browser bookmarklet that scrapes a candidate
  off indeed.com and POSTs to `/api/indeed/import`.
- **Careers form** — public endpoint at `/api/careers/apply` for
  candidates applying through the marketing site.

---

*End of locked baseline. If you change anything in §2 (Hard Rules), update
the snapshot tag and amend this file in the same commit.*
