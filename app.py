"""
Resume Database Application
Run this file with Python to start the app: python app.py
Then open your browser at: http://localhost:5000
"""

from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, send_from_directory, jsonify, session
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import signal
import threading
import base64
import json
import secrets
import hashlib
import re
import hmac

# ── Anthropic API key resolution ───────────────────────────────────────────
# Priority 1: config.py (user-supplied key)
# Priority 2: ANTHROPIC_API_KEY environment variable
# Priority 3: Claude Code managed auth (ANTHROPIC_BASE_URL set by host, no key needed)
try:
    from config import ANTHROPIC_API_KEY as _cfg_key
    ANTHROPIC_API_KEY = _cfg_key if _cfg_key != 'your-api-key-here' else ''
except ImportError:
    ANTHROPIC_API_KEY = ''

# ── Login on/off switch + security settings ───────────────────────────────
# Lookup order:
#   1. config.py (local development, never deployed) — wins if it exists.
#   2. REQUIRE_LOGIN env var — explicit override on the host.
#   3. Auto-detect: if we're running on a managed cloud host (Render, Heroku,
#      Railway, Fly, etc.), login is forced ON. On localhost it stays OFF
#      so the developer doesn't have to log in every time they restart the
#      dev server. The signal we use is the presence of host-specific env
#      vars OR a real DATABASE_URL (no one runs Postgres locally for this
#      app — local dev is SQLite).
try:
    from config import REQUIRE_LOGIN as _require_login
    REQUIRE_LOGIN = bool(_require_login)
except ImportError:
    _env_login = (os.environ.get('REQUIRE_LOGIN') or '').strip().lower()
    if _env_login in ('1', 'true', 'yes', 'on'):
        REQUIRE_LOGIN = True
    elif _env_login in ('0', 'false', 'no', 'off'):
        REQUIRE_LOGIN = False
    else:
        _on_cloud_host = bool(
            (os.environ.get('DATABASE_URL') or '').strip() or
            os.environ.get('RENDER') or
            os.environ.get('RENDER_SERVICE_ID') or
            os.environ.get('RAILWAY_ENVIRONMENT') or
            os.environ.get('FLY_APP_NAME') or
            os.environ.get('HEROKU_APP_NAME') or
            os.environ.get('DYNO')
        )
        REQUIRE_LOGIN = _on_cloud_host

try:
    from config import SESSION_TIMEOUT_MINUTES as _stm
    SESSION_TIMEOUT_MINUTES = int(_stm)
except ImportError:
    SESSION_TIMEOUT_MINUTES = 30

try:
    from config import MAX_LOGIN_ATTEMPTS as _mla
    MAX_LOGIN_ATTEMPTS = int(_mla)
except ImportError:
    MAX_LOGIN_ATTEMPTS = 5

try:
    from config import PASSWORD_MIN_LENGTH as _pml
    PASSWORD_MIN_LENGTH = int(_pml)
except ImportError:
    PASSWORD_MIN_LENGTH = 8

if not ANTHROPIC_API_KEY:
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')

ANTHROPIC_BASE_URL  = os.environ.get('ANTHROPIC_BASE_URL', '')

# ── Email / office settings ───────────────────────────────────────────────
# Lookup order (each later step only used if the earlier returned a placeholder):
#   1. config.py (local development)
#   2. environment variable of the same NAME (production hosting like Render)
#   3. default
# This way the SAME codebase works locally (with config.py) and in the cloud
# (with env vars) without any code change.
def _cfg(name, default=''):
    try:
        import config as _c
        val = getattr(_c, name, None)
        if val not in (None, '', 'your-api-key-here',
                       'your-mail-password-or-bridge-password',
                       'hr@your-company.com'):
            return val
    except ImportError:
        pass
    return os.environ.get(name, default)

MAIL_SERVER          = _cfg('MAIL_SERVER',          'smtp.gmail.com')
MAIL_PORT            = int(_cfg('MAIL_PORT',         587))
MAIL_USERNAME        = _cfg('MAIL_USERNAME',         '')
MAIL_PASSWORD        = _cfg('MAIL_PASSWORD',         '')
MAIL_FROM            = _cfg('MAIL_FROM',             'TransCrypts HR <hr@transcrypts.com>')
COMPANY_NAME         = _cfg('COMPANY_NAME',          'TransCrypts')
OFFICE_ADDRESS       = _cfg('OFFICE_ADDRESS',        '160 Front Street West, Toronto, ON M5J 2X5')
OFFICE_FLOOR_ROOM    = _cfg('OFFICE_FLOOR_ROOM',     'Office 1820, 18th Floor')
OFFICE_CONTACT_NAME  = _cfg('OFFICE_CONTACT_NAME',  'Reception')
OFFICE_CONTACT_PHONE = _cfg('OFFICE_CONTACT_PHONE', '')


# ── Indeed inbox ingestion (IMAP) ─────────────────────────────────────────
# Read at request-time via _indeed_settings() so env-var changes on the host
# take effect without a code redeploy. The poll endpoint and admin page both
# go through that helper, so there's exactly one source of truth.
def _truthy(val, default=True):
    """Parse a string flag like 'true' / 'false' / '1' / '0' / 'yes' / 'no'."""
    if val is None or val == '':
        return default
    return str(val).strip().lower() in ('1', 'true', 'yes', 'on', 'y', 't')


def _indeed_settings():
    """Return the current Indeed-inbox config as a dict (never raises).

    Each call re-reads via _cfg(), so changing the env vars on Render and
    redeploying is enough — no code change needed. We never log or echo back
    the password value; the admin page only checks `is_configured`.
    """
    host    = (_cfg('INDEED_IMAP_HOST', '') or '').strip()
    user    = (_cfg('INDEED_IMAP_USER', '') or '').strip()
    pwd     = _cfg('INDEED_IMAP_PASSWORD', '') or ''
    folder  = (_cfg('INDEED_IMAP_FOLDER', 'INBOX') or 'INBOX').strip() or 'INBOX'
    use_ssl = _truthy(_cfg('INDEED_IMAP_USE_SSL', 'true'), default=True)
    try:
        port = int(_cfg('INDEED_IMAP_PORT', '993') or (993 if use_ssl else 143))
    except (TypeError, ValueError):
        port = 993 if use_ssl else 143
    domains_raw = (_cfg('INDEED_SENDER_DOMAINS',
                        'indeed.com,indeedemail.com') or '')
    domains = tuple(d.strip().lower() for d in domains_raw.split(',') if d.strip())
    if not domains:
        domains = ('indeed.com', 'indeedemail.com')
    token = (_cfg('INDEED_CRON_TOKEN', '') or '').strip()

    missing = []
    if not host: missing.append('INDEED_IMAP_HOST')
    if not user: missing.append('INDEED_IMAP_USER')
    # The password / token are also required for actual polling, but we
    # surface them as separate warnings so the admin page can be precise.
    missing_for_poll = list(missing)
    if not pwd:   missing_for_poll.append('INDEED_IMAP_PASSWORD')
    if not token: missing_for_poll.append('INDEED_CRON_TOKEN')

    return {
        'host':              host,
        'port':              port,
        'user':              user,
        'password':          pwd,
        'folder':            folder,
        'use_ssl':           use_ssl,
        'sender_domains':    domains,
        'cron_token':        token,
        'is_configured':     bool(host and user),
        'is_poll_ready':     bool(host and user and pwd and token),
        'missing':           missing,
        'missing_for_poll':  missing_for_poll,
    }


def _indeed_bookmarklet_settings():
    """Return the current Indeed bookmarklet config as a dict.

    The HR user drags a generated bookmarklet into their bookmarks bar; when
    clicked on a candidate's Indeed page the bookmarklet POSTs the scraped
    fields to /api/indeed/import using the API key baked in by the server.
    This helper centralizes config so both the admin page and the import
    endpoint read from a single source.

    Never raises; never echoes the key value into logs or flash messages.
    """
    key  = (_cfg('INDEED_BOOKMARKLET_KEY', '') or '').strip()
    base = (_cfg('PUBLIC_BASE_URL', '') or '').strip().rstrip('/')
    return {
        'api_key':       key,
        'public_base':   base,         # may be '' — caller falls back to request.url_root
        'is_configured': bool(key),
    }


# When Claude Code manages auth, the base URL is set and the key may be empty
CLAUDE_CODE_MANAGED = bool(os.environ.get('CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST', ''))
from datetime import datetime, timedelta

app = Flask(__name__)

# ── Persistent secret key ─────────────────────────────────────────────────
# Lookup order:
#   1. FLASK_SECRET_KEY env var (explicit override)
#   2. Derived from DATABASE_URL hash (stable per-deployment, survives
#      redeploys without anyone having to set FLASK_SECRET_KEY manually).
#      Safe because DATABASE_URL is itself a secret the host already protects.
#   3. .secret_key file in the app folder (local dev)
#   4. Auto-generate and persist (first local run)
_env_secret = os.environ.get('FLASK_SECRET_KEY', '').strip()
if _env_secret:
    app.secret_key = _env_secret
elif (os.environ.get('DATABASE_URL') or '').strip():
    # Production environment with a cloud Postgres. Hash the URL with a
    # constant app-specific salt to get a stable 64-char hex string. This
    # key is identical across redeploys of the same app (so sessions
    # survive deploys) but unique per environment (staging vs prod).
    import hashlib as _hashlib
    app.secret_key = _hashlib.sha256(
        (os.environ['DATABASE_URL'] + '|transcrypts-resume-db|v1').encode('utf-8')
    ).hexdigest()
else:
    _secret_key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
    if os.path.exists(_secret_key_file):
        with open(_secret_key_file, 'r') as _f:
            app.secret_key = _f.read().strip()
    else:
        _sk = secrets.token_hex(32)
        try:
            with open(_secret_key_file, 'w') as _f:
                _f.write(_sk)
        except OSError:
            pass
        app.secret_key = _sk

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif'}
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resumes.db')

# How long a "Remember Me" session lives in the browser cookie. The actual
# idle-timeout check still runs in before_request; this is just the upper
# bound that Flask will let the cookie survive. A full year keeps a
# developer's personal-laptop session essentially permanent — they log in
# once and the cookie covers them for a full year before it has to be
# renewed. Non-super_admin sessions still hit the 30-min idle timeout
# regardless, see login() and the before_request handler.
REMEMBER_ME_DAYS = 365
app.permanent_session_lifetime = timedelta(days=REMEMBER_ME_DAYS)

# ── TransCrypts logo for emails (loaded as raw bytes; sent as CID attachment) ──
# Gmail and most email clients block data: URIs, but CID (Content-ID) inline
# attachments are fully supported everywhere.  The bytes are attached to the
# MIME message and the HTML references them via  src="cid:transcrypts_logo".
_LOGO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'static', 'img', 'transcrypts_logo.png')
try:
    with open(_LOGO_PATH, 'rb') as _lf:
        _EMAIL_LOGO_BYTES = _lf.read()   # raw PNG bytes for CID attachment
except Exception:
    _EMAIL_LOGO_BYTES = None             # fallback: text logo used instead

# Prompt sent to Claude AI for resume parsing
PARSE_PROMPT = """You are an expert resume/CV parser. Carefully read the resume and extract information.
Return ONLY a valid JSON object with exactly these keys — no explanation, no markdown, just raw JSON:

{
  "name": "The applicant's real personal name — typically the LARGEST text at the very TOP of the resume, appearing before or alongside contact details. It is a human name like 'Ahmed Khan' or 'Sarah Johnson'. NEVER return a job title (e.g. 'Team Lead', 'Senior Engineer'), a section heading (e.g. 'Core Technical Skills', 'Work Experience'), a company name, a resume-builder watermark (e.g. 'ResumeAI', 'VisualCV'), or any text that is not the person's actual name. If you are not confident, return an empty string.",
  "email": "email address exactly as written, or empty string if not found",
  "phone": "phone number exactly as written, or empty string if not found",
  "specialty": "Primary job title or professional field (e.g. Software Engineering, Marketing, Finance & Accounting, Civil Engineering, Data Science)",
  "years_experience": 0,
  "highest_education": "exactly one of: High School Diploma | Associate Degree | Bachelor's Degree | Master's Degree | MBA | PhD / Doctorate | Professional Certification | Diploma / Vocational Training | Self-Taught — or empty string if unclear",
  "skills": "comma-separated list of key technical skills, tools and technologies found in the resume",
  "notes": "A 1-2 sentence professional summary of the candidate based on their resume content",
  "linkedin_url": "Full LinkedIn profile URL (e.g. https://linkedin.com/in/username) or empty string if not found",
  "github_url": "Full GitHub profile URL (e.g. https://github.com/username) or empty string if not found"
}

years_experience must be an integer (estimate from employment date ranges if not stated; use 0 for fresh graduates or students)."""

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32 MB max file size

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Role definitions ──────────────────────────────────────────────────────────
# Each role name maps to a human-readable label shown in the UI.
# The order here determines the dropdown order in user management.
ROLES = {
    'super_admin':    'Super Admin',
    'hr_manager':     'HR Manager',
    'recruiter':      'HR Recruiter',
    'hiring_manager': 'Hiring Manager',
    'viewer':         'Viewer (Read Only)',
}

# Permission groups — used by @role_required() decorator on each route.
# Instead of hardcoding role lists in every route, we define named groups here.
# This makes it easy to change who can do what — edit one line, not dozens.
CAN_VIEW     = ('super_admin', 'hr_manager', 'recruiter', 'hiring_manager', 'viewer')
CAN_ADD      = ('super_admin', 'hr_manager', 'recruiter')
CAN_EDIT     = ('super_admin', 'hr_manager', 'recruiter')
CAN_NOTES    = ('super_admin', 'hr_manager', 'recruiter', 'hiring_manager')
CAN_DELETE   = ('super_admin', 'hr_manager')
CAN_DOWNLOAD = ('super_admin', 'hr_manager', 'recruiter', 'hiring_manager')
CAN_AUDIT    = ('super_admin', 'hr_manager')
CAN_STAFF    = ('super_admin', 'hr_manager')   # Staff directory management
CAN_USERS    = ('super_admin',)
CAN_SHUTDOWN = ('super_admin',)


# ─── Production error logging ───────────────────────────────────────────────
# When the app is running on Render, default Flask returns the generic "500
# Internal Server Error" page with no detail visible to admins. This handler
# writes the full traceback to stdout (which Render captures in its logs)
# and includes a short error code in the response so we can correlate.
@app.errorhandler(500)
@app.errorhandler(Exception)
def _log_unhandled_exception(error):
    import traceback, sys, uuid
    err_id = uuid.uuid4().hex[:8]
    print(f'\n[ERROR {err_id}] Unhandled exception in {request.path}:',
          file=sys.stderr, flush=True)
    traceback.print_exc(file=sys.stderr)
    print(f'[ERROR {err_id}] end\n', file=sys.stderr, flush=True)
    # Re-raise non-HTTPExceptions so Flask returns a proper 500 page
    from werkzeug.exceptions import HTTPException
    if isinstance(error, HTTPException):
        return error
    return (f'<h1>500 Internal Server Error</h1>'
            f'<p>Reference: <code>{err_id}</code></p>'
            f'<p>Type: <code>{type(error).__name__}</code></p>'
            f'<p>Message: <code>{str(error)[:300]}</code></p>'), 500


@app.context_processor
def inject_globals():
    """Inject variables into EVERY template automatically.

    Programming concept — context processor:
    Instead of passing the same variables to render_template() in every single
    route, a context processor runs before every template render and injects
    variables globally. Every template can use these without the route needing
    to pass them explicitly.

    We inject:
    - require_login : bool — whether auth is on (controls navbar login menu)
    - user_role     : str  — current user's role (controls which buttons appear)
    - can_*         : bool — one flag per permission group, used in templates
                             to show/hide buttons like Add, Edit, Delete, etc.
    """
    role = session.get('user_role', '') if REQUIRE_LOGIN else 'super_admin'
    # In local mode (no login), treat the operator as super_admin so all
    # buttons appear. When login is on, use the actual signed-in role.
    return dict(
        require_login = REQUIRE_LOGIN,
        user_role     = role,
        # Permission flags — templates use these to show/hide UI elements
        can_add       = role in CAN_ADD,
        can_edit      = role in CAN_EDIT,
        can_notes     = role in CAN_NOTES,
        can_delete    = role in CAN_DELETE,
        can_download  = role in CAN_DOWNLOAD,
        can_audit     = role in CAN_AUDIT,
        can_users     = role in CAN_USERS,
        can_shutdown  = role in CAN_SHUTDOWN,
        ROLES         = ROLES,
        ROLE_LABEL    = ROLES.get(role, role),
    )


# ─── Database helpers ──────────────────────────────────────────────────────────
# Routed through db.py which auto-selects Postgres (production, when DATABASE_URL
# is set) or SQLite (local development). All existing conn.execute('… ?', (…,))
# code keeps working unchanged.
import db as _db
import storage as _storage

def get_db():
    return _db.get_db()


def init_db():
    with get_db() as conn:
        # ── Resumes ──────────────────────────────────────────────────────────
        conn.execute('''
            CREATE TABLE IF NOT EXISTS applicants (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT    NOT NULL,
                email            TEXT,
                phone            TEXT,
                specialty        TEXT    NOT NULL,
                years_experience INTEGER DEFAULT 0,
                highest_education TEXT,
                skills           TEXT,
                resume_filename  TEXT,
                notes            TEXT,
                date_added       TEXT    DEFAULT (datetime('now','localtime'))
            )
        ''')

        # ── Users ─────────────────────────────────────────────────────────────
        # failed_attempts: counts consecutive wrong passwords
        # locked_until:    datetime string — account is locked until this time
        # last_login:      last successful sign-in (shown in user management)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash   TEXT    NOT NULL,
                full_name       TEXT,
                role            TEXT    NOT NULL DEFAULT 'viewer',
                failed_attempts INTEGER DEFAULT 0,
                locked_until    TEXT,
                last_login      TEXT,
                created_at      TEXT    DEFAULT (datetime('now','localtime'))
            )
        ''')

        # On Postgres the COLLATE NOCASE on username is stripped (no equivalent).
        # We add a functional UNIQUE index on LOWER(username) so case-insensitive
        # uniqueness is still enforced — i.e. "admin" and "Admin" can't both exist.
        # On SQLite this same statement is a harmless no-op (it creates a normal
        # unique index on lower(username) which complements the existing one).
        try:
            conn.execute(
                'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower '
                'ON users (LOWER(username))'
            )
        except Exception:
            pass

        # ── Audit Log ─────────────────────────────────────────────────────────
        # Records every important action: who did what to which record and when.
        # This table is append-only — rows are never updated or deleted.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT DEFAULT (datetime('now','localtime')),
                username   TEXT,
                user_role  TEXT,
                action     TEXT,
                target     TEXT,
                details    TEXT
            )
        ''')

        # ── Interviews ────────────────────────────────────────────────────────
        # Each applicant can have multiple interview records.
        # One row = one interview session with one interviewer.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS interviews (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                applicant_id            INTEGER NOT NULL,
                interview_date          TEXT,
                interviewer_name        TEXT NOT NULL,
                interviewer_designation TEXT,
                outcome                 TEXT DEFAULT 'Pending',
                interview_notes         TEXT,
                created_at              TEXT DEFAULT (datetime('now','localtime')),
                FOREIGN KEY (applicant_id) REFERENCES applicants(id)
            )
        ''')

        # ── Staff directory table ────────────────────────────────────────────
        conn.execute('''
            CREATE TABLE IF NOT EXISTS staff (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                email       TEXT,
                designation TEXT,
                department  TEXT,
                created_at  TEXT DEFAULT (datetime('now','localtime'))
            )
        ''')

        # ── Migrate interviews table — new notification columns ─────────────
        for col, definition in [
            ('interview_time',     'TEXT'),
            ('interview_type',     "TEXT DEFAULT 'In-Person'"),
            ('interviewer_email',  'TEXT'),
            ('contact_person',     'TEXT'),
            ('meeting_link',       'TEXT'),
            ('interview_position', 'TEXT'),
        ]:
            try:
                conn.execute(f'ALTER TABLE interviews ADD COLUMN {col} {definition}')
            except Exception:
                pass

        # ── Migrate applicants table — all new columns ───────────────────────
        for col, definition in [
            ('hiring_status',     "TEXT DEFAULT 'Under Review'"),
            ('hire_date',         'TEXT'),
            ('rejection_reason',  'TEXT'),
            ('linkedin_url',      'TEXT'),
            ('github_url',        'TEXT'),
            ('interview_date',    'TEXT'),
            ('interview_time',    'TEXT'),
            ('interview_type',    "TEXT DEFAULT 'In-Person'"),
            ('interview_outcome', "TEXT DEFAULT 'Pending'"),
            ('decision_date',     'TEXT'),
            ('decision_notes',    'TEXT'),
            ('file_hash',         'TEXT'),
            # text_hash = MD5 of the normalized resume TEXT (lowercase, collapsed
            # whitespace). Lets us spot duplicates even when the bytes differ —
            # e.g. same resume re-exported with different metadata, or saved
            # from a different tool. file_hash catches byte-identical files;
            # text_hash catches content-identical ones.
            ('text_hash',         'TEXT'),
            # parsed_text = full plain-text extracted from the resume file.
            # Stored once so the "Find Best Matches" job-matcher can search
            # without re-reading + re-extracting every file on every query.
            # Populated lazily on the first /match-job visit and on every new
            # upload that already runs text extraction.
            ('parsed_text',       'TEXT'),
            # ── Career-website integration ────────────────────────────────────
            ('source',            "TEXT DEFAULT 'Manual Entry'"),
            ('applied_position',  'TEXT'),
            ('cover_letter',      'TEXT'),
        ]:
            try:
                conn.execute(f'ALTER TABLE applicants ADD COLUMN {col} {definition}')
            except Exception:
                pass  # Column already exists

        # ── Migrate existing users table (adds new columns to old databases) ──
        # SQLite doesn't support "ADD COLUMN IF NOT EXISTS" so we try each one.
        for col, definition in [
            ('failed_attempts',    'INTEGER DEFAULT 0'),
            ('locked_until',       'TEXT'),
            ('last_login',         'TEXT'),
            ('must_change_password','INTEGER DEFAULT 0'),
        ]:
            try:
                conn.execute(f'ALTER TABLE users ADD COLUMN {col} {definition}')
            except Exception:
                pass  # Column already exists — that's fine

        # ── Migrate old role names to new 5-role system ───────────────────────
        # Old 'admin' → 'super_admin'   |   Old 'user' → 'recruiter'
        conn.execute("UPDATE users SET role='super_admin' WHERE role='admin'")
        conn.execute("UPDATE users SET role='recruiter'   WHERE role='user'")

        # ── Indeed inbox poll status (single-row state table) ────────────────
        # Exactly one row (id=1) is kept and upserted on every poll. Lets the
        # admin page show "Last run: …, processed N, created N" without having
        # to scan the audit log.
        conn.execute('''
            CREATE TABLE IF NOT EXISTS indeed_poll_status (
                id         INTEGER PRIMARY KEY,
                last_run   TEXT,
                processed  INTEGER DEFAULT 0,
                created    INTEGER DEFAULT 0,
                duplicates INTEGER DEFAULT 0,
                errors     TEXT
            )
        ''')

        conn.commit()


def create_default_admin():
    """Create the default super_admin account on first run if no users exist."""
    with get_db() as conn:
        count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if count == 0:
            conn.execute('''
                INSERT INTO users (username, password_hash, full_name, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', generate_password_hash('admin123'), 'Administrator', 'super_admin'))
            conn.commit()
            print()
            print("   *** FIRST-TIME SETUP ***")
            print("   Default admin account created:")
            print("   Username : admin")
            print("   Password : admin123")
            print("   Please change the password after your first login!")
            print()


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def log_action(action, target='', details=''):
    """Write one row to the audit_log table.

    Programming concept — Audit trail:
    Every important action (add/edit/delete/login/logout/email) calls this.
    It records who did it, when, and what. Because it's a separate table that
    only ever gets rows appended (never deleted), it is tamper-evident.

    Logging happens ALWAYS, regardless of REQUIRE_LOGIN — when login is off
    the username is recorded as 'system'. This way email-delivery outcomes
    and admin actions are always visible on the Audit Log page.
    """
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit_log (username, user_role, action, target, details) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    session.get('username', 'system') if REQUIRE_LOGIN else 'system',
                    session.get('user_role', '')      if REQUIRE_LOGIN else 'super_admin',
                    action,
                    target,
                    details,
                )
            )
            conn.commit()
    except Exception:
        pass  # Never let audit logging crash the main application


def _has_role(*allowed_roles):
    """Return True if the current user has one of the given roles."""
    # Use the module-level REQUIRE_LOGIN — that variable already has a
    # safe fallback for environments where config.py isn't present
    # (e.g. Render, where settings come from env vars instead).
    if not REQUIRE_LOGIN:
        return True   # login off → all actions allowed
    return session.get('user_role') in allowed_roles


def role_required(*allowed_roles):
    """Decorator factory — protects a route so only certain roles can access it.

    Programming concept — Decorator factory:
    A regular decorator wraps one function. A decorator *factory* is a function
    that *returns* a decorator. This lets us pass arguments (the allowed roles).

    Usage:
        @role_required(*CAN_DELETE)         # only super_admin, hr_manager
        def delete_resume(applicant_id): ...

    When REQUIRE_LOGIN=False (local mode) the check is skipped entirely —
    every route is open, just like before authentication was added.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if REQUIRE_LOGIN:
                if 'user_id' not in session:
                    flash('Please sign in to access the Resume Database.', 'error')
                    return redirect(url_for('login', next=request.path))
                if session.get('user_role') not in allowed_roles:
                    log_action('ACCESS DENIED', request.path,
                               f'Role {session.get("user_role")} tried to access {request.path}')
                    flash('You do not have permission to do that.', 'error')
                    return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated
    return decorator


# Keep login_required as an alias — used on routes accessible by all roles
def login_required(f):
    return role_required(*CAN_VIEW)(f)


# ─── Session timeout (runs before every request) ──────────────────────────────
@app.before_request
def check_session_timeout():
    """Automatically sign out users who have been idle too long.

    Programming concept — before_request hook:
    Flask calls this function before EVERY route handler. We use it to check
    how long it has been since the user last did anything. If it's over the
    limit, we clear their session and redirect to login.

    'last_activity' is stored in the session (server-side cookie) and updated
    on every request, so it only counts idle time, not total logged-in time.
    """
    if not REQUIRE_LOGIN:
        return
    # Skip for login/logout pages and static files
    if request.endpoint in ('login', 'logout', 'static', None):
        return
    if 'user_id' not in session:
        return

    last = session.get('last_activity')
    if last:
        # "Remember Me" sessions get a much longer idle window — basically the
        # full cookie lifetime — so the user can leave the tab idle for a day
        # and come back without re-logging in. Sessions without Remember Me
        # still enforce the strict timeout for security on shared devices.
        if session.get('remember_me'):
            idle_limit_minutes = REMEMBER_ME_DAYS * 24 * 60
        else:
            idle_limit_minutes = SESSION_TIMEOUT_MINUTES
        idle_minutes = (datetime.now() - datetime.fromisoformat(last)).total_seconds() / 60
        if idle_minutes > idle_limit_minutes:
            username = session.get('username', '')
            session.clear()
            flash(f'You were automatically signed out after '
                  f'{SESSION_TIMEOUT_MINUTES} minutes of inactivity.', 'error')
            return redirect(url_for('login'))

    session['last_activity'] = datetime.now().isoformat()

    # ── Force password change for new / just-reset accounts ──────────────────
    # If the admin created this account (or reset the password), the
    # must_change_pw flag is set.  We block every page except the
    # change-password page itself until the user sets a proper password.
    if session.get('must_change_pw') and request.endpoint != 'change_password':
        flash('You are using a temporary password. Please set a new password to continue.', 'error')
        return redirect(url_for('change_password'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def make_unique_filename(original_filename):
    base, ext = os.path.splitext(secure_filename(original_filename))
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{base}_{timestamp}{ext}"


def _safe_int(value, default=0):
    """
    Coerce a value to int, returning `default` on any failure.
    SQLite silently accepts strings for INTEGER columns; Postgres errors
    with 'invalid input syntax for type integer'. This helper bridges
    that gap whenever a parsed-from-resume value is bound to an INT column.
    """
    if value is None or value == '':
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def compute_file_hash(file_obj):
    """Return the SHA-256 hex digest of an open file object.

    Programming concept — streaming hash:
    We read in 8 KB chunks rather than loading the whole file into memory at
    once.  This keeps memory usage constant even for large resume files.
    We seek(0) before AND after so the caller can still read the file later.
    """
    sha256 = hashlib.sha256()
    file_obj.seek(0)
    for chunk in iter(lambda: file_obj.read(8192), b''):
        sha256.update(chunk)
    file_obj.seek(0)
    return sha256.hexdigest()


def _normalize_resume_text(text):
    """Lowercase, strip, collapse whitespace, drop non-alphanumeric noise so
    that two resumes with identical content but different formatting / page
    breaks / soft hyphens still produce the same hash. This is intentionally
    aggressive — false negatives (missed dupes) are worse than false positives
    (manually reviewed dupes).
    """
    if not text:
        return ''
    import re
    s = text.lower()
    # Drop everything that isn't a letter, digit, @ (preserve emails), or space.
    s = re.sub(r'[^a-z0-9@ ]+', ' ', s)
    # Collapse all whitespace into single spaces.
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def compute_text_hash(raw_bytes, filename):
    """Return MD5 of the normalized text extracted from a resume file.

    Returns an empty string when extraction fails (scanned image with no OCR,
    corrupt PDF, etc.) — callers should treat empty as "skip text-hash dedup
    for this file" rather than as a real hash.
    """
    if not raw_bytes:
        return ''
    try:
        text = _extract_text_from_file(raw_bytes, (filename or '').lower())
    except Exception:
        return ''
    norm = _normalize_resume_text(text)
    if not norm or len(norm) < 50:
        # Too little extractable text to be a reliable identity signal.
        return ''
    return hashlib.md5(norm.encode('utf-8')).hexdigest()


def _read_file_bytes_from_field(file_obj):
    """Read the bytes from a Werkzeug FileStorage without losing position."""
    file_obj.seek(0)
    data = file_obj.read()
    file_obj.seek(0)
    return data


def parse_resume_bytes(raw_bytes, filename):
    """Run the standard extract + smart_parse pipeline on raw resume bytes.
    Returns a dict with name/email/phone/etc., never None."""
    if not raw_bytes:
        return {}
    try:
        text = _extract_text_from_file(raw_bytes, (filename or '').lower())
        if text and text.strip():
            return _smart_parse(text) or {}
    except Exception:
        pass
    return {}


# ─── Job-matching helpers ─────────────────────────────────────────────────────
# A small hard-coded English stopword set used by the keyword pre-filter
# in `/match-job`. Deliberately minimal — no NLTK / sklearn dependency.
_MATCH_STOPWORDS = {
    'the','a','an','and','or','but','if','then','else','of','in','on','at','to',
    'for','with','from','by','as','is','are','was','were','be','been','being',
    'have','has','had','do','does','did','will','would','could','should','may',
    'might','can','this','that','these','those','it','its','we','you','they',
    'i','our','your','their','his','her','him','them','us','me','my','mine',
    'who','what','which','when','where','why','how','not','no','nor','so','too',
    'very','just','also','about','into','than','because','while','during',
    'over','under','up','down','out','off','more','most','some','any','all',
    'each','every','other','another','same','such','only','own','here','there',
    'job','role','position','candidate','candidates','required','requirements',
    'responsibility','responsibilities','must','will','should','need','needs',
    'work','working','team','please','etc',
}


def _tokenize_job_description(text):
    """Lowercase, split on non-alphanumerics, drop stopwords + short tokens.
    Returns a deduplicated list of keyword tokens used for the cheap
    keyword-overlap pre-filter in /match-job."""
    if not text:
        return []
    import re as _re
    seen = set()
    tokens = []
    for raw in _re.split(r'[^a-zA-Z0-9+#.]+', text.lower()):
        tok = raw.strip('.+#')
        if not tok or len(tok) < 3:
            continue
        if tok in _MATCH_STOPWORDS:
            continue
        if tok in seen:
            continue
        seen.add(tok)
        tokens.append(tok)
    return tokens


def _score_applicant_keywords(applicant, tokens):
    """Cheap weighted keyword overlap score. Higher = better match."""
    if not tokens:
        return 0
    skills_blob    = (applicant.get('skills')      or '').lower()
    specialty_blob = (applicant.get('specialty')   or '').lower()
    parsed_blob    = (applicant.get('parsed_text') or '').lower()
    score = 0
    for tok in tokens:
        if tok in skills_blob:
            score += 3
        if tok in specialty_blob:
            score += 2
        if tok in parsed_blob:
            score += 1
    return score


def _ai_rerank_candidates(job_description, shortlist):
    """Ask Claude to re-rank up to 30 candidates and return top 10.

    Returns: (results_list, error_message)
      • results_list = [{'id', 'score', 'reasoning'}, ...]  ordered best-first
      • error_message = None on success, else short human-readable warning
    """
    if not shortlist:
        return [], None
    if not ANTHROPIC_API_KEY:
        return [], 'AI rerank is disabled (no Anthropic API key configured) — showing keyword matches only.'

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        # Build a compact candidate payload. Keep it small — 30 candidates
        # × ~600 chars each ≈ 18 KB, well within token budget.
        payload = []
        for a in shortlist:
            snippet = (a.get('parsed_text') or '')[:500]
            payload.append({
                'id':                a['id'],
                'name':              a.get('name') or '',
                'specialty':         a.get('specialty') or '',
                'years_experience':  a.get('years_experience') or 0,
                'highest_education': a.get('highest_education') or '',
                'skills':            a.get('skills') or '',
                'snippet':           snippet,
            })

        system_prompt = (
            "You are an expert technical recruiter. Given a job description and a "
            "JSON list of candidates, rank the candidates by how well they fit the "
            "job. Return ONLY a JSON array — no prose, no markdown, no code fences. "
            "Each element must be exactly: "
            '{"id": <integer>, "score": <0-100 integer>, "reasoning": "<1-2 short sentences>"}. '
            "Order best-first. Return at most 10 items. Score reflects overall fit: "
            "skills match, experience level, education, and specialty relevance."
        )

        user_prompt = (
            f"JOB DESCRIPTION:\n{job_description}\n\n"
            f"CANDIDATES (JSON):\n{json.dumps(payload, ensure_ascii=False)}\n\n"
            "Return the ranked JSON array now."
        )

        message = client.messages.create(
            model='claude-haiku-4-5-20251001',
            max_tokens=2000,
            system=system_prompt,
            messages=[{'role': 'user', 'content': user_prompt}],
        )
        raw = (message.content[0].text or '').strip()
        # Strip ``` fences if Claude adds them despite the instruction
        if raw.startswith('```'):
            raw = raw.split('```', 2)[1] if '```' in raw[3:] else raw[3:]
            if raw.startswith('json'):
                raw = raw[4:]
            raw = raw.strip().rstrip('`').strip()

        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return [], 'AI rerank returned an unexpected format — showing keyword matches only.'

        cleaned = []
        for item in parsed[:10]:
            if not isinstance(item, dict):
                continue
            try:
                cid = int(item.get('id'))
                cscore = int(item.get('score', 0))
            except (TypeError, ValueError):
                continue
            cscore = max(0, min(100, cscore))
            reasoning = str(item.get('reasoning') or '').strip()[:600]
            cleaned.append({'id': cid, 'score': cscore, 'reasoning': reasoning})
        if not cleaned:
            return [], 'AI rerank returned no valid items — showing keyword matches only.'
        return cleaned, None
    except Exception as e:
        return [], f'AI rerank unavailable ({type(e).__name__}). Showing keyword matches only.'


def find_identity_match(name='', email='', phone='', exclude_id=None):
    """Return an existing applicant row that looks like the SAME PERSON, or None.

    Match strategies (strongest first):
      1. Email exact match (case-insensitive) — almost certainly the same person.
      2. Name + phone exact match — same person who used a different email.

    We deliberately do NOT match on name alone because common names produce
    huge false-positive rates; "John Smith" applying twice is normal.
    """
    name  = (name or '').strip()
    email = (email or '').strip()
    phone = (phone or '').strip()

    with get_db() as conn:
        if email:
            q = ('SELECT id, name, email, phone, specialty, hiring_status, '
                 'date_added FROM applicants WHERE LOWER(email) = LOWER(?)')
            params = [email]
            if exclude_id is not None:
                q += ' AND id != ?'
                params.append(exclude_id)
            row = conn.execute(q, params).fetchone()
            if row:
                return dict(row)

        if name and phone:
            q = ('SELECT id, name, email, phone, specialty, hiring_status, '
                 'date_added FROM applicants '
                 'WHERE LOWER(name) = LOWER(?) AND phone = ?')
            params = [name, phone]
            if exclude_id is not None:
                q += ' AND id != ?'
                params.append(exclude_id)
            row = conn.execute(q, params).fetchone()
            if row:
                return dict(row)

    return None


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        next_url = request.form.get('next', '')

        with get_db() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ? COLLATE NOCASE', (username,)
            ).fetchone()

            if not user:
                flash('Incorrect username or password.', 'error')
                return render_template('login.html', next=next_url)

            # ── Check if account is currently locked ──────────────────────
            # locked_until is stored as an ISO datetime string.
            # If current time is still before locked_until, deny entry.
            if user['locked_until']:
                lock_time = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < lock_time:
                    remaining = max(1, int((lock_time - datetime.now()).seconds / 60) + 1)
                    flash(f'Account is locked after too many failed attempts. '
                          f'Please try again in {remaining} minute(s).', 'error')
                    return render_template('login.html', next=next_url)
                else:
                    # Lockout has expired — reset the counter automatically
                    conn.execute('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?',
                                 (user['id'],))
                    conn.commit()

            # ── Check password ────────────────────────────────────────────
            if check_password_hash(user['password_hash'], password):
                # Correct password — reset failed counter, record login time
                conn.execute(
                    'UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE id=?',
                    (datetime.now().strftime('%Y-%m-%d %H:%M'), user['id'])
                )
                conn.commit()
                remember_me = (request.form.get('remember_me') or '').strip() == '1'
                # Security policy: long-lived sessions are only allowed for
                # super_admin accounts. The database holds PII (resumes,
                # personal contact info, hiring decisions); a forgotten
                # session on a shared device would be a serious leak.
                # All non-super_admin sessions are forced into the strict
                # 30-min idle timeout, regardless of what the user ticked.
                if user['role'] != 'super_admin':
                    remember_me = False
                session.permanent = True
                session['user_id']          = user['id']
                session['username']         = user['username']
                session['full_name']        = user['full_name'] or user['username']
                session['user_role']        = user['role']
                session['last_activity']    = datetime.now().isoformat()
                session['must_change_pw']   = bool(user['must_change_password'])
                session['remember_me']      = remember_me
                log_action('LOGIN', user['username'],
                           f'Role: {ROLES.get(user["role"], user["role"])}'
                           + (' [Remember Me]' if remember_me else ''))
                flash(f'Welcome, {user["full_name"] or user["username"]}!', 'success')
                return redirect(next_url if next_url and next_url.startswith('/') else url_for('index'))
            else:
                # Wrong password — increment failure counter
                # Programming concept — progressive lockout:
                # Each wrong attempt increments a counter. When it hits the
                # limit, we calculate a future datetime for when the lock expires
                # and store it. The user sees a countdown, not just "wrong password".
                attempts = (user['failed_attempts'] or 0) + 1
                locked_until = None
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    locked_until = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
                    flash(f'Too many failed attempts. Account locked for 15 minutes.', 'error')
                    log_action('ACCOUNT LOCKED', username, f'{attempts} failed attempts')
                else:
                    remaining_attempts = MAX_LOGIN_ATTEMPTS - attempts
                    flash(f'Incorrect password. {remaining_attempts} attempt(s) remaining '
                          f'before account is locked.', 'error')
                conn.execute(
                    'UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?',
                    (attempts, locked_until, user['id'])
                )
                conn.commit()

    next_url = request.args.get('next', '')
    return render_template('login.html', next=next_url)


@app.route('/logout', methods=['POST'])
def logout():
    name = session.get('full_name', 'User')
    log_action('LOGOUT', session.get('username', ''))
    session.clear()
    flash(f'You have been signed out. Goodbye, {name}!', 'success')
    return redirect(url_for('login'))


@app.route('/users')
@role_required(*CAN_USERS)
def manage_users():
    with get_db() as conn:
        users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    return render_template('users.html', users=users, roles=ROLES)


@app.route('/users/add', methods=['POST'])
@role_required(*CAN_USERS)
def add_user():
    username  = request.form.get('username', '').strip()
    full_name = request.form.get('full_name', '').strip()
    password  = request.form.get('password', '')
    role      = (request.form.get('role') or '').strip()

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('manage_users'))
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters.', 'error')
        return redirect(url_for('manage_users'))
    if not role or role not in ROLES:
        flash('Please pick a role for the new user.', 'error')
        return redirect(url_for('manage_users'))

    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO users (username, password_hash, full_name, role, must_change_password) '
                'VALUES (?,?,?,?,1)',
                (username, generate_password_hash(password), full_name, role)
            )
            conn.commit()
        log_action('USER ADDED', username, f'Role: {ROLES[role]} (temp password set)')
        flash(f'User "{username}" ({ROLES[role]}) has been added. '
              f'They must change their password on first login.', 'success')
    except Exception as _e:
        # SQLite raises sqlite3.IntegrityError, Postgres raises
        # psycopg2.errors.UniqueViolation. We catch broadly and look at the
        # message so this works on either backend.
        msg = str(_e).lower()
        if 'unique' in msg or 'duplicate' in msg:
            flash(f'Username "{username}" already exists. Please choose another.',
                  'error')
        else:
            flash(f'Could not add user: {_e}', 'error')

    return redirect(url_for('manage_users'))


@app.route('/users/edit-role/<int:user_id>', methods=['POST'])
@role_required(*CAN_USERS)
def edit_user_role(user_id):
    """Change a user's role — Super Admin only."""
    new_role = request.form.get('new_role', 'viewer')
    if new_role not in ROLES:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('manage_users'))
    if user_id == session.get('user_id'):
        flash('You cannot change your own role.', 'error')
        return redirect(url_for('manage_users'))
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if user:
            conn.execute('UPDATE users SET role=? WHERE id=?', (new_role, user_id))
            conn.commit()
            log_action('ROLE CHANGED', user['username'],
                       f'Changed to {ROLES[new_role]}')
            flash(f'Role for "{user["username"]}" updated to {ROLES[new_role]}.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/users/edit/<int:user_id>', methods=['POST'])
@role_required(*CAN_USERS)
def edit_user(user_id):
    """Edit a user's full name and role together — Super Admin only.
    Username is immutable (it's the login identifier — changing it would
    silently break references to past audit-log entries)."""
    new_name = (request.form.get('full_name') or '').strip()
    new_role = (request.form.get('role')      or '').strip()

    if new_role not in ROLES:
        flash('Please select a valid role.', 'error')
        return redirect(url_for('manage_users'))

    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('manage_users'))

        # Self-edit is allowed for full_name, but a Super Admin cannot
        # demote themselves — they'd lock themselves out of this very page.
        if user_id == session.get('user_id') and new_role != user['role']:
            flash('You cannot change your own role. Ask another Super Admin '
                  'to do it.', 'error')
            return redirect(url_for('manage_users'))

        conn.execute(
            'UPDATE users SET full_name=?, role=? WHERE id=?',
            (new_name, new_role, user_id)
        )
        conn.commit()
        details = []
        if (user['full_name'] or '') != new_name:
            details.append(f'Name → "{new_name}"')
        if user['role'] != new_role:
            details.append(f'Role → {ROLES[new_role]}')
        log_action('USER EDITED', user['username'],
                   ', '.join(details) if details else 'No fields changed')
        flash(f'User "{user["username"]}" updated.', 'success')

    return redirect(url_for('manage_users'))


@app.route('/users/unlock/<int:user_id>', methods=['POST'])
@role_required(*CAN_USERS)
def unlock_user(user_id):
    """Manually unlock a locked account before the 15 min timer expires."""
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if user:
            conn.execute(
                'UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?',
                (user_id,)
            )
            conn.commit()
            log_action('ACCOUNT UNLOCKED', user['username'], 'Manually unlocked by admin')
            flash(f'Account "{user["username"]}" has been unlocked.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@role_required(*CAN_USERS)
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('manage_users'))
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if user:
            conn.execute('DELETE FROM users WHERE id=?', (user_id,))
            conn.commit()
            log_action('USER DELETED', user['username'])
            flash(f'User "{user["username"]}" has been removed.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/users/reset-password/<int:user_id>', methods=['POST'])
@role_required(*CAN_USERS)
def admin_reset_password(user_id):
    new_password = request.form.get('new_password', '')
    if len(new_password) < PASSWORD_MIN_LENGTH:
        flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters.', 'error')
        return redirect(url_for('manage_users'))
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if user:
            conn.execute(
                'UPDATE users SET password_hash=?, failed_attempts=0, locked_until=NULL, '
                'must_change_password=1 WHERE id=?',
                (generate_password_hash(new_password), user_id)
            )
            conn.commit()
            log_action('PASSWORD RESET', user['username'], 'Reset by admin — must change on next login')
            flash(f'Password for "{user["username"]}" has been reset. '
                  f'They will be asked to set a new password on their next login.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    # is_forced = True when the admin set a temp password and the user must change it
    is_forced = session.get('must_change_pw', False)

    if request.method == 'POST':
        current_pw = request.form.get('current_password', '')
        new_pw     = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        with get_db() as conn:
            user = conn.execute('SELECT * FROM users WHERE id=?',
                                (session['user_id'],)).fetchone()

        # For forced changes the user already authenticated via login,
        # so we skip re-checking the current password.
        current_ok = is_forced or check_password_hash(user['password_hash'], current_pw)

        if not current_ok:
            flash('Your current password is incorrect.', 'error')
        elif len(new_pw) < PASSWORD_MIN_LENGTH:
            flash(f'New password must be at least {PASSWORD_MIN_LENGTH} characters.', 'error')
        elif new_pw != confirm_pw:
            flash('New passwords do not match.', 'error')
        else:
            with get_db() as conn:
                conn.execute(
                    'UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?',
                    (generate_password_hash(new_pw), session['user_id'])
                )
                conn.commit()
            session['must_change_pw'] = False   # clear the flag in the current session too
            log_action('PASSWORD CHANGED', session.get('username', ''),
                       'First-login change' if is_forced else 'Self-changed')
            flash('Password changed successfully! Welcome to the system.', 'success')
            return redirect(url_for('index'))

    return render_template('change_password.html', is_forced=is_forced,
                           min_length=PASSWORD_MIN_LENGTH)


@app.route('/audit-log')
@role_required(*CAN_AUDIT)
def audit_log():
    """Show the audit trail — who did what and when."""
    page     = request.args.get('page', 1, type=int)
    per_page = 50
    offset   = (page - 1) * per_page

    with get_db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0]
        logs  = conn.execute(
            'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template('audit_log.html', logs=logs, page=page,
                           total_pages=total_pages, total=total)


# ─── Duplicate-detection endpoint ────────────────────────────────────────────

@app.route('/check-duplicate', methods=['POST'])
@role_required(*CAN_ADD)
def check_duplicate():
    """AJAX endpoint: check whether an about-to-be-uploaded resume already exists.

    Two independent checks are performed:
    1. File hash match  — exact duplicate of file content (different filename is OK).
       Result: 'hash_match': {...}  → caller MUST block upload (no override).
    2. Contact match    — same name AND (same email OR same phone) in the DB.
       Result: 'contact_matches': [...]  → caller shows a warning and can let
       the user confirm it is intentional (e.g. same person, different role).

    Request JSON  { name, email, phone, file_hash, exclude_id (optional) }
    Response JSON { hash_match: {id,name,date_added} | null,
                    contact_matches: [{id,name,email,phone,specialty,date_added}] }
    """
    data       = request.get_json() or {}
    name       = (data.get('name')      or '').strip()
    email      = (data.get('email')     or '').strip().lower()
    phone      = (data.get('phone')     or '').strip()
    file_hash  = (data.get('file_hash') or '').strip()
    exclude_id = data.get('exclude_id')   # int or None — skip current record on edits

    result = {'hash_match': None, 'contact_matches': []}

    with get_db() as conn:
        # ── 1. Exact file content match ──────────────────────────────────────
        if file_hash:
            q      = 'SELECT id, name, date_added FROM applicants WHERE file_hash = ?'
            params = [file_hash]
            if exclude_id:
                q += ' AND id != ?'
                params.append(int(exclude_id))
            row = conn.execute(q, params).fetchone()
            if row:
                result['hash_match'] = {
                    'id':         row['id'],
                    'name':       row['name'],
                    'date_added': row['date_added'],
                }

        # ── 2. Contact info match (name + email  OR  name + phone) ───────────
        name_lower = name.lower()
        if name_lower:
            sub_conds, params = [], [name_lower]
            if email:
                sub_conds.append('LOWER(email) = ?')
                params.append(email)
            if phone:
                sub_conds.append('phone = ?')
                params.append(phone)

            if sub_conds:
                q = (
                    'SELECT id, name, email, phone, specialty, date_added '
                    'FROM applicants '
                    f'WHERE LOWER(name) = ? AND ({" OR ".join(sub_conds)})'
                )
                if exclude_id:
                    q += ' AND id != ?'
                    params.append(int(exclude_id))
                rows = conn.execute(q, params).fetchall()
                result['contact_matches'] = [
                    {
                        'id':         r['id'],
                        'name':       r['name'],
                        'email':      r['email'],
                        'phone':      r['phone'],
                        'specialty':  r['specialty'],
                        'date_added': r['date_added'],
                    }
                    for r in rows
                ]

    return jsonify(result)


# ─── Resume routes ─────────────────────────────────────────────────────────────

@app.route('/')
@role_required(*CAN_VIEW)
def index():
    # ── Collect all filter parameters ─────────────────────────────────────
    q           = request.args.get('q', '').strip()
    f_specialty = request.args.get('specialty', '').strip()
    f_skills    = request.args.get('skills', '').strip()
    f_education = request.args.get('education', '').strip()
    f_exp_min   = request.args.get('exp_min', '').strip()
    f_exp_max   = request.args.get('exp_max', '').strip()
    f_has_file  = request.args.get('has_file', '').strip()   # 'yes' / 'no' / ''
    f_linkedin  = request.args.get('linkedin', '').strip()   # 'yes' / 'no' / ''
    f_github    = request.args.get('github', '').strip()     # 'yes' / 'no' / ''
    f_status    = request.args.get('status', '').strip()     # hiring status filter
    f_source    = request.args.get('source', '').strip()     # 'career' / 'manual' / ''

    # ── Build SQL WHERE clause (all filters are AND) ───────────────────────
    conditions, params = [], []

    if q:
        conditions.append(
            '(name LIKE ? OR specialty LIKE ? OR skills LIKE ? OR highest_education LIKE ? OR notes LIKE ?)'
        )
        like = f'%{q}%'
        params.extend([like, like, like, like, like])

    if f_specialty:
        conditions.append('specialty LIKE ?')
        params.append(f'%{f_specialty}%')

    if f_skills:
        for kw in [k.strip() for k in f_skills.split(',') if k.strip()]:
            conditions.append('skills LIKE ?')
            params.append(f'%{kw}%')

    if f_education:
        conditions.append('highest_education = ?')
        params.append(f_education)

    try:
        if f_exp_min != '':
            conditions.append('years_experience >= ?')
            params.append(int(f_exp_min))
    except ValueError:
        f_exp_min = ''

    try:
        if f_exp_max != '':
            conditions.append('years_experience <= ?')
            params.append(int(f_exp_max))
    except ValueError:
        f_exp_max = ''

    if f_has_file == 'yes':
        conditions.append("resume_filename IS NOT NULL AND resume_filename != ''")
    elif f_has_file == 'no':
        conditions.append("(resume_filename IS NULL OR resume_filename = '')")

    if f_linkedin == 'yes':
        conditions.append("linkedin_url IS NOT NULL AND linkedin_url != ''")
    elif f_linkedin == 'no':
        conditions.append("(linkedin_url IS NULL OR linkedin_url = '')")

    if f_github == 'yes':
        conditions.append("github_url IS NOT NULL AND github_url != ''")
    elif f_github == 'no':
        conditions.append("(github_url IS NULL OR github_url = '')")

    if f_status == 'Open':
        # 'Open' = no decision made yet (NULL, empty, or 'Under Review')
        conditions.append(
            "(hiring_status IS NULL OR hiring_status = '' OR hiring_status = 'Under Review')"
        )
    elif f_status:
        conditions.append('hiring_status = ?')
        params.append(f_status)

    # Source filter: 'career' = applied through the website, 'manual' = HR added
    if f_source == 'career':
        conditions.append("source LIKE 'Career Website%'")
    elif f_source == 'manual':
        conditions.append("(source IS NULL OR source = 'Manual Entry' OR source NOT LIKE 'Career Website%')")

    with get_db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM applicants').fetchone()[0]

        # Unique specialty values for the dropdown
        specialties = [
            row[0] for row in conn.execute(
                "SELECT DISTINCT specialty FROM applicants WHERE specialty != '' ORDER BY specialty"
            ).fetchall()
        ]

        # Order:
        #   1. Career-website applicants first (so HR sees fresh applications at the top)
        #   2. Newest career applications first (by date_added DESC)
        #   3. Then everyone else, alphabetical by name
        order_clause = (
            " ORDER BY "
            "  CASE WHEN source LIKE 'Career Website%' THEN 0 ELSE 1 END, "
            "  date_added DESC, "
            "  name COLLATE NOCASE ASC"
        )
        if conditions:
            sql = 'SELECT * FROM applicants WHERE ' + ' AND '.join(conditions) + order_clause
            applicants = conn.execute(sql, params).fetchall()
        else:
            applicants = conn.execute('SELECT * FROM applicants' + order_clause).fetchall()

        # Count of career-website applicants (for header badge)
        career_count = conn.execute(
            "SELECT COUNT(*) FROM applicants WHERE source LIKE 'Career Website%'"
        ).fetchone()[0]

    any_filter = bool(q or f_specialty or f_skills or f_education
                      or f_exp_min or f_exp_max or f_has_file
                      or f_linkedin or f_github or f_status or f_source)

    return render_template(
        'index.html',
        applicants=applicants,
        total=total,
        career_count=career_count,
        specialties=specialties,
        q=q,
        f_specialty=f_specialty,
        f_skills=f_skills,
        f_education=f_education,
        f_exp_min=f_exp_min,
        f_exp_max=f_exp_max,
        f_has_file=f_has_file,
        f_linkedin=f_linkedin,
        f_github=f_github,
        f_status=f_status,
        f_source=f_source,
        any_filter=any_filter,
    )


@app.route('/match-job', methods=['GET', 'POST'])
@role_required(*CAN_VIEW)
def match_job():
    """Find Best Matching Candidates — paste a JD, get the top 10 ranked.

    Pipeline:
      1. Lazily backfill parsed_text for up to 50 resumes per request so
         the keyword search can run cheaply.
      2. Tokenize the JD, score every applicant by weighted keyword overlap.
      3. Pass the top 30 to Claude for a structured rerank (one API call).
      4. Render the page with the top 10 results + scores + reasoning.
    """
    # ── 1. Lazy backfill of parsed_text (cap at 50 files per request) ──────
    BACKFILL_BUDGET     = 50
    indexed_this_visit  = 0
    pending_after_visit = 0

    with get_db() as conn:
        pending_rows = conn.execute(
            "SELECT id, resume_filename FROM applicants "
            "WHERE (parsed_text IS NULL OR parsed_text = '') "
            "  AND resume_filename IS NOT NULL "
            "  AND resume_filename != ''"
        ).fetchall()

    pending_total = len(pending_rows)
    for r in pending_rows[:BACKFILL_BUDGET]:
        try:
            data = _storage.read_file(r['resume_filename'])
            if not data:
                continue
            text = _extract_text_from_file(data, (r['resume_filename'] or '').lower())
            if not text or not text.strip():
                continue
            with get_db() as conn:
                conn.execute('UPDATE applicants SET parsed_text=? WHERE id=?',
                             (text, r['id']))
                conn.commit()
            indexed_this_visit += 1
        except Exception:
            # Extraction failed — leave parsed_text NULL so a later request
            # can retry. Don't bubble the error to the user.
            pass

    pending_after_visit = max(0, pending_total - indexed_this_visit)

    backfill_status = None
    if pending_total > 0:
        if pending_after_visit == 0:
            backfill_status = f"Indexed {indexed_this_visit} resume(s) for fast search — all caught up."
        else:
            # Show "Indexed X of Y" so HR knows the rest will catch up on subsequent visits
            total_for_msg = pending_total
            shown = indexed_this_visit
            with get_db() as conn:
                total_with_text = conn.execute(
                    "SELECT COUNT(*) FROM applicants "
                    "WHERE parsed_text IS NOT NULL AND parsed_text != ''"
                ).fetchone()[0]
                total_with_files = conn.execute(
                    "SELECT COUNT(*) FROM applicants "
                    "WHERE resume_filename IS NOT NULL AND resume_filename != ''"
                ).fetchone()[0]
            backfill_status = (
                f"Indexed {total_with_text} of {total_with_files} resumes for fast "
                f"search ({pending_after_visit} still pending — they'll be picked "
                f"up on future searches)."
            )

    # ── GET request: just show the empty form ──────────────────────────────
    if request.method == 'GET':
        return render_template(
            'match_job.html',
            jd_text='',
            results=[],
            warning=None,
            backfill_status=backfill_status,
            searched=False,
        )

    # ── POST request: validate + run the match ─────────────────────────────
    jd_text = (request.form.get('jd_text') or '').strip()
    if len(jd_text) < 20:
        flash('Please paste a job description of at least 20 characters.', 'error')
        return render_template(
            'match_job.html',
            jd_text=jd_text,
            results=[],
            warning=None,
            backfill_status=backfill_status,
            searched=False,
        )

    # ── Stage 1: Keyword pre-filter ────────────────────────────────────────
    tokens = _tokenize_job_description(jd_text)

    with get_db() as conn:
        all_applicants = conn.execute(
            'SELECT id, name, email, specialty, years_experience, '
            'highest_education, skills, resume_filename, parsed_text '
            'FROM applicants'
        ).fetchall()

    scored = []
    for row in all_applicants:
        applicant = dict(row)
        kscore = _score_applicant_keywords(applicant, tokens)
        if kscore <= 0:
            continue
        applicant['_keyword_score'] = kscore
        scored.append(applicant)

    scored.sort(key=lambda a: a['_keyword_score'], reverse=True)
    shortlist = scored[:30]

    warning = None
    results = []

    if not shortlist:
        # No keyword overlap at all — empty state will be rendered.
        log_action('JOB MATCH', '',
                   f'JD chars={len(jd_text)} | applicants={len(all_applicants)} | matches=0')
        return render_template(
            'match_job.html',
            jd_text=jd_text,
            results=[],
            warning=None,
            backfill_status=backfill_status,
            searched=True,
        )

    # ── Stage 2: Claude rerank (or graceful fallback) ──────────────────────
    rerank, ai_error = _ai_rerank_candidates(jd_text, shortlist)

    by_id = {a['id']: a for a in shortlist}

    if rerank:
        # Use Claude's order + score + reasoning
        for item in rerank:
            applicant = by_id.get(item['id'])
            if not applicant:
                continue
            results.append({
                'id':                applicant['id'],
                'name':              applicant.get('name') or '—',
                'specialty':         applicant.get('specialty') or '',
                'years_experience':  applicant.get('years_experience') or 0,
                'highest_education': applicant.get('highest_education') or '',
                'skills':            applicant.get('skills') or '',
                'has_file':          bool(applicant.get('resume_filename')),
                'score':             item['score'],
                'reasoning':         item['reasoning'] or 'Matches several keywords from the job description.',
            })
        if ai_error:
            warning = ai_error
    else:
        # Fall back to keyword ranking; normalize the raw score to 0–100.
        warning = ai_error or 'AI rerank unavailable — showing keyword matches only.'
        top_score = shortlist[0]['_keyword_score'] or 1
        for applicant in shortlist[:10]:
            kscore = applicant['_keyword_score']
            norm = int(round(100 * kscore / top_score))
            norm = max(1, min(100, norm))
            results.append({
                'id':                applicant['id'],
                'name':              applicant.get('name') or '—',
                'specialty':         applicant.get('specialty') or '',
                'years_experience':  applicant.get('years_experience') or 0,
                'highest_education': applicant.get('highest_education') or '',
                'skills':            applicant.get('skills') or '',
                'has_file':          bool(applicant.get('resume_filename')),
                'score':             norm,
                'reasoning':         (f'Matched {kscore} weighted keyword(s) '
                                      f'across skills, specialty and resume text.'),
            })

    log_action('JOB MATCH', '',
               f'JD chars={len(jd_text)} | shortlist={len(shortlist)} | '
               f'returned={len(results)}' + (' | ai_fallback' if warning else ''))

    return render_template(
        'match_job.html',
        jd_text=jd_text,
        results=results,
        warning=warning,
        backfill_status=backfill_status,
        searched=True,
    )


@app.route('/add', methods=['GET', 'POST'])
@role_required(*CAN_ADD)
def add_resume():
    if request.method == 'POST':

        # ── "Update existing record" path ────────────────────────────────────
        # Triggered when the user clicks "Update [Name]'s Resume" in the
        # duplicate-detection modal.  We replace the existing record's file
        # and re-parse to refresh auto-extracted fields, keeping everything
        # else (hiring status, notes, interview history) untouched.
        update_id_str = request.form.get('update_existing_id', '').strip()
        if update_id_str:
            try:
                update_id = int(update_id_str)
            except ValueError:
                flash('Invalid update target.', 'error')
                return render_template('add_resume.html', form=request.form)

            with get_db() as conn:
                existing = conn.execute(
                    'SELECT * FROM applicants WHERE id=?', (update_id,)
                ).fetchone()
            if not existing:
                flash('The record to update could not be found.', 'error')
                return render_template('add_resume.html', form=request.form)

            file = request.files.get('resume_file')
            if not file or not file.filename or not allowed_file(file.filename):
                flash('Please provide a valid resume file to replace the existing one.', 'error')
                return render_template('add_resume.html', form=request.form)

            # Compute hashes — block if either the bytes OR the text content
            # already belongs to a DIFFERENT record.
            new_hash = compute_file_hash(file)
            _file_bytes = _read_file_bytes_from_field(file)
            new_text_hash = compute_text_hash(_file_bytes, file.filename or '')
            with get_db() as conn:
                hash_dup = conn.execute(
                    'SELECT id, name FROM applicants WHERE file_hash=? AND id!=?',
                    (new_hash, update_id)
                ).fetchone()
            if hash_dup:
                flash(
                    f'The uploaded file is an exact duplicate of the resume already '
                    f'on record for "{hash_dup["name"]}" (ID #{hash_dup["id"]}). '
                    f'No changes were made.',
                    'error'
                )
                return render_template('add_resume.html', form=request.form)

            if new_text_hash:
                with get_db() as conn:
                    text_dup = conn.execute(
                        'SELECT id, name FROM applicants '
                        'WHERE text_hash=? AND id!=?',
                        (new_text_hash, update_id)
                    ).fetchone()
                if text_dup:
                    flash(
                        f'The uploaded file has the SAME CONTENT as the resume '
                        f'already on record for "{text_dup["name"]}" '
                        f'(ID #{text_dup["id"]}). Even though the file is '
                        f'different on disk, the resume text is identical. '
                        f'No changes were made.',
                        'error'
                    )
                    return render_template('add_resume.html', form=request.form)

            # Delete old file
            if existing['resume_filename']:
                _storage.delete_file(existing['resume_filename'])

            # Save new file via storage abstraction (Supabase or local)
            new_filename = make_unique_filename(file.filename)
            _storage.save_file(new_filename, _file_bytes,
                               file.mimetype or 'application/octet-stream')

            # Re-parse new file — use parsed values where available, fall back
            # to whatever is already stored so we never blank-out a field
            parsed = _parse_saved_file(new_filename) or {}

            # Extract full plain text so the job-matcher can search it later.
            # Falls back to NULL on any failure — match-job will lazy-fill it.
            new_parsed_text = None
            try:
                _txt = _extract_text_from_file(_file_bytes, (file.filename or '').lower())
                if _txt and _txt.strip():
                    new_parsed_text = _txt
            except Exception:
                new_parsed_text = None

            def _pick(pv, ev):
                v = str(pv).strip() if pv is not None else ''
                return v if v else (ev or '')

            with get_db() as conn:
                conn.execute('''
                    UPDATE applicants
                       SET resume_filename=?, file_hash=?, text_hash=?,
                           parsed_text=?,
                           name=?, email=?, phone=?,
                           specialty=?, years_experience=?,
                           highest_education=?, skills=?
                     WHERE id=?
                ''', (
                    new_filename, new_hash, new_text_hash,
                    new_parsed_text,
                    _pick(parsed.get('name'),              existing['name']),
                    _pick(parsed.get('email'),             existing['email']),
                    _pick(parsed.get('phone'),             existing['phone']),
                    _pick(parsed.get('specialty'),         existing['specialty']),
                    _safe_int(parsed.get('years_experience'), _safe_int(existing['years_experience'], 0)),
                    _pick(parsed.get('highest_education'), existing['highest_education']),
                    _pick(parsed.get('skills'),            existing['skills']),
                    update_id,
                ))
                conn.commit()

            flash(f'✓ Resume for {existing["name"]} has been updated with the new file!',
                  'success')
            log_action('RESUME UPDATED', existing['name'],
                       f'File replaced — old: {existing["resume_filename"] or "none"}, '
                       f'new: {file.filename}')
            return redirect(url_for('view_resume', applicant_id=update_id))

        # ── Normal "add new record" path ─────────────────────────────────────
        name             = request.form.get('name', '').strip()
        email            = request.form.get('email', '').strip()
        phone            = request.form.get('phone', '').strip()
        linkedin_url     = request.form.get('linkedin_url', '').strip()
        github_url       = request.form.get('github_url', '').strip()
        specialty        = request.form.get('specialty', '').strip()
        years_experience = request.form.get('years_experience', '0').strip() or '0'
        highest_education= request.form.get('highest_education', '').strip()
        skills           = request.form.get('skills', '').strip()
        notes            = request.form.get('notes', '').strip()

        errors = []
        if not name:
            errors.append('Applicant name is required.')
        if not specialty:
            errors.append('Specialty / Field is required.')
        try:
            years_experience = int(years_experience)
            if years_experience < 0:
                errors.append('Years of experience cannot be negative.')
        except ValueError:
            errors.append('Years of experience must be a whole number.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('add_resume.html', form=request.form)

        # ── Server-side contact-info duplicate check (safety net) ───────────
        # The client-side AJAX modal handles this interactively, but we must
        # also check server-side in case JS was slow, disabled, or bypassed.
        # If the user confirmed the duplicate intentionally via the modal,
        # the form sends confirmed_duplicate=1 and we skip this block.
        confirmed = request.form.get('confirmed_duplicate', '').strip() == '1'
        if not confirmed and name and (email or phone):
            sub_conds, cparams = [], [name.lower()]
            if email:
                sub_conds.append('LOWER(email) = ?')
                cparams.append(email.lower())
            if phone:
                sub_conds.append('phone = ?')
                cparams.append(phone)
            q = (
                'SELECT id, name, specialty FROM applicants '
                f'WHERE LOWER(name) = ? AND ({" OR ".join(sub_conds)})'
            )
            with get_db() as _conn:
                contact_dup = _conn.execute(q, cparams).fetchone()
            if contact_dup:
                flash(
                    f'An applicant named "{contact_dup["name"]}" with the same '
                    f'contact details already exists (record ID #{contact_dup["id"]}, '
                    f'specialty: {contact_dup["specialty"] or "—"}). '
                    f'If this is genuinely a new application for a different role, '
                    f'tick the confirmation box in the duplicate warning and resubmit.',
                    'error'
                )
                return render_template('add_resume.html', form=request.form)

        # Handle file upload
        resume_filename = None
        file_hash       = None
        text_hash       = None
        parsed_text     = None
        file = request.files.get('resume_file')
        if file and file.filename:
            if allowed_file(file.filename):
                # ── Server-side hash duplicate check (always blocks — no override) ─
                file_hash = compute_file_hash(file)
                _file_bytes = _read_file_bytes_from_field(file)
                text_hash = compute_text_hash(_file_bytes, file.filename)
                with get_db() as _conn:
                    existing = _conn.execute(
                        'SELECT id, name FROM applicants WHERE file_hash = ?',
                        (file_hash,)
                    ).fetchone()
                if existing:
                    flash(
                        f'This file is an exact duplicate of the resume already on record '
                        f'for "{existing["name"]}" (ID #{existing["id"]}). '
                        f'Upload blocked — identical files are never allowed.',
                        'error'
                    )
                    return render_template('add_resume.html', form=request.form)

                if text_hash:
                    with get_db() as _conn:
                        text_existing = _conn.execute(
                            'SELECT id, name FROM applicants WHERE text_hash = ?',
                            (text_hash,)
                        ).fetchone()
                    if text_existing:
                        flash(
                            f'This resume has the SAME CONTENT as the one already on '
                            f'record for "{text_existing["name"]}" '
                            f'(ID #{text_existing["id"]}). Even though the file is '
                            f'different on disk, the resume text is identical. '
                            f'Upload blocked.',
                            'error'
                        )
                        return render_template('add_resume.html', form=request.form)

                # ── Identity match from the parsed resume content ───────────
                # Parses the file and checks whether the email or name+phone
                # inside it already belongs to another applicant. Catches the
                # "same person, brand-new file, no form-input duplicates" case
                # which the earlier checks all miss.
                parsed = parse_resume_bytes(_file_bytes, file.filename)
                id_match = find_identity_match(
                    name  = parsed.get('name')  or name,
                    email = parsed.get('email') or email,
                    phone = parsed.get('phone') or phone,
                )
                if id_match and not confirmed:
                    flash(
                        f'The uploaded resume looks like the same person as an '
                        f'existing record: "{id_match["name"]}" (ID #{id_match["id"]}, '
                        f'specialty: {id_match.get("specialty") or "—"}, status: '
                        f'{id_match.get("hiring_status") or "—"}). If you are '
                        f'updating this person\'s resume, edit their existing '
                        f'record instead. If this really is a different '
                        f'applicant, tick the duplicate-confirmation box and '
                        f'resubmit.',
                        'error'
                    )
                    return render_template('add_resume.html', form=request.form)

                resume_filename = make_unique_filename(file.filename)
                _storage.save_file(resume_filename, _file_bytes,
                                   file.mimetype or 'application/octet-stream')

                # Cache the extracted plain text for the job-matcher.
                try:
                    _txt = _extract_text_from_file(_file_bytes, file.filename.lower())
                    if _txt and _txt.strip():
                        parsed_text = _txt
                except Exception:
                    parsed_text = None
            else:
                flash('Only PDF, DOC, and DOCX files are allowed.', 'error')
                return render_template('add_resume.html', form=request.form)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO applicants
                    (name, email, phone, linkedin_url, github_url,
                     specialty, years_experience, highest_education,
                     skills, resume_filename, notes, file_hash, text_hash,
                     parsed_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, email, phone, linkedin_url, github_url,
                  specialty, years_experience, highest_education,
                  skills, resume_filename, notes, file_hash, text_hash,
                  parsed_text))
            conn.commit()

        flash(f'✓ Resume for {name} has been added successfully!', 'success')
        log_action('RESUME ADDED', name)
        return redirect(url_for('index'))

    return render_template('add_resume.html', form={})


@app.route('/add-bulk', methods=['GET', 'POST'])
@role_required(*CAN_ADD)
def add_bulk():
    """Upload and auto-parse multiple resume files in one go.
    Each uploaded file becomes a separate applicant record.
    """
    if request.method == 'POST':
        files   = request.files.getlist('resume_files')
        added   = []   # list of applicant names successfully created
        failed  = []   # list of {'filename': ..., 'reason': ...}

        for file in files:
            if not file or not file.filename:
                continue
            if not allowed_file(file.filename):
                failed.append({'filename': file.filename,
                               'reason': 'Unsupported file type'})
                continue

            # ── Compute hashes in memory BEFORE saving ──────────────────────
            try:
                fhash = compute_file_hash(file)
                _file_bytes = _read_file_bytes_from_field(file)
                thash = compute_text_hash(_file_bytes, file.filename)
            except Exception as e:
                failed.append({'filename': file.filename, 'reason': f'Could not hash file: {e}'})
                continue

            # ── Block if exact-byte duplicate already exists ────────────────
            with get_db() as _conn:
                dup = _conn.execute(
                    'SELECT id, name FROM applicants WHERE file_hash = ?', (fhash,)
                ).fetchone()
            if dup:
                failed.append({
                    'filename': file.filename,
                    'reason':   f'Duplicate — identical file already on record for "{dup["name"]}" (ID #{dup["id"]})'
                })
                continue

            # ── Block if content-duplicate already exists ───────────────────
            if thash:
                with get_db() as _conn:
                    tdup = _conn.execute(
                        'SELECT id, name FROM applicants WHERE text_hash = ?',
                        (thash,)
                    ).fetchone()
                if tdup:
                    failed.append({
                        'filename': file.filename,
                        'reason': (f'Duplicate content — resume text matches '
                                   f'existing record for "{tdup["name"]}" '
                                   f'(ID #{tdup["id"]})')
                    })
                    continue

            # Parse BEFORE saving so we can run identity dedup without writing
            # files we are going to reject anyway.
            parsed = parse_resume_bytes(_file_bytes, file.filename)

            # ── Identity match: same person already in the database? ────────
            id_match = find_identity_match(
                name  = parsed.get('name', ''),
                email = parsed.get('email', ''),
                phone = parsed.get('phone', ''),
            )
            if id_match:
                failed.append({
                    'filename': file.filename,
                    'reason': (f'Same person already on record: '
                               f'"{id_match["name"]}" (ID #{id_match["id"]}). '
                               f'Edit that record to update their resume.')
                })
                continue

            # Save the file via storage abstraction (works with Supabase or local)
            filename = make_unique_filename(file.filename)
            try:
                _storage.save_file(filename, _file_bytes,
                                   file.mimetype or 'application/octet-stream')
            except Exception as e:
                failed.append({'filename': file.filename, 'reason': f'Could not save: {e}'})
                continue

            # ── Build fallback name from filename if parsing found nothing ────
            # Strip common resume-tool prefixes/suffixes so a file named
            # "ResumeAI_JohnSmith.pdf" becomes "John Smith", not "ResumeAI JohnSmith".
            import re as _re
            raw_stem = file.filename.rsplit('.', 1)[0]
            raw_stem = raw_stem.replace('_', ' ').replace('-', ' ').strip()
            # Remove leading "Resume", "CV", "ResumeAI", "My Resume" etc.
            cleaned_stem = _re.sub(
                r'(?i)^(resume\s*ai|resumeai|resume|curriculum\s*vitae|vitae|'
                r'my\s*resume|my\s*cv|updated\s*resume|new\s*resume|cv)\s*',
                '', raw_stem
            ).strip()
            # Remove trailing "resume" / "cv"
            cleaned_stem = _re.sub(r'(?i)\s*(resume|cv)$', '', cleaned_stem).strip()
            # If nothing useful is left, use the original stem as a last resort
            stem_name = cleaned_stem or raw_stem

            parsed_name = (parsed.get('name') or '').strip()
            name        = parsed_name or stem_name or 'Please Edit Name'
            specialty   = (parsed.get('specialty') or '').strip() or 'General'

            # Cache the full text for the job-matcher.
            bulk_parsed_text = None
            try:
                _txt = _extract_text_from_file(_file_bytes, file.filename.lower())
                if _txt and _txt.strip():
                    bulk_parsed_text = _txt
            except Exception:
                bulk_parsed_text = None

            try:
                with get_db() as conn:
                    conn.execute('''
                        INSERT INTO applicants
                            (name, email, phone, linkedin_url, github_url,
                             specialty, years_experience,
                             highest_education, skills, resume_filename,
                             file_hash, text_hash, parsed_text)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (name,
                          (parsed.get('email') or '').strip(),
                          (parsed.get('phone') or '').strip(),
                          (parsed.get('linkedin_url') or '').strip(),
                          (parsed.get('github_url') or '').strip(),
                          specialty,
                          _safe_int(parsed.get('years_experience'), 0),
                          (parsed.get('highest_education') or '').strip(),
                          (parsed.get('skills') or '').strip(),
                          filename,
                          fhash, thash, bulk_parsed_text))
                    conn.commit()
                added.append({'name': name, 'filename': file.filename})
                log_action('RESUME ADDED', name, f'Bulk upload — {file.filename}')
            except Exception as e:
                failed.append({'filename': file.filename, 'reason': f'DB error: {e}'})

        return render_template('add_bulk.html', added=added, failed=failed, done=True)

    return render_template('add_bulk.html', added=[], failed=[], done=False)


@app.route('/view/<int:applicant_id>')
@role_required(*CAN_VIEW)
def view_resume(applicant_id):
    with get_db() as conn:
        applicant = conn.execute(
            'SELECT * FROM applicants WHERE id = ?', (applicant_id,)
        ).fetchone()

        if not applicant:
            flash('Applicant not found.', 'error')
            return redirect(url_for('index'))

        interviews = conn.execute(
            'SELECT * FROM interviews WHERE applicant_id = ? '
            'ORDER BY interview_date DESC, created_at DESC',
            (applicant_id,)
        ).fetchall()

        staff_list = conn.execute(
            'SELECT * FROM staff ORDER BY name COLLATE NOCASE ASC'
        ).fetchall()

        # Most recent interview record — used to pre-fill the Schedule form
        latest_iv = interviews[0] if interviews else None

    file_ext = None
    if applicant['resume_filename']:
        file_ext = applicant['resume_filename'].rsplit('.', 1)[-1].lower()

    return render_template('view_resume.html', applicant=applicant,
                           file_ext=file_ext, interviews=interviews,
                           staff_list=staff_list,
                           latest_iv=latest_iv,
                           office_contact_name=OFFICE_CONTACT_NAME)


@app.route('/edit/<int:applicant_id>', methods=['GET', 'POST'])
@role_required(*CAN_EDIT)
def edit_resume(applicant_id):
    with get_db() as conn:
        applicant = conn.execute(
            'SELECT * FROM applicants WHERE id = ?', (applicant_id,)
        ).fetchone()

    if not applicant:
        flash('Applicant not found.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name             = request.form.get('name', '').strip()
        email            = request.form.get('email', '').strip()
        phone            = request.form.get('phone', '').strip()
        linkedin_url     = request.form.get('linkedin_url', '').strip()
        github_url       = request.form.get('github_url', '').strip()
        specialty        = request.form.get('specialty', '').strip()
        years_experience = request.form.get('years_experience', '0').strip() or '0'
        highest_education= request.form.get('highest_education', '').strip()
        skills           = request.form.get('skills', '').strip()
        notes            = request.form.get('notes', '').strip()

        errors = []
        if not name:
            errors.append('Applicant name is required.')
        if not specialty:
            errors.append('Specialty / Field is required.')
        try:
            years_experience = int(years_experience)
        except ValueError:
            errors.append('Years of experience must be a whole number.')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('edit_resume.html', applicant=applicant)

        # Handle new file upload
        resume_filename = applicant['resume_filename']
        new_file_hash   = applicant['file_hash']   # keep existing hash unless replaced
        # text_hash may not exist on very old rows — fall back to None safely.
        try:
            new_text_hash = applicant['text_hash']
        except (KeyError, IndexError):
            new_text_hash = None
        # parsed_text may also be missing on old rows; keep existing unless replaced
        try:
            new_parsed_text = applicant['parsed_text']
        except (KeyError, IndexError):
            new_parsed_text = None
        file = request.files.get('resume_file')
        if file and file.filename:
            if allowed_file(file.filename):
                # ── Hash check: block if replacing with an exact duplicate ───
                new_file_hash = compute_file_hash(file)
                _file_bytes = _read_file_bytes_from_field(file)
                new_text_hash = compute_text_hash(_file_bytes, file.filename)
                with get_db() as _conn:
                    existing = _conn.execute(
                        'SELECT id, name FROM applicants WHERE file_hash = ? AND id != ?',
                        (new_file_hash, applicant_id)
                    ).fetchone()
                if existing:
                    flash(
                        f'The uploaded file is an exact duplicate of the resume already on '
                        f'record for "{existing["name"]}" (ID #{existing["id"]}). '
                        f'File not replaced.',
                        'error'
                    )
                    return render_template('edit_resume.html', applicant=applicant)

                if new_text_hash:
                    with get_db() as _conn:
                        text_existing = _conn.execute(
                            'SELECT id, name FROM applicants '
                            'WHERE text_hash = ? AND id != ?',
                            (new_text_hash, applicant_id)
                        ).fetchone()
                    if text_existing:
                        flash(
                            f'The uploaded file has the SAME CONTENT as the resume '
                            f'already on record for "{text_existing["name"]}" '
                            f'(ID #{text_existing["id"]}). File not replaced.',
                            'error'
                        )
                        return render_template('edit_resume.html', applicant=applicant)

                # Delete old file first
                if resume_filename:
                    _storage.delete_file(resume_filename)
                resume_filename = make_unique_filename(file.filename)
                _storage.save_file(resume_filename, _file_bytes,
                                   file.mimetype or 'application/octet-stream')

                # Re-extract full text for the job-matcher.
                try:
                    _txt = _extract_text_from_file(_file_bytes, file.filename.lower())
                    new_parsed_text = _txt if (_txt and _txt.strip()) else None
                except Exception:
                    new_parsed_text = None
            else:
                flash('Only PDF, DOC, and DOCX files are allowed.', 'error')
                return render_template('edit_resume.html', applicant=applicant)

        # Handle file removal
        if request.form.get('remove_file') == '1':
            if resume_filename:
                _storage.delete_file(resume_filename)
            resume_filename  = None
            new_file_hash    = None
            new_text_hash    = None
            new_parsed_text  = None

        with get_db() as conn:
            conn.execute('''
                UPDATE applicants
                SET name=?, email=?, phone=?, linkedin_url=?, github_url=?,
                    specialty=?, years_experience=?, highest_education=?,
                    skills=?, resume_filename=?, notes=?,
                    file_hash=?, text_hash=?, parsed_text=?
                WHERE id=?
            ''', (name, email, phone, linkedin_url, github_url,
                  specialty, years_experience, highest_education,
                  skills, resume_filename, notes,
                  new_file_hash, new_text_hash, new_parsed_text, applicant_id))
            conn.commit()

        edit_notes = request.form.get('edit_notes', '').strip()
        flash(f'✓ Resume for {name} has been updated!', 'success')
        log_action('RESUME EDITED', name,
                   f'Edit notes: {edit_notes}' if edit_notes else 'No edit notes provided')
        return redirect(url_for('view_resume', applicant_id=applicant_id))

    return render_template('edit_resume.html', applicant=applicant)


@app.route('/delete/<int:applicant_id>', methods=['POST'])
@role_required(*CAN_DELETE)
def delete_resume(applicant_id):
    delete_reason = request.form.get('delete_reason', '').strip()
    with get_db() as conn:
        applicant = conn.execute(
            'SELECT * FROM applicants WHERE id = ?', (applicant_id,)
        ).fetchone()

        if applicant:
            if applicant['resume_filename']:
                _storage.delete_file(applicant['resume_filename'])
            # Also remove all interview records for this applicant
            conn.execute('DELETE FROM interviews WHERE applicant_id = ?', (applicant_id,))
            conn.execute('DELETE FROM applicants WHERE id = ?', (applicant_id,))
            conn.commit()
            flash(f'Resume for {applicant["name"]} has been deleted.', 'success')
            log_action('RESUME DELETED', applicant["name"],
                       f'Reason: {delete_reason}' if delete_reason else 'No reason provided')
        else:
            flash('Applicant not found.', 'error')

    return redirect(url_for('index'))


@app.route('/uploads/<filename>')
@role_required(*CAN_DOWNLOAD)
def uploaded_file(filename):
    """
    Serve a resume file.

    • Local backend  → send the file from disk
    • Supabase backend → redirect to a short-lived signed URL
                         (browser fetches directly from Supabase Storage)
    """
    if _storage.backend() == 'supabase':
        signed = _storage.file_url(filename, expires=3600)
        if not signed:
            flash('File not found in storage.', 'error')
            return redirect(url_for('index'))
        return redirect(signed)
    # Local: serve from disk directly
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ─── Interview routes ──────────────────────────────────────────────────────────

# ─── Email helpers ─────────────────────────────────────────────────────────────

def _email_credentials():
    """
    Read email credentials in this priority order:
      1. config.py (local development)
      2. MAIL_* environment variables (cloud / production via module-level _cfg)

    If neither yields valid credentials, the caller (_send_email) returns a
    clear "not configured" error and the interview save still succeeds —
    only the email notification is skipped.
    """
    try:
        import importlib, config as _c
        importlib.reload(_c)
        return {
            'server':   getattr(_c, 'MAIL_SERVER',   '') or MAIL_SERVER,
            'port':     int(getattr(_c, 'MAIL_PORT', 0) or MAIL_PORT or 587),
            'username': getattr(_c, 'MAIL_USERNAME', '') or MAIL_USERNAME,
            'password': getattr(_c, 'MAIL_PASSWORD', '') or MAIL_PASSWORD,
            'from':     getattr(_c, 'MAIL_FROM',     '') or MAIL_FROM,
        }
    except Exception:
        return {'server': MAIL_SERVER, 'port': MAIL_PORT,
                'username': MAIL_USERNAME, 'password': MAIL_PASSWORD,
                'from': MAIL_FROM}


def _email_enabled():
    creds = _email_credentials()
    return bool(creds.get('username') and creds.get('password'))


def _ics_escape(text):
    """Escape text for ICS SUMMARY/DESCRIPTION/LOCATION fields (RFC 5545)."""
    # Replace non-ASCII dashes/quotes with ASCII equivalents first
    text = text.replace('—', '-').replace('–', '-').replace('’', "'")
    # RFC 5545 escaping: backslash, semicolon, comma, newline
    text = text.replace('\\', '\\\\').replace(';', '\\;').replace(',', '\\,')
    text = text.replace('\n', '\\n').replace('\r', '')
    return text


def _generate_ics(candidate_name, position, interview_date, interview_time,
                  interview_type, meeting_link, contact_person, attendee_email):
    """
    Return an ICS calendar-invite string (RFC 5545).

    LOCATION is set correctly per interview type:
      • In-Person   → office address  (contact_person becomes "Ask for X" in DESC)
      • Video/Phone → meeting_link    (or the format if no link given)

    attendee_email  — the interviewer who receives the invite.
    ORGANIZER       — the HR sender address from config (who is sending the invite).
    """
    import hashlib
    from datetime import datetime as _dt, timedelta as _td

    # Parse start datetime
    fmt_date = '%Y-%m-%d'
    fmt_12   = '%Y-%m-%d %I:%M %p'
    fmt_24   = '%Y-%m-%d %H:%M'
    dt_start = None
    if interview_date:
        raw = f"{interview_date} {interview_time}".strip() if interview_time else interview_date
        for fmt in (fmt_12, fmt_24, fmt_date):
            try:
                dt_start = _dt.strptime(raw, fmt)
                break
            except ValueError:
                pass
    if not dt_start:
        return None

    dt_end   = dt_start + _td(hours=1)
    dtstamp  = _dt.utcnow().strftime('%Y%m%dT%H%M%SZ')
    dtstart  = dt_start.strftime('%Y%m%dT%H%M%S')
    dtend    = dt_end.strftime('%Y%m%dT%H%M%S')
    uid      = hashlib.md5(
        f"{candidate_name}{interview_date}{interview_time}{attendee_email}".encode()
    ).hexdigest()

    if interview_type == 'In-Person':
        loc_str = _ics_escape(OFFICE_ADDRESS)
    else:
        loc_str = _ics_escape(meeting_link or interview_type)

    summary  = _ics_escape(f"Interview: {candidate_name} - {position}")

    desc_parts = [f"Interview with {candidate_name} for the position of {position}."]
    if interview_type == 'In-Person' and contact_person:
        desc_parts.append(f"On arrival, ask reception for {contact_person}.")
    if interview_type != 'In-Person' and meeting_link:
        desc_parts.append(f"Meeting link: {meeting_link}")
    desc = _ics_escape(' '.join(desc_parts))

    # ORGANIZER = the HR team / sender address (not the interviewer)
    creds          = _email_credentials()
    organizer_addr = creds.get('from') or creds.get('username') or 'hr@transcrypts.com'

    TZID = "America/Toronto"
    return (
        "BEGIN:VCALENDAR\r\n"
        "VERSION:2.0\r\n"
        "PRODID:-//TransCrypts//Resume Database//EN\r\n"
        "METHOD:REQUEST\r\n"
        "CALSCALE:GREGORIAN\r\n"
        # ── Timezone definition (Eastern Time / America/Toronto) ──────────────
        "BEGIN:VTIMEZONE\r\n"
        f"TZID:{TZID}\r\n"
        "BEGIN:STANDARD\r\n"
        "TZNAME:EST\r\n"
        "DTSTART:19671029T020000\r\n"
        "TZOFFSETFROM:-0400\r\n"
        "TZOFFSETTO:-0500\r\n"
        "RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=11\r\n"
        "END:STANDARD\r\n"
        "BEGIN:DAYLIGHT\r\n"
        "TZNAME:EDT\r\n"
        "DTSTART:19870405T020000\r\n"
        "TZOFFSETFROM:-0500\r\n"
        "TZOFFSETTO:-0400\r\n"
        "RRULE:FREQ=YEARLY;BYDAY=2SU;BYMONTH=3\r\n"
        "END:DAYLIGHT\r\n"
        "END:VTIMEZONE\r\n"
        # ── Event ─────────────────────────────────────────────────────────────
        "BEGIN:VEVENT\r\n"
        f"UID:{uid}@transcrypts.com\r\n"
        f"DTSTAMP:{dtstamp}\r\n"
        f"DTSTART;TZID={TZID}:{dtstart}\r\n"
        f"DTEND;TZID={TZID}:{dtend}\r\n"
        f"SUMMARY:{summary}\r\n"
        f"LOCATION:{loc_str}\r\n"
        f"DESCRIPTION:{desc}\r\n"
        "STATUS:CONFIRMED\r\n"
        f"ORGANIZER;CN=TransCrypts HR:mailto:{organizer_addr}\r\n"
        f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;"
        f"RSVP=TRUE:mailto:{attendee_email}\r\n"
        "END:VEVENT\r\n"
        "END:VCALENDAR\r\n"
    )


def _send_via_resend_http(api_key, from_addr, to_addr, subject, html_body,
                            attachments=None, _retry_with_default=True):
    """
    Send an email via Resend's HTTP API — works from any cloud host even when
    outbound SMTP is blocked. Returns (ok, error_message).

    POST https://api.resend.com/emails
    Authorization: Bearer <RESEND_API_KEY>

    If the configured MAIL_FROM uses an unverified domain (e.g. you set
    @transcrypts.com but haven't yet added DNS records), we retry once with
    Resend's universal default sender 'onboarding@resend.dev' so emails still
    go out. The original from_addr will work the moment the domain is
    verified — no code change needed at that point.
    """
    import urllib.request, urllib.error, json as _json, base64 as _b64

    payload = {
        'from':    from_addr,
        'to':      [to_addr],
        'subject': subject,
        'html':    html_body,
    }

    if attachments:
        att_list = []
        for fname, fdata, fmime in attachments:
            if isinstance(fdata, str):
                fdata = fdata.encode('utf-8')
            att_list.append({
                'filename':    fname,
                'content':     _b64.b64encode(fdata).decode(),
                'content_type': fmime,
            })
        if att_list:
            payload['attachments'] = att_list

    # Inline the TransCrypts logo as a CID-style attachment if present
    if _EMAIL_LOGO_BYTES:
        payload.setdefault('attachments', []).append({
            'filename':     'transcrypts_logo.png',
            'content':      _b64.b64encode(_EMAIL_LOGO_BYTES).decode(),
            'content_type': 'image/png',
            'content_id':   'transcrypts_logo',
        })

    req = urllib.request.Request(
        'https://api.resend.com/emails',
        data=_json.dumps(payload).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type':  'application/json',
            # A real-looking User-Agent — Cloudflare (which fronts Resend's API)
            # blocks the default 'Python-urllib/3.x' UA with error 1010.
            'User-Agent':    'TransCrypts-Resume-DB/1.0 (contact: hr@transcrypts.com)',
            'Accept':        'application/json',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read().decode('utf-8', 'replace')
            try:
                data = _json.loads(body)
            except Exception:
                data = {}
            if r.status in (200, 201, 202) and (data.get('id') or data.get('data')):
                return True, ''
            return False, f'Resend HTTP {r.status}: {body[:300]}'
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode('utf-8', 'replace')
        except Exception:
            err_body = ''
        # Auto-fallback: if MAIL_FROM uses an unverified domain, retry once
        # with Resend's default 'onboarding@resend.dev' so the email still
        # goes out. Once the user verifies their custom domain in Resend,
        # the original FROM works automatically — no code change needed.
        if (_retry_with_default and e.code == 403 and
                ('not verified' in err_body.lower()
                 or 'domain' in err_body.lower())):
            fallback_from = 'TransCrypts HR <onboarding@resend.dev>'
            print(f'[email] FROM "{from_addr}" rejected (domain not verified); '
                  f'retrying with {fallback_from}')
            return _send_via_resend_http(
                api_key, fallback_from, to_addr, subject, html_body,
                attachments, _retry_with_default=False
            )
        return False, f'Resend HTTP {e.code}: {err_body[:300]}'
    except Exception as e:
        return False, f'Resend API error: {type(e).__name__}: {e}'


def _send_email(to_addr, subject, html_body, attachments=None):
    """
    Send an HTML email via SMTP (configured in config.py).
    attachments: list of (filename, data_bytes, mime_type) tuples.

    The TransCrypts logo is automatically attached as a CID inline image so
    that email clients (Gmail, Outlook, Apple Mail, ProtonMail …) display it
    correctly.  Gmail blocks data: URIs but supports CID images fully.

    MIME structure:
        multipart/mixed
          multipart/related          ← ties the HTML to its inline image
            multipart/alternative
              text/html
            image/png  (logo, Content-ID: transcrypts_logo)
          [optional file attachments — resume PDF/DOCX, ICS …]

    Returns (True, '') on success, (False, error_message) on failure.
    """
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text      import MIMEText
    from email.mime.base      import MIMEBase
    from email.mime.image     import MIMEImage
    from email                import encoders

    creds = _email_credentials()
    if not (creds.get('username') and creds.get('password')):
        return False, ('Email not configured. Set MAIL_USERNAME, MAIL_PASSWORD, '
                       'MAIL_SERVER (e.g. smtp.gmail.com), MAIL_PORT (587), and '
                       'MAIL_FROM as environment variables on the host.')

    # ── HTTP API short-circuit for Resend (only when MAIL_SERVER says so) ────
    # When MAIL_SERVER explicitly points at Resend's host, send via Resend's
    # HTTP API instead of SMTP (Render free tier blocks outbound SMTP).
    # If MAIL_SERVER is anything else (e.g. smtp.protonmail.ch on a paid
    # Render instance, smtp.gmail.com, smtp.office365.com…), we fall through
    # to the standard SMTP path so the user's choice of provider is honoured.
    server_l = (creds.get('server') or '').lower()
    if 'resend' in server_l and creds.get('password'):
        return _send_via_resend_http(
            creds['password'],
            creds.get('from') or creds['username'],
            to_addr, subject, html_body, attachments
        )

    msg = MIMEMultipart('mixed')
    msg['From']    = creds['from'] or creds['username']
    msg['To']      = to_addr
    msg['Subject'] = subject

    # ── HTML body + inline logo (CID) inside multipart/related ───────────────
    related = MIMEMultipart('related')
    alt     = MIMEMultipart('alternative')
    alt.attach(MIMEText(html_body, 'html', 'utf-8'))
    related.attach(alt)

    # Attach the TransCrypts logo so src="cid:transcrypts_logo" resolves in
    # email clients that honour CID inline images (Gmail, Apple Mail, Outlook).
    # Clients that strip inline images (e.g. ProtonMail web) fall back to the
    # styled text logo — which still looks correct on the white header.
    if _EMAIL_LOGO_BYTES:
        logo_part = MIMEImage(_EMAIL_LOGO_BYTES, 'png')
        logo_part.add_header('Content-ID', '<transcrypts_logo>')
        logo_part.add_header('Content-Disposition', 'inline',
                             filename='transcrypts_logo.png')
        related.attach(logo_part)

    msg.attach(related)

    # ── File attachments (resume, ICS, …) ────────────────────────────────────
    for fname, fdata, fmime in (attachments or []):
        if fmime == 'text/calendar':
            # ICS files must NOT be base64-encoded — use MIMEText with proper params
            # so calendar clients (ProtonMail, Apple Mail, Outlook) parse them correctly
            cal_str = fdata.decode('utf-8') if isinstance(fdata, bytes) else fdata
            part = MIMEText(cal_str, 'calendar', 'utf-8')
            part.set_param('method', 'REQUEST')
            part.add_header('Content-Disposition', 'attachment', filename=fname)
        else:
            main_type, sub_type = fmime.split('/', 1)
            part = MIMEBase(main_type, sub_type)
            part.set_payload(fdata)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment', filename=fname)
        msg.attach(part)

    try:
        # Single send path that works for every SMTP provider:
        #   • Port 465 → implicit SSL (SMTP_SSL)
        #   • Any other port → plain SMTP, opportunistic STARTTLS
        #   • Re-EHLO after STARTTLS per RFC 3207 — without this, some
        #     servers (notably Office 365) reject AUTH
        #   • 30s socket timeout caps how long we wait — under gunicorn's
        #     120s worker timeout even when sending to N interviewers
        if int(creds['port']) == 465:
            smtp_class = smtplib.SMTP_SSL
            with smtp_class(creds['server'], creds['port'], timeout=12) as s:
                s.ehlo()
                s.login(creds['username'], creds['password'])
                s.sendmail(creds['username'], to_addr, msg.as_bytes())
        else:
            with smtplib.SMTP(creds['server'], creds['port'], timeout=12) as s:
                s.ehlo()
                try:
                    s.starttls()
                    s.ehlo()                       # required after STARTTLS
                except smtplib.SMTPNotSupportedError:
                    pass                            # plaintext fallback (Bridge etc.)
                s.login(creds['username'], creds['password'])
                s.sendmail(creds['username'], to_addr, msg.as_bytes())
        return True, ''
    except smtplib.SMTPAuthenticationError as exc:
        return False, ('SMTP login failed — check MAIL_USERNAME and MAIL_PASSWORD. '
                       f'Server said: {exc.smtp_error.decode(errors="replace") if isinstance(exc.smtp_error, bytes) else exc.smtp_error}')
    except smtplib.SMTPRecipientsRefused as exc:
        return False, f'Recipient rejected: {to_addr} — {exc.recipients}'
    except smtplib.SMTPConnectError as exc:
        return False, ('Cannot connect to SMTP server — check MAIL_SERVER and MAIL_PORT. '
                       f'Server said: {exc}')
    except (smtplib.SMTPServerDisconnected, ConnectionRefusedError) as exc:
        return False, f'SMTP server disconnected — check MAIL_SERVER/MAIL_PORT. ({exc})'
    except Exception as exc:
        return False, f'{type(exc).__name__}: {exc}'


def _fmt_date(d):
    """Format YYYY-MM-DD → Monday, May 5, 2026."""
    try:
        from datetime import datetime as _dt
        return _dt.strptime(d, '%Y-%m-%d').strftime('%A, %B %-d, %Y')
    except Exception:
        return d or ''


def _fmt_interview_type(t):
    """Map internal format value to human-readable label for emails/UI."""
    return {'Video':    'Video Call',
            'Phone':    'Phone Call',
            'In-Person': 'In-Person'}.get(t, t or '')


def _generate_jitsi_link(applicant_id: int, position: str = '') -> str:
    """
    Generate a unique, unguessable Jitsi Meet room URL for a video interview.

    Why Jitsi:
      • No account, no app, no API keys — just a URL that anyone can join
      • Works in any modern browser (Chrome, Firefox, Safari, Edge)
      • End-to-end encrypted, privacy-focused (matches Proton ethos)
      • Free and open-source — zero IT burden

    Room-name format:
        transcrypts-<position-slug>-<applicant-id>-<24-hex-token>

    The 24-char random hex token (96 bits of entropy) makes the URL
    effectively un-guessable — a stranger would have to try 8e28 combinations
    to stumble into the room.
    """
    # Slugify the position: lowercase, alphanumerics + dashes only
    slug = ''.join(c if c.isalnum() else '-' for c in (position or 'interview').lower())
    slug = '-'.join(p for p in slug.split('-') if p)[:40]   # trim to 40 chars
    token = secrets.token_hex(12)                             # 24 hex chars
    room  = f"transcrypts-{slug}-{applicant_id}-{token}"
    return f"https://meet.jit.si/{room}"


def _is_jitsi_link(url: str) -> bool:
    """True if the URL points to a Jitsi Meet room (used for nicer email copy)."""
    return bool(url and 'meet.jit.si' in url)


def _fmt_time(t):
    """Format HH:MM → 10:30 AM."""
    try:
        from datetime import datetime as _dt
        for fmt in ('%H:%M', '%I:%M %p', '%I:%M%p'):
            try:
                return _dt.strptime(t.strip(), fmt).strftime('%I:%M %p').lstrip('0')
            except ValueError:
                pass
    except Exception:
        pass
    return t or ''


def _email_logo_header(subtitle: str) -> str:
    """
    Shared email header: green gradient banner with the real TransCrypts logo
    image (base64-embedded so no external URL is needed) + subtitle text.
    """
    # Logo image embedded via CID (the bytes are attached to the email by
    # _send_email).  On a WHITE header background — which matches the logo
    # PNG perfectly — even if a client (e.g. ProtonMail web) strips the
    # inline image, the fallback "TransCrypts" text in dark/green still looks
    # exactly like the brand mark on the home page.
    if _EMAIL_LOGO_BYTES:
        logo_html = (
            '<img src="cid:transcrypts_logo" alt="TransCrypts" height="48" '
            'style="display:block;height:48px;border:0;max-width:260px">'
        )
    else:
        logo_html = (
            '<span style="font-size:26px;font-weight:900;color:#1a1a1a;'
            'letter-spacing:-0.5px">Trans</span>'
            '<span style="font-size:26px;font-weight:900;color:#6DC49A;'
            'letter-spacing:-0.5px">Crypts</span>'
        )

    return f"""
  <!-- ── Email Header (WHITE — matches the logo image background) ─────── -->
  <div style="background:#ffffff;padding:22px 32px;
              border:1px solid #c2e0cf;border-bottom:none;
              border-radius:12px 12px 0 0">
    <table cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">
      <tr>
        <!-- The actual TransCrypts logo image -->
        <td style="vertical-align:middle">{logo_html}</td>
        <!-- Subtitle, right-aligned -->
        <td style="vertical-align:middle;text-align:right">
          <div style="display:inline-block;background:#e8f5ee;
                      padding:6px 14px;border-radius:20px">
            <span style="font-size:13px;color:#1a5c3e;font-weight:700;
                         letter-spacing:0.02em">{subtitle}</span>
          </div>
        </td>
      </tr>
    </table>
  </div>"""


def _candidate_email_html(applicant, interview_date, interview_time,
                           interview_type, position, contact_person, meeting_link):
    """Build the HTML body of the interview invitation sent to the candidate."""

    date_str = _fmt_date(interview_date)
    time_str = _fmt_time(interview_time) if interview_time else 'To be confirmed'
    contact  = contact_person or OFFICE_CONTACT_NAME
    floor    = f'<br>{OFFICE_FLOOR_ROOM}' if OFFICE_FLOOR_ROOM else ''

    if interview_type == 'In-Person':
        location_block = f"""
        <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0">
          <tr>
            <td style="background:#f0fdf4;border-left:4px solid #4aaa7a;
                       padding:20px 24px;border-radius:0 8px 8px 0">
              <h3 style="margin:0 0 16px;color:#1a5c3e;font-size:16px">
                &#128205; Interview Location
              </h3>
              <p style="margin:0 0 4px"><strong>{COMPANY_NAME}</strong></p>
              <p style="margin:0 0 2px">{OFFICE_ADDRESS}</p>
              {f'<p style="margin:0 0 4px">{OFFICE_FLOOR_ROOM}</p>' if OFFICE_FLOOR_ROOM else ''}
              <p style="margin:12px 0 0">
                <a href="https://maps.google.com/?q={OFFICE_ADDRESS.replace(' ', '+')}"
                   style="color:#3d8a64;font-weight:600">View on Google Maps &#8594;</a>
              </p>
            </td>
          </tr>
        </table>

        <h3 style="color:#1a5c3e;font-size:16px;margin:24px 0 12px">
          &#128694; When You Arrive
        </h3>
        <p style="margin:0 0 8px">
          Upon arrival, proceed directly to the <strong>elevators</strong> in the
          lobby — take them up to the <strong>18th Floor</strong> and go to
          <strong>Office 1820</strong>. There is no need to check in at the front desk.
        </p>
        <p style="margin:0 0 8px">
          Please allow an extra 10–15 minutes for your journey and building entry.
        </p>
        <p style="margin:0 0 24px">
          Please bring a valid <strong>photo ID</strong> as it may be required
          upon entry to the building.
          {f'<br>Ask for <strong>{contact}</strong> upon arrival.' if contact else ''}
        </p>

        <h3 style="color:#1a5c3e;font-size:16px;margin:0 0 12px">
          &#128663; Getting Here — By Car
        </h3>
        <p style="margin:0 0 8px">
          Our office is located in downtown Toronto's financial district near
          <strong>Front Street &amp; Bay Street</strong>.
        </p>
        <p style="margin:0 0 8px">
          From the <strong>Gardiner Expressway</strong>: take the
          <strong>Bay Street / Yonge Street</strong> exit, head north on Bay Street,
          then turn west on Front Street.
        </p>
        <p style="margin:0 0 16px">
          Paid parking is available at nearby lots and garages, including
          <strong>Green P Parking at 10 Bay Street</strong> and
          <strong>Union Station Parking at 65 Front Street West</strong>.
          Please note that parking costs are <strong>at your own expense</strong>.
        </p>

        <h3 style="color:#1a5c3e;font-size:16px;margin:0 0 12px">
          &#128647; Getting Here — By Public Transit
        </h3>
        <p style="margin:0 0 8px">
          The most convenient option is the <strong>TTC subway</strong>:
        </p>
        <ul style="margin:0 0 8px;padding-left:20px">
          <li style="margin-bottom:4px">
            Take <strong>Line 1 (Yonge–University)</strong> to
            <strong>Union Station</strong>.
          </li>
          <li style="margin-bottom:4px">
            Exit the station at the <strong>Front Street / Bay Street</strong> exit.
          </li>
          <li style="margin-bottom:4px">
            Walk west along <strong>Front Street</strong> — our building will be
            on your right.
          </li>
        </ul>
        <p style="margin:0 0 24px">
          GO Train passengers can also arrive directly at
          <strong>Union Station</strong>, which connects to the same street-level exit.
        </p>
        """
    else:
        mode = 'phone call' if interview_type == 'Phone' else 'video call'
        link_line = ''
        if meeting_link and interview_type == 'Video':
            # Big prominent JOIN button for video interviews
            jitsi_note = ""
            if _is_jitsi_link(meeting_link):
                jitsi_note = """
            <p style="margin:14px 0 0;font-size:12px;color:#6b7280;
                      text-align:center;line-height:1.5">
              &#128274; This meeting uses <strong>Jitsi Meet</strong> — a free,
              end-to-end encrypted video service.<br>
              <strong>No account or app required</strong> — just click the
              button above in any modern browser (Chrome, Firefox, Safari, Edge).<br>
              <span style="color:#94a3b8">
                If you arrive before the interviewer, you may briefly see a
                "waiting for the host" screen — this is normal. You'll be
                admitted as soon as they join.
              </span>
            </p>"""
            link_line = f"""
            <table width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0 4px">
              <tr><td align="center">
                <a href="{meeting_link}" target="_blank"
                   style="display:inline-block;background:linear-gradient(135deg,#4aaa7a,#6DC49A);
                          color:#ffffff;text-decoration:none;padding:14px 32px;
                          border-radius:8px;font-size:15px;font-weight:700;
                          letter-spacing:0.02em">
                  &#127909; Join Video Interview
                </a>
              </td></tr>
            </table>
            <p style="margin:8px 0 0;font-size:12px;color:#6b7280;text-align:center;
                      word-break:break-all">
              Or copy this link into your browser:<br>
              <a href="{meeting_link}" style="color:#3d8a64">{meeting_link}</a>
            </p>{jitsi_note}"""
        elif meeting_link:
            link_line = f"""
            <p style="margin:12px 0 0">
              <strong>Meeting Link:</strong>
              <a href="{meeting_link}" style="color:#3d8a64;font-weight:600">{meeting_link}</a>
            </p>"""
        location_block = f"""
        <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0">
          <tr>
            <td style="background:#f0fdf4;border-left:4px solid #4aaa7a;
                       padding:20px 24px;border-radius:0 8px 8px 0">
              <h3 style="margin:0 0 12px;color:#1a5c3e;font-size:16px">
                &#128187; {_fmt_interview_type(interview_type)}
              </h3>
              <p style="margin:0">
                This interview will be conducted as a <strong>{mode}</strong>.
                Please ensure you are in a quiet location with a stable
                {'internet connection' if interview_type == 'Video' else 'phone signal'}
                at the time of the interview.
              </p>
              {link_line}
            </td>
          </tr>
        </table>
        """

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;color:#1f2937;max-width:680px;
             margin:0 auto;padding:32px 16px;background:#f2f8f5">

  {_email_logo_header("Human Resources Department")}

  <!-- Body -->
  <div style="background:#fff;padding:32px;border:1px solid #c2e0cf;
              border-top:none;border-radius:0 0 12px 12px">

    <h2 style="margin:0 0 24px;font-size:20px;font-weight:700;color:#1a5c3e;
               border-bottom:2px solid #e8f5ee;padding-bottom:16px">
      Interview Invitation &mdash; {position} at {COMPANY_NAME}
    </h2>

    <p style="margin:0 0 20px;font-size:16px">
      Dear <strong>{applicant['name']}</strong>,
    </p>
    <p style="margin:0 0 20px">
      We are pleased to invite you for an interview for the position of
      <strong style="color:#1a5c3e">{position}</strong> at
      <strong>{COMPANY_NAME}</strong>.
      Please review the details below carefully.
    </p>

    <!-- Interview Details table -->
    <table width="100%" cellpadding="0" cellspacing="0"
           style="border:1px solid #c2e0cf;border-radius:8px;
                  margin:0 0 24px;overflow:hidden;border-collapse:separate;
                  border-spacing:0">
      <tr style="background:linear-gradient(135deg,#4aaa7a,#6DC49A)">
        <td colspan="2" style="padding:12px 20px;color:#fff;
                                font-weight:700;font-size:14px;
                                border-radius:8px 8px 0 0">
          &#128197; Interview Details
        </td>
      </tr>
      <tr>
        <td style="padding:12px 20px;font-weight:600;width:38%;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Position</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px;color:#1a5c3e;font-weight:600">{position}</td>
      </tr>
      <tr style="background:#f7fdf9">
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Date</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px">{date_str}</td>
      </tr>
      <tr>
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Time</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px">{time_str}</td>
      </tr>
      <tr style="background:#f7fdf9">
        <td style="padding:12px 20px;font-weight:600;font-size:14px;
                   color:#374151">Format</td>
        <td style="padding:12px 20px;font-size:14px">{_fmt_interview_type(interview_type)}</td>
      </tr>
    </table>

    {location_block}

    <p style="margin:24px 0 8px">
      If you have any questions or need to reschedule, please reply to this
      email or contact our HR team as soon as possible.
    </p>
    <p style="margin:0 0 32px">
      We look forward to speaking with you.
    </p>

    <p style="margin:0;color:#6b7280;font-size:13px;
              border-top:1px solid #e8f5ee;padding-top:20px">
      Best regards,<br>
      <strong>Human Resources Team</strong><br>
      <span style="color:#3d8a64;font-weight:700">Trans</span><span
            style="color:#6DC49A;font-weight:700">Crypts</span>
    </p>
  </div>
</body></html>"""


def _interviewer_email_html(applicant, position, interview_date, interview_time,
                             interview_type, interviewer_name,
                             contact_person, meeting_link):
    """Build the HTML body of the notification sent to the interviewer."""
    from datetime import datetime as _dt, timedelta as _td
    import urllib.parse

    date_str = _fmt_date(interview_date)
    time_str = _fmt_time(interview_time) if interview_time else 'See invitation'

    # Real location: office address (+ floor/room) for in-person, meeting link
    # for virtual. contact_person is the reception greeter (NOT the location).
    if interview_type == 'In-Person':
        loc_str = OFFICE_ADDRESS
        if OFFICE_FLOOR_ROOM:
            loc_str = f"{OFFICE_ADDRESS}<br><span style='color:#1a5c3e;font-weight:600'>{OFFICE_FLOOR_ROOM}</span>"
    else:
        loc_str = meeting_link or interview_type

    # ── Build Add-to-Calendar URLs ────────────────────────────────────────────
    gcal_url    = ''
    outlook_url = ''
    try:
        if interview_date and interview_time:
            dt_s = _dt.strptime(f"{interview_date} {interview_time[:5]}", '%Y-%m-%d %H:%M')
        elif interview_date:
            dt_s = _dt.strptime(interview_date, '%Y-%m-%d').replace(hour=9)
        else:
            dt_s = None

        if dt_s:
            dt_e     = dt_s + _td(hours=1)
            ev_title = f"Interview: {applicant['name']} — {position}"
            ev_desc  = (f"Interview with {applicant['name']} for the position of {position}. "
                        f"Format: {interview_type}. Location/Link: {loc_str}")

            # Google Calendar
            gc_s = dt_s.strftime('%Y%m%dT%H%M%S')
            gc_e = dt_e.strftime('%Y%m%dT%H%M%S')
            gcal_url = (
                "https://calendar.google.com/calendar/render?action=TEMPLATE"
                f"&text={urllib.parse.quote(ev_title)}"
                f"&dates={gc_s}/{gc_e}"
                f"&details={urllib.parse.quote(ev_desc)}"
                f"&location={urllib.parse.quote(loc_str or '')}"
            )

            # Outlook.com
            ol_s = dt_s.strftime('%Y-%m-%dT%H:%M:%S')
            ol_e = dt_e.strftime('%Y-%m-%dT%H:%M:%S')
            outlook_url = (
                "https://outlook.live.com/calendar/0/deeplink/compose"
                "?path=/calendar/action/compose&rru=addevent"
                f"&subject={urllib.parse.quote(ev_title)}"
                f"&startdt={urllib.parse.quote(ol_s)}"
                f"&enddt={urllib.parse.quote(ol_e)}"
                f"&body={urllib.parse.quote(ev_desc)}"
                f"&location={urllib.parse.quote(loc_str or '')}"
            )
    except Exception:
        pass

    # Calendar button block — shown only when we have valid dates
    if gcal_url:
        cal_block = f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 28px">
      <tr>
        <td style="background:#f0fdf4;border:1px solid #c2e0cf;border-radius:10px;
                   padding:20px 24px;text-align:center">
          <p style="margin:0 0 16px;font-size:14px;font-weight:700;color:#1a5c3e">
            &#128197;&nbsp; Add this interview to your calendar
          </p>
          <table cellpadding="0" cellspacing="0" style="margin:0 auto">
            <tr>
              <td style="padding:0 6px 8px">
                <a href="{gcal_url}" target="_blank"
                   style="display:inline-block;background:linear-gradient(135deg,#4aaa7a,#6DC49A);
                          color:#ffffff;text-decoration:none;padding:11px 22px;
                          border-radius:7px;font-size:13px;font-weight:700;
                          letter-spacing:0.01em">
                  &#128197; Add to Google Calendar
                </a>
              </td>
              <td style="padding:0 6px 8px">
                <a href="{outlook_url}" target="_blank"
                   style="display:inline-block;background:#0078d4;
                          color:#ffffff;text-decoration:none;padding:11px 22px;
                          border-radius:7px;font-size:13px;font-weight:700;
                          letter-spacing:0.01em">
                  &#128197; Add to Outlook Calendar
                </a>
              </td>
            </tr>
          </table>
          <p style="margin:10px 0 0;font-size:11px;color:#6b7280">
            Or open the attached <strong>.ics</strong> file to add to Apple Calendar
            or any other calendar app
          </p>
        </td>
      </tr>
    </table>"""
    else:
        cal_block = ''

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;color:#1f2937;max-width:680px;
             margin:0 auto;padding:32px 16px;background:#f2f8f5">

  {_email_logo_header("Interview Notification")}

  <!-- Body -->
  <div style="background:#fff;padding:32px;border:1px solid #c2e0cf;
              border-top:none;border-radius:0 0 12px 12px">

    <p style="margin:0 0 20px;font-size:16px">
      Dear <strong>{interviewer_name}</strong>,
    </p>
    <p style="margin:0 0 20px">
      An interview has been scheduled. The candidate's resume is attached for
      your review. Please use the buttons below to add this interview to your
      calendar.
    </p>

    <table width="100%" cellpadding="0" cellspacing="0"
           style="border:1px solid #c2e0cf;border-radius:8px;
                  margin:0 0 24px;overflow:hidden;border-collapse:separate;
                  border-spacing:0">
      <tr style="background:linear-gradient(135deg,#4aaa7a,#6DC49A)">
        <td colspan="2" style="padding:12px 20px;color:#fff;
                                font-weight:700;font-size:14px;
                                border-radius:8px 8px 0 0">
          &#128203; Interview Schedule
        </td>
      </tr>
      <tr>
        <td style="padding:12px 20px;font-weight:600;width:38%;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Candidate</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px;font-weight:600">{applicant['name']}</td>
      </tr>
      <tr style="background:#f7fdf9">
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Position</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px;color:#1a5c3e;font-weight:600">{position}</td>
      </tr>
      <tr>
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Date</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px">{date_str}</td>
      </tr>
      <tr style="background:#f7fdf9">
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Time</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px">{time_str}</td>
      </tr>
      <tr>
        <td style="padding:12px 20px;font-weight:600;
                   border-bottom:1px solid #e8f5ee;font-size:14px;
                   color:#374151">Format</td>
        <td style="padding:12px 20px;border-bottom:1px solid #e8f5ee;
                   font-size:14px">{_fmt_interview_type(interview_type)}</td>
      </tr>
      <tr style="background:#f7fdf9">
        <td style="padding:12px 20px;font-weight:600;font-size:14px;
                   color:#374151;{'border-bottom:1px solid #e8f5ee;' if interview_type == 'In-Person' and contact_person else ''}">
          {'Location' if interview_type == 'In-Person' else 'Link / Details'}
        </td>
        <td style="padding:12px 20px;font-size:14px;{'border-bottom:1px solid #e8f5ee;' if interview_type == 'In-Person' and contact_person else ''}">
          {('<a href="' + meeting_link + '" style="color:#3d8a64;font-weight:600;word-break:break-all">' + meeting_link + '</a>') if interview_type == 'Video' and meeting_link else loc_str}
        </td>
      </tr>
      {f'''<tr>
        <td style="padding:12px 20px;font-weight:600;font-size:14px;
                   color:#374151">Reception Contact</td>
        <td style="padding:12px 20px;font-size:14px">
          <span style="color:#1a5c3e;font-weight:600">{contact_person}</span>
          <span style="color:#6b7280;font-size:12px"> &nbsp;— candidate will ask for this person at reception</span>
        </td>
      </tr>''' if interview_type == 'In-Person' and contact_person else ''}
    </table>

    {('''<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 16px">
      <tr><td align="center" style="padding:6px 0 14px">
        <a href="''' + meeting_link + '''" target="_blank"
           style="display:inline-block;background:linear-gradient(135deg,#4aaa7a,#6DC49A);
                  color:#ffffff;text-decoration:none;padding:13px 30px;
                  border-radius:8px;font-size:14px;font-weight:700;
                  letter-spacing:0.02em">
          &#127909; Join Video Interview
        </a>
      </td></tr>
    </table>''' + ('''
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px">
      <tr><td style="background:#fff8e6;border-left:4px solid #f0b400;
                     border-radius:0 8px 8px 0;padding:14px 18px">
        <p style="margin:0 0 6px;color:#8a6d00;font-weight:700;font-size:14px">
          &#9888;&#65039; Important — you are the meeting host
        </p>
        <p style="margin:0;font-size:13px;color:#5a4a00;line-height:1.55">
          When you join, click the blue <strong>"Log-in"</strong> button and
          sign in with <strong>Google</strong> or <strong>Facebook</strong> —
          this starts the meeting as moderator and admits the candidate.
          One-time, takes 5 seconds. The candidate doesn't need to log in.
        </p>
      </td></tr>
    </table>''' if _is_jitsi_link(meeting_link) else '''
    <table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 24px">
      <tr><td align="center" style="font-size:12px;color:#6b7280;padding:0 16px">
        Google Calendar &amp; Outlook reminders below also include this link.
      </td></tr>
    </table>''')) if interview_type == 'Video' and meeting_link else ''}

    {cal_block}

    <p style="margin:0 0 8px">
      The candidate's resume is attached to this email for your review.
    </p>
    <p style="margin:0 0 32px">
      Please do not hesitate to contact HR if you have any questions.
    </p>

    <p style="margin:0;color:#6b7280;font-size:13px;
              border-top:1px solid #e8f5ee;padding-top:20px">
      Best regards,<br>
      <strong>Human Resources Team</strong><br>
      <span style="color:#3d8a64;font-weight:700">Trans</span><span
            style="color:#6DC49A;font-weight:700">Crypts</span>
    </p>
  </div>
</body></html>"""


@app.route('/interviews/add/<int:applicant_id>', methods=['POST'])
@role_required(*CAN_NOTES)
def add_interview(applicant_id):
    """Add one interview record per selected interviewer; optionally send emails."""
    interview_date     = request.form.get('interview_date', '').strip()
    interview_time     = request.form.get('interview_time', '').strip()
    interview_type     = request.form.get('interview_type', 'In-Person').strip()
    interview_position = request.form.get('interview_position', '').strip()
    contact_person     = request.form.get('contact_person', '').strip()
    meeting_link       = request.form.get('meeting_link', '').strip()
    outcome            = request.form.get('outcome', 'Pending')
    interview_notes    = request.form.get('interview_notes', '').strip()
    send_candidate     = request.form.get('send_candidate_email') == '1'
    send_interviewer   = request.form.get('send_interviewer_email') == '1'

    # ── Collect interviewers ──────────────────────────────────────────────────
    # List of staff IDs chosen via checkboxes
    iv_sel_ids  = request.form.getlist('iv_sel')
    # Manual "Other" entry
    other_name  = request.form.get('other_name',  '').strip()
    other_desig = request.form.get('other_desig', '').strip()
    other_email = request.form.get('other_email', '').strip()

    with get_db() as conn:
        applicant = conn.execute(
            'SELECT * FROM applicants WHERE id=?', (applicant_id,)
        ).fetchone()
        if not applicant:
            flash('Applicant not found.', 'error')
            return redirect(url_for('index'))

        # Build list of (name, designation, email) tuples
        interviewers = []
        for sid in iv_sel_ids:
            row = conn.execute(
                'SELECT * FROM staff WHERE id=?', (sid,)
            ).fetchone()
            if row:
                interviewers.append((
                    row['name'],
                    row['designation'] or '',
                    row['email'] or ''
                ))

        # Manual "Other" entry — included if a name was typed
        if other_name:
            interviewers.append((other_name, other_desig, other_email))

        if not interviewers:
            flash('Please select at least one interviewer.', 'error')
            return redirect(url_for('view_resume', applicant_id=applicant_id))

        # ── Auto-create Jitsi Meet link (Video Call, no manual link) ────────
        # Generates a unique, unguessable Jitsi room URL — no account, no
        # app, no API keys. Works in any browser. Privacy-focused.
        if interview_type == 'Video' and not meeting_link:
            position_for_room = interview_position or applicant['specialty'] or 'interview'
            meeting_link = _generate_jitsi_link(applicant_id, position_for_room)
            flash(f'Jitsi Meet room created automatically: {meeting_link}', 'success')

        # Remove any previous interview records for this applicant before
        # saving the new/updated schedule — keeps exactly one set of records
        conn.execute('DELETE FROM interviews WHERE applicant_id=?', (applicant_id,))

        # Insert one record per interviewer (same session details, different person)
        for iv_name, iv_desig, iv_email in interviewers:
            conn.execute(
                'INSERT INTO interviews '
                '(applicant_id, interview_date, interview_time, interview_type, '
                ' interview_position, interviewer_name, interviewer_designation, '
                ' interviewer_email, contact_person, meeting_link, outcome, interview_notes) '
                'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                (applicant_id, interview_date or None, interview_time or None,
                 interview_type, interview_position or None,
                 iv_name, iv_desig,
                 iv_email or None, contact_person or None,
                 meeting_link or None, outcome, interview_notes)
            )

        # Keep the applicant's hiring status / date in sync.
        # NB: SQL string literals must use single quotes (Postgres treats
        # double quotes as identifier delimiters).
        conn.execute(
            "UPDATE applicants SET interview_date=?, interview_time=?, interview_type=?, "
            "hiring_status='Interview Scheduled' WHERE id=?",
            (interview_date or None, interview_time or None, interview_type, applicant_id)
        )
        conn.commit()

    position = interview_position or (applicant['specialty'] or 'the open position').strip()
    email_results = []

    # ── Email to candidate ────────────────────────────────────────────────────
    if send_candidate and applicant['email']:
        html = _candidate_email_html(
            applicant, interview_date, interview_time,
            interview_type, position, contact_person, meeting_link)
        ok, err = _send_email(
            applicant['email'],
            f"Interview Invitation — {position} at {COMPANY_NAME}",
            html)
        email_results.append((
            ok,
            f"Candidate ({applicant['email']}): {'sent ✓' if ok else f'FAILED — {err}'}"
        ))
        log_action('INTERVIEW EMAIL', applicant['name'],
                   f'Candidate → {applicant["email"]}: '
                   f'{"sent OK" if ok else f"FAILED — {err}"}')
    elif send_candidate and not applicant['email']:
        email_results.append((False,
            'Candidate email not sent — no email address on record.'))

    # ── Email to each interviewer ─────────────────────────────────────────────
    # Read the resume bytes ONCE so all interviewer emails reuse them
    resume_attachment = None
    if send_interviewer and applicant['resume_filename']:
        resume_data = _storage.read_file(applicant['resume_filename'])
        if resume_data:
            ext = applicant['resume_filename'].rsplit('.', 1)[-1].lower()
            mime_map = {
                'pdf':  'application/pdf',
                'docx': 'application/vnd.openxmlformats-officedocument'
                        '.wordprocessingml.document',
                'doc':  'application/msword'
            }
            resume_attachment = (
                f"{applicant['name']} — Resume.{ext}",
                resume_data,
                mime_map.get(ext, 'application/octet-stream')
            )

    if send_interviewer:
        for iv_name, iv_desig, iv_email in interviewers:
            if not iv_email:
                email_results.append((False,
                    f'Interviewer {iv_name}: no email address — notification skipped.'))
                continue

            html = _interviewer_email_html(
                applicant, position, interview_date, interview_time,
                interview_type, iv_name, contact_person, meeting_link)
            attachments = []
            if resume_attachment:
                attachments.append(resume_attachment)
            ics = _generate_ics(applicant['name'], position, interview_date,
                                interview_time, interview_type,
                                meeting_link, contact_person, iv_email)
            if ics:
                attachments.append(('interview_invite.ics', ics.encode('utf-8'),
                                     'text/calendar'))

            ok, err = _send_email(
                iv_email,
                f"Interview Scheduled — {applicant['name']} for {position} "
                f"on {_fmt_date(interview_date)}",
                html, attachments)
            email_results.append((
                ok,
                f"Interviewer {iv_name} ({iv_email}): "
                f"{'sent ✓' if ok else f'FAILED — {err}'}"
            ))
            log_action('INTERVIEW EMAIL', applicant['name'],
                       f'Interviewer {iv_name} → {iv_email}: '
                       f'{"sent OK" if ok else f"FAILED — {err}"}')

    iv_names_str = ', '.join(iv[0] for iv in interviewers)
    log_action('INTERVIEW ADDED', applicant['name'],
               f'Interviewers: {iv_names_str} — {interview_type} — Outcome: {outcome}')

    # Show every email outcome as its own flash (success or warning)
    for ok, msg in email_results:
        flash(f'Email — {msg}', 'success' if ok else 'warning')

    n = len(interviewers)
    flash(f'Interview scheduled with {n} interviewer{"s" if n != 1 else ""}.', 'success')
    return redirect(url_for('view_resume', applicant_id=applicant_id))


@app.route('/interviews/delete/<int:interview_id>', methods=['POST'])
@role_required(*CAN_EDIT)
def delete_interview(interview_id):
    """Remove a single interview record.
    If no interviews remain, revert the applicant status to Under Review
    and clear the stored interview date / time / type.
    """
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM interviews WHERE id=?', (interview_id,)
        ).fetchone()
        if not row:
            flash('Interview record not found.', 'error')
            return redirect(url_for('index'))

        applicant_id = row['applicant_id']
        conn.execute('DELETE FROM interviews WHERE id=?', (interview_id,))

        # How many interviews still exist for this applicant?
        remaining = conn.execute(
            'SELECT COUNT(*) FROM interviews WHERE applicant_id=?',
            (applicant_id,)
        ).fetchone()[0]

        if remaining == 0:
            # No interviews left — revert to Under Review, clear dates.
            # NB: SQL string literals MUST use single quotes — Postgres treats
            # double-quoted text as identifiers (column / table names).
            conn.execute(
                "UPDATE applicants "
                "SET hiring_status='Under Review', "
                "    interview_date=NULL, "
                "    interview_time=NULL, "
                "    interview_type=NULL "
                "WHERE id=? AND hiring_status='Interview Scheduled'",
                (applicant_id,)
            )
            flash('Interview record removed — status reset to Under Review.', 'success')
        else:
            # Other interviews still exist — keep the most recent date on record
            latest = conn.execute(
                '''SELECT interview_date, interview_time, interview_type
                   FROM interviews WHERE applicant_id=?
                   ORDER BY interview_date DESC, created_at DESC LIMIT 1''',
                (applicant_id,)
            ).fetchone()
            if latest:
                conn.execute(
                    '''UPDATE applicants
                       SET interview_date=?, interview_time=?, interview_type=?
                       WHERE id=?''',
                    (latest['interview_date'], latest['interview_time'],
                     latest['interview_type'], applicant_id)
                )
            flash('Interview record removed.', 'success')

        conn.commit()
        log_action('INTERVIEW DELETED', f'Interviewer: {row["interviewer_name"]}')
        return redirect(url_for('view_resume', applicant_id=applicant_id))


@app.route('/hiring-status/<int:applicant_id>', methods=['POST'])
@role_required(*CAN_NOTES)
def update_hiring_status(applicant_id):
    """Update the overall hiring decision for an applicant."""
    hiring_status      = request.form.get('hiring_status', 'Under Review')
    decision_notes     = request.form.get('decision_notes', '').strip()
    # Interview-specific
    interview_date     = request.form.get('interview_date', '').strip() or None
    interview_time     = request.form.get('interview_time', '').strip() or None
    interview_type     = request.form.get('interview_type', 'In-Person').strip()
    interview_outcome  = request.form.get('interview_outcome', 'Pending')
    # Hired-specific
    hire_date          = request.form.get('hire_date', '').strip() or None
    # Rejected-specific
    decision_date      = request.form.get('decision_date', '').strip() or None
    rejection_reason   = request.form.get('rejection_reason', '').strip()

    valid_statuses = ('Under Review', 'Interview Scheduled', 'Hired', 'Rejected', 'On Hold')
    if hiring_status not in valid_statuses:
        hiring_status = 'Under Review'

    with get_db() as conn:
        applicant = conn.execute(
            'SELECT * FROM applicants WHERE id=?', (applicant_id,)
        ).fetchone()
        if not applicant:
            flash('Applicant not found.', 'error')
            return redirect(url_for('index'))
        conn.execute('''
            UPDATE applicants
            SET hiring_status=?, hire_date=?, rejection_reason=?,
                interview_date=?, interview_time=?, interview_type=?,
                interview_outcome=?, decision_date=?, decision_notes=?
            WHERE id=?
        ''', (hiring_status, hire_date, rejection_reason,
              interview_date, interview_time, interview_type,
              interview_outcome, decision_date, decision_notes, applicant_id))

        # ── Keep the interview records in sync with the Change-Status form ──
        # When the user edits date/time/format/outcome here, propagate the
        # change to every existing interview record for this applicant so the
        # Interview Records table and the Schedule Interview form pre-fill
        # both reflect the new values immediately.
        if hiring_status == 'Interview Scheduled':
            conn.execute(
                'UPDATE interviews '
                'SET interview_date=?, interview_time=?, interview_type=?, outcome=? '
                'WHERE applicant_id=?',
                (interview_date, interview_time, interview_type,
                 interview_outcome, applicant_id)
            )

        conn.commit()

    detail = f'Status: {hiring_status}'
    if decision_notes:    detail += f' | Notes: {decision_notes}'
    if interview_date:    detail += f' | Interview: {interview_date}'
    if hire_date:         detail += f' | Hire date: {hire_date}'
    if decision_date:     detail += f' | Decision date: {decision_date}'
    if rejection_reason:  detail += f' | Reason: {rejection_reason}'
    log_action('HIRING STATUS UPDATED', applicant['name'], detail)
    flash(f'Status updated to "{hiring_status}".', 'success')
    return redirect(url_for('view_resume', applicant_id=applicant_id))


def _parse_saved_file(resume_filename):
    """
    Load an already-saved resume file (local OR Supabase Storage), extract
    its text, and return a parsed-fields dict.
    Returns None if the file is missing or unreadable.
    """
    file_data = _storage.read_file(resume_filename)
    if not file_data:
        return None
    try:
        text = _extract_text_from_file(file_data, resume_filename.lower())
        if not text.strip():
            return None
        return _smart_parse(text)
    except Exception:
        return None


def _extract_text_from_file(file_data, filename):
    """Extract plain text from PDF, DOCX, or image file. Returns text string.

    For PDFs, falls back to bounding-box-based word extraction when default
    extraction yields suspiciously long concatenated words — common in PDFs
    with tight kerning where the standard extractor loses inter-word spaces
    (e.g. "ALEXEY KUVSHINOV" coming back as "ALEXEYKUVSHINOV").
    """
    import io

    if filename.endswith('.pdf'):
        import pdfplumber
        text_parts = []
        with pdfplumber.open(io.BytesIO(file_data)) as pdf:
            for page in pdf.pages:
                t = page.extract_text() or ''
                # Detect bad spacing — any word ≥ 16 chars without separators
                # is almost certainly two real words concatenated
                bad_kerning = any(len(w) >= 16 for w in t.split())
                if bad_kerning:
                    try:
                        # Re-extract using positional words; pdfplumber respects
                        # the underlying glyph bounding boxes so word breaks
                        # match what the eye sees in the PDF reader
                        words = page.extract_words(
                            x_tolerance=2, y_tolerance=3,
                            keep_blank_chars=False, use_text_flow=True
                        )
                        if words:
                            # Group words into lines by similar 'top' coordinate
                            lines, cur_top, cur_line = [], None, []
                            for w in words:
                                if cur_top is None or abs(w['top'] - cur_top) < 4:
                                    cur_line.append(w['text'])
                                    cur_top = w['top'] if cur_top is None else cur_top
                                else:
                                    lines.append(' '.join(cur_line))
                                    cur_line = [w['text']]
                                    cur_top = w['top']
                            if cur_line:
                                lines.append(' '.join(cur_line))
                            t = '\n'.join(lines)
                    except Exception:
                        pass        # fall back to whatever extract_text gave us
                if t:
                    text_parts.append(t)
        return '\n'.join(text_parts)

    elif filename.endswith('.docx'):
        from docx import Document
        doc = Document(io.BytesIO(file_data))
        return '\n'.join(p.text for p in doc.paragraphs if p.text.strip())

    return ''


# Words that appear in resume section headings — never part of a person's name
_SECTION_WORDS = {
    'summary', 'profile', 'experience', 'education', 'skills', 'objective',
    'contact', 'information', 'details', 'overview', 'background', 'qualifications',
    'certifications', 'certification', 'achievements', 'achievement', 'projects',
    'references', 'languages', 'hobbies', 'interests', 'history', 'employment',
    'career', 'professional', 'personal', 'technical', 'about', 'introduction',
    'resume', 'curriculum', 'vitae', 'executive', 'academic', 'awards',
    'accomplishments', 'activities', 'publications', 'volunteer', 'leadership',
    'training', 'courses', 'course', 'expertise', 'competencies', 'areas',
    'highlights', 'key', 'core', 'additional', 'other', 'miscellaneous',
    'portfolio', 'internship', 'work', 'job', 'position', 'responsibilities',
    'goal', 'statement', 'declaration', 'appendix', 'annexure',
}

# 2-letter (and a few 3-letter) location codes — not real name tokens.
# Catches address lines like "Toronto, ON" → reversed by comma logic into
# "ON Toronto", which would otherwise pass the looks-like-a-name checks.
_LOCATION_CODES = {
    # Canadian provinces & territories
    'on','bc','qc','ab','mb','sk','ns','nb','pe','nl','nt','yt','nu',
    # US states
    'al','ak','az','ar','ca','co','ct','de','fl','ga','hi','id','il','in','ia',
    'ks','ky','la','me','md','ma','mi','mn','ms','mo','mt','ne','nv','nh','nj',
    'nm','ny','nc','nd','oh','ok','or','pa','ri','sc','sd','tn','tx','ut','vt',
    'va','wa','wv','wi','wy','dc',
    # Country / region codes
    'usa','uk','eu','uae','ksa','can','gbr','aus','ind','pak',
    # Common non-name words that can appear in address-style lines
    'street','ave','avenue','road','blvd','suite','apt','floor','postal','zip',
}

# Job-title words that are sometimes mistakenly picked up as the applicant's name
# (e.g. "Team Lead", "Senior Engineer" appearing on the line right after the name)
_TITLE_WORDS = {
    'lead', 'manager', 'director', 'engineer', 'developer', 'analyst',
    'consultant', 'specialist', 'coordinator', 'supervisor', 'executive',
    'officer', 'head', 'chief', 'senior', 'junior', 'associate', 'intern',
    'architect', 'designer', 'administrator', 'representative', 'agent',
    'technician', 'operator', 'assistant', 'secretary', 'team', 'staff',
    'advisor', 'trainer', 'instructor', 'programmer', 'scientist',
    'researcher', 'accountant', 'auditor', 'recruiter', 'strategist',
    'freelancer', 'contractor', 'president', 'vice', 'founder', 'owner',
    'principal', 'partner', 'fellow', 'lecturer', 'professor', 'doctor',
}


def _looks_like_name(line):
    """Return True if a line of text looks like a real person's full name.

    Common false-positive sources that we filter out:
    - Section headings  : "Core Technical Skills", "Work Experience"
    - Job titles        : "Team Lead", "Senior Engineer"
    - Template text     : "ResumeAI", "Curriculum Vitae"
    - Concatenated words: "Coretechnicalskills" (section title run together)
    """
    import re
    line = line.strip()

    # Must be a reasonable length
    if not line or len(line) > 60 or len(line) < 4:
        return False

    # Normalise ALL-CAPS lines (e.g. "JOHN SMITH" → "John Smith")
    if line.isupper():
        line = line.title()

    words = line.split()

    # Require at least 2 words — professional resumes always show First + Last.
    # Single-word entries are almost always section headings or template text.
    if not (2 <= len(words) <= 5):
        return False

    # Every word must look like a proper name token.
    # Allow lowercase particles: de, van, von, bin, binti, el, al, ul, di, da, etc.
    particles  = {'de','van','von','bin','binti','binte','el','al','ul','di','da',
                  'du','del','della','dos','das','les','la','le','lo','ben','abd',
                  'der','den','ter','ten','zu','zum','zur','ibn','abu','bint',
                  'md','dr','mr','ms','mrs','prof','op','af','av'}
    name_token = re.compile(r"^[A-Z][a-zA-Z'\-\.]{0,29}$")
    if not all(name_token.match(w) or w.lower() in particles for w in words):
        return False

    # Reject if ANY word is a known section heading
    if any(w.lower() in _SECTION_WORDS for w in words):
        return False

    # Reject if ANY word is a known job title
    # (catches "Team Lead", "Senior Developer", "Head of Marketing", etc.)
    if any(w.lower() in _TITLE_WORDS for w in words):
        return False

    # Reject if ANY word is a known location code / address word
    # (catches "ON Toronto" produced from a reversed "Toronto, ON" address line)
    if any(w.lower() in _LOCATION_CODES for w in words):
        return False

    # Reject words that EMBED section-heading text as a substring.
    # This catches concatenated headings like "Coretechnicalskills" (contains "skills"),
    # template watermarks like "ResumeAI" (contains "resume"), etc.
    for w in words:
        wl = w.lower()
        if any(sw in wl and len(sw) >= 4 for sw in _SECTION_WORDS):
            return False

    # Reject lines that are obviously contact/metadata, not names
    bad_phrases = [
        'page ', 'curriculum vitae', 'cover letter', 'date of birth',
        'place of birth', 'nationality', 'marital', 'linkedin', 'github',
        'www.', 'http', '.com', '.org', '.net', '@',
    ]
    line_lower = line.lower()
    if any(p in line_lower for p in bad_phrases):
        return False

    return True


def _normalise_name_line(ln):
    """
    Clean up a raw text line before checking if it looks like a name.

    Handles:
      - ALL-CAPS lines          : "ALEXEY KUVSHINOV"   → "Alexey Kuvshinov"
      - Letter-spaced styling   : "A L I , A L-M A H M U D"
                                                       → "Ali Al-Mahmud"
      - Last, First format      : "ALI, AL-MAHMUD"     → "Ali Al-Mahmud"
      - Trailing punctuation    : "John Smith."        → "John Smith"
      - Inline contact info     : "ALEXEY KUVSHINOV lyoha_@hotmail.com" →
                                  "Alexey Kuvshinov"  (email stripped)

    Does NOT swap parts when the comma separates an address —
    e.g. "Toronto, ON" stays as "Toronto, ON" (and is later rejected by
    _looks_like_name's location-code filter).
    """
    import re
    ln = ln.strip().rstrip('.,;')

    # Strip inline contact info that some PDFs render on the same line as the name
    # (emails, URLs, phone numbers). After removal we may be left with just the name.
    ln = re.sub(r'[\w.+\-]+@[\w\-]+\.[\w.]+', '', ln)            # email
    ln = re.sub(r'https?://\S+|www\.\S+', '', ln, flags=re.I)    # URLs
    ln = re.sub(r'[\+\(]?\d[\d\s\(\)\-\.]{7,18}\d', '', ln)      # phone numbers
    ln = re.sub(r'\s{2,}', ' ', ln).strip(' \t,;|·•-–—')

    # ── Collapse "letter-spaced" stylised lines ──────────────────────────────
    # Some PDFs render names with letterspacing like "A L I  A L-M A H M U D"
    # (visually striking, but the extractor sees each letter as a separate word).
    # If at least 4 of the tokens are single uppercase letters, treat the whole
    # line as letter-spaced and collapse adjacent single-letter tokens into words.
    tokens = ln.split()
    single_upper = sum(1 for t in tokens if len(t) == 1 and t.isalpha() and t.isupper())
    if single_upper >= 4:
        rebuilt, current = [], []
        for tok in tokens:
            if len(tok) == 1 and tok.isalpha():
                current.append(tok)
            else:
                if current:
                    rebuilt.append(''.join(current))
                    current = []
                rebuilt.append(tok)
        if current:
            rebuilt.append(''.join(current))
        ln = ' '.join(rebuilt)
        # Tidy spaces around punctuation introduced by the rebuild
        ln = re.sub(r'\s*([,\-])\s*', r'\1', ln)

    # "LAST, FIRST" → "First Last", but only when neither side looks
    # like a location/address fragment
    if ',' in ln:
        parts = [p.strip() for p in ln.split(',', 1)]
        if len(parts) == 2 and parts[0] and parts[1]:
            both_words = parts[0].split() + parts[1].split()
            looks_like_address = any(
                w.lower() in _LOCATION_CODES for w in both_words
            )
            if not looks_like_address:
                ln = f"{parts[1]} {parts[0]}"
    # Convert ALL-CAPS to title case
    if ln.isupper():
        ln = ln.title()
    return ln


def _smart_parse(text):
    """
    Locally parse resume text using regex + keyword matching.
    Returns a dict with the same keys the Claude API would return.
    No internet or API key required.
    """
    import re

    result = {
        'name': '', 'email': '', 'phone': '', 'specialty': '',
        'years_experience': 0, 'highest_education': '', 'skills': '', 'notes': '',
        'linkedin_url': '', 'github_url': '',
    }

    if not text:
        return result

    lines      = [l.strip() for l in text.split('\n') if l.strip()]
    text_lower = text.lower()

    # ── Email ────────────────────────────────────────────────────────────────
    m = re.search(r'[\w.+\-]+@[\w\-]+\.[\w.]+', text)
    if m:
        result['email'] = m.group()

    # ── Phone ────────────────────────────────────────────────────────────────
    m = re.search(r'[\+\(]?[\d][\d\s\(\)\-\.]{7,18}[\d]', text)
    if m:
        p = re.sub(r'[^\d\+\-\(\)\s]', '', m.group()).strip()
        if len(re.sub(r'\D', '', p)) >= 7:
            result['phone'] = p

    # ── Name — smart multi-strategy detection ────────────────────────────────
    #
    # Strategy 1 (best): look in the ±5 lines around the email address,
    #   because the name is almost always right next to the contact info.
    # Strategy 2 (fallback): scan the first 30 lines of the document,
    #   skipping any line that is a known section heading word.
    # Both strategies use _looks_like_name() to validate candidates.

    email_line_idx = None
    if result['email']:
        for i, ln in enumerate(lines):
            if result['email'] in ln:
                email_line_idx = i
                break

    name_found = False

    # Strategy 1: neighbourhood of the email line
    # Note: we do NOT skip the email line itself — _normalise_name_line strips
    # any inline email/phone/url, so a line like "ALEXEY KUVSHINOV lyoha@..."
    # becomes a clean candidate "Alexey Kuvshinov".
    if email_line_idx is not None:
        window_start = max(0, email_line_idx - 6)
        window_end   = min(len(lines), email_line_idx + 6)
        window       = lines[window_start:window_end]
        # Sort the window so lines closest to the email come first
        window.sort(key=lambda ln: abs(lines.index(ln) - email_line_idx)
                    if ln in lines else 99)
        for ln in window:
            candidate = _normalise_name_line(ln)
            if candidate and _looks_like_name(candidate):
                result['name'] = candidate
                name_found = True
                break

    # Strategy 2: scan first 10 lines if strategy 1 failed
    # Names are almost always in the top section of the resume.
    # Scanning too far down risks picking up company names, degree titles, etc.
    if not name_found:
        for ln in lines[:10]:
            candidate = _normalise_name_line(ln)
            if candidate and _looks_like_name(candidate):
                result['name'] = candidate
                break

    # ── Education ────────────────────────────────────────────────────────────
    if re.search(r'ph\.?\s*d|doctorate', text_lower):
        result['highest_education'] = 'PhD / Doctorate'
    elif re.search(r'\bmba\b', text_lower):
        result['highest_education'] = 'MBA'
    elif re.search(r"master'?s?|m\.?sc|m\.?eng|m\.?a\b|mphil", text_lower):
        result['highest_education'] = "Master's Degree"
    elif re.search(r"bachelor'?s?|b\.?sc|b\.?eng|b\.?a\b|b\.?tech|b\.?s\b|hons", text_lower):
        result['highest_education'] = "Bachelor's Degree"
    elif re.search(r'\bassociate\b', text_lower):
        result['highest_education'] = 'Associate Degree'
    elif re.search(r'diploma|vocational|nvq|hnc|hnd', text_lower):
        result['highest_education'] = 'Diploma / Vocational Training'
    elif re.search(r'high school|secondary school|gcse|a.?level', text_lower):
        result['highest_education'] = 'High School Diploma'
    elif re.search(r'certified|certification|pmp|cpa|cfa|cma|cissp|aws certified', text_lower):
        result['highest_education'] = 'Professional Certification'

    # ── Years of experience — from actual WORK date ranges only ──────────────
    #
    # We look specifically for "YYYY – YYYY" or "YYYY – Present/Current" patterns.
    # This correctly captures job periods and ignores standalone graduation years,
    # birth years, or any other isolated years sprinkled through the document.

    current_year = datetime.now().year
    present_words = r'present|current|now|till\s*date|to\s*date|ongoing|today'

    # Match:  2010 - 2015  |  2010–Present  |  2010 to present  |  Jan 2010 – Dec 2015
    range_pattern = re.compile(
        r'\b((?:19|20)\d{2})\s*(?:[-–—]|to)\s*((?:19|20)\d{2}|' + present_words + r')\b',
        re.IGNORECASE
    )
    job_ranges = range_pattern.findall(text)

    if job_ranges:
        start_years, end_years = [], []
        for start_str, end_str in job_ranges:
            try:
                start_years.append(int(start_str))
            except ValueError:
                continue
            if re.search(present_words, end_str, re.IGNORECASE):
                end_years.append(current_year)
            else:
                try:
                    end_years.append(int(end_str))
                except ValueError:
                    end_years.append(current_year)

        if start_years and end_years:
            earliest_start = min(start_years)
            latest_end     = max(end_years)
            result['years_experience'] = min(max(latest_end - earliest_start, 0), 60)
    else:
        # Fallback: no explicit ranges found — count only years that appear in
        # employment-context lines (lines containing job-related keywords)
        job_context = re.compile(
            r'(experience|worked|employment|position|role|joined|promoted|'
            r'company|corporation|pvt|ltd|inc\b|llc|firm|organization)',
            re.IGNORECASE
        )
        context_years = []
        for ln in lines:
            if job_context.search(ln):
                context_years += [int(y) for y in re.findall(r'\b(19[89]\d|20[012]\d)\b', ln)]
        if context_years:
            result['years_experience'] = min(max(current_year - min(context_years), 0), 60)

    # ── Specialty from job title keywords ────────────────────────────────────
    #
    # Rules are ordered from MOST SPECIFIC to MOST GENERIC.
    # This prevents "DevOps Engineer" from being swallowed by the generic
    # "software engineer" catch-all at the bottom.

    specialty_rules = [
        # ── IT Infrastructure / SysAdmin / DevOps (must come BEFORE generic dev)
        (r'system\s*admin(?:istrator)?|sysadmin|systems\s*admin', 'IT Administration & DevOps'),
        (r'devops\s*engineer|devsecops|site\s*reliability\s*engineer|sre\b', 'IT Administration & DevOps'),
        (r'network\s*admin(?:istrator)?|network\s*engineer|network\s*specialist', 'Network Engineering'),
        (r'cloud\s*(?:engineer|architect|admin)|infrastructure\s*engineer', 'IT Administration & DevOps'),
        (r'it\s*manager|it\s*director|it\s*head|chief\s*information|cio\b|cto\b', 'IT Administration & DevOps'),
        (r'database\s*admin(?:istrator)?|\bdba\b|sql\s*admin', 'Database Administration'),
        (r'security\s*engineer|cybersecurity|information\s*security|infosec|cissp', 'Cybersecurity'),
        (r'helpdesk|help\s*desk|technical\s*support|it\s*support|desktop\s*support', 'IT Support'),

        # ── Data & AI
        (r'data\s*scientist|machine\s*learning|deep\s*learning|ai\s*engineer|nlp\s*engineer', 'Data Science'),
        (r'data\s*engineer|etl\s*developer|data\s*architect|data\s*pipeline', 'Data Engineering'),
        (r'data\s*analyst|business\s*analyst|bi\s*analyst|business\s*intelligence', 'Data Analytics'),

        # ── Software Development (generic — comes AFTER specific IT roles)
        (r'software\s*engineer|full.?stack|backend\s*developer|frontend\s*developer', 'Software Engineering'),
        (r'web\s*developer|mobile\s*developer|app\s*developer|ios\s*developer|android\s*developer', 'Software Engineering'),
        (r'programmer|software\s*developer|application\s*developer', 'Software Engineering'),

        # ── Management
        (r'product\s*manager|product\s*owner', 'Product Management'),
        (r'project\s*manager|programme\s*manager|\bpmo\b|scrum\s*master|agile\s*coach', 'Project Management'),

        # ── Finance
        (r'account(?:ant|ing\s*manager)|chartered\s*accountant|\bcpa\b|\bcfa\b|\bcma\b', 'Finance & Accounting'),
        (r'financial\s*analyst|financial\s*controller|finance\s*manager|treasury|tax\s*(?:manager|specialist)', 'Finance & Accounting'),
        (r'auditor|internal\s*audit|external\s*audit', 'Finance & Accounting'),

        # ── Marketing
        (r'marketing\s*manager|digital\s*marketing|\bseo\b|\bsem\b|content\s*strateg', 'Marketing'),
        (r'brand\s*manager|social\s*media\s*manager|growth\s*hacker|\bpr\s*manager', 'Marketing'),

        # ── HR
        (r'\bhr\s*manager|\bhr\s*director|human\s*resources|talent\s*acquisition|recruiter|people\s*partner', 'Human Resources'),

        # ── Engineering disciplines
        (r'civil\s*engineer|structural\s*engineer|site\s*engineer', 'Civil Engineering'),
        (r'mechanical\s*engineer|manufacturing\s*engineer', 'Mechanical Engineering'),
        (r'electrical\s*engineer|electronics\s*engineer|instrumentation', 'Electrical Engineering'),

        # ── Creative
        (r'graphic\s*design|ui[/\s]?ux|visual\s*design|creative\s*director|art\s*director', 'Graphic Design'),
        (r'architect\b', 'Architecture'),

        # ── Other professional
        (r'sales\s*manager|sales\s*director|account\s*executive|business\s*development\s*manager', 'Sales'),
        (r'lawyer|attorney|solicitor|legal\s*counsel|paralegal', 'Legal'),
        (r'doctor\b|physician|surgeon|\bnurse\b|pharmacist|dentist|radiologist', 'Healthcare'),
        (r'teacher|lecturer|professor|academic|corporate\s*trainer|instructor', 'Education'),
        (r'supply\s*chain|logistics\s*manager|procurement|warehouse\s*manager|inventory', 'Supply Chain & Logistics'),
        (r'customer\s*service\s*manager|customer\s*support|call\s*cent(?:er|re)|client\s*relations', 'Customer Service'),
        (r'operations\s*manager|general\s*manager|\bcoo\b', 'Operations'),
    ]

    # Count how many rules match — pick the one with the most hits to handle
    # mixed-role resumes (e.g. a DevOps person who also codes)
    best_specialty, best_count = '', 0
    for pattern, title in specialty_rules:
        hits = len(re.findall(pattern, text_lower))
        if hits > best_count:
            best_specialty, best_count = title, hits
    if best_specialty:
        result['specialty'] = best_specialty

    # ── Skills keyword matching ───────────────────────────────────────────────
    skills_db = [
        # Languages
        'Python','Java','JavaScript','TypeScript','C++','C#','Ruby','Go','PHP',
        'Swift','Kotlin','R','MATLAB','Scala','Rust','Dart','Perl','Bash',
        # Web / Frameworks
        'React','Angular','Vue','Next.js','Node.js','Django','Flask','FastAPI',
        'Spring','Laravel','Rails','ASP.NET','HTML','CSS','Bootstrap','jQuery',
        'REST API','GraphQL','WebSocket',
        # Data / AI
        'SQL','MySQL','PostgreSQL','MongoDB','Redis','Elasticsearch','Oracle',
        'Pandas','NumPy','TensorFlow','PyTorch','Keras','Scikit-learn',
        'Power BI','Tableau','Excel','SPSS','SAS','Spark','Hadoop',
        # Cloud / DevOps
        'AWS','Azure','GCP','Docker','Kubernetes','Terraform','Jenkins',
        'Git','Linux','CI/CD','Ansible','Nginx',
        # Business / Finance
        'SAP','Salesforce','QuickBooks','Xero','Bloomberg','IFRS','GAAP',
        'Budgeting','Financial Modelling','Forecasting','Jira','Confluence',
        # Design
        'Photoshop','Illustrator','Figma','Sketch','InDesign','AutoCAD',
        'Revit','SolidWorks',
        # Soft skills
        'Project Management','Agile','Scrum','Leadership','Communication',
        'Problem Solving','Team Management','Strategic Planning',
    ]
    found = [s for s in skills_db
             if re.search(r'\b' + re.escape(s) + r'\b', text, re.IGNORECASE)]
    result['skills'] = ', '.join(dict.fromkeys(found))   # preserve order, deduplicate

    # ── LinkedIn URL ─────────────────────────────────────────────────────────
    m = re.search(
        r'(https?://)?(?:www\.)?linkedin\.com/in/[\w\-\.%]+/?',
        text, re.IGNORECASE)
    if m:
        url = m.group()
        if not url.startswith('http'):
            url = 'https://' + url
        result['linkedin_url'] = url.rstrip('/')

    # ── GitHub URL ───────────────────────────────────────────────────────────
    m = re.search(
        r'(https?://)?(?:www\.)?github\.com/[\w\-\.]+/?',
        text, re.IGNORECASE)
    if m:
        url = m.group()
        if not url.startswith('http'):
            url = 'https://' + url
        result['github_url'] = url.rstrip('/')

    # ── Notes: first long sentence that looks like a summary ─────────────────
    for line in lines[:25]:
        if (len(line) > 80
                and '@' not in line
                and not re.match(r'^[\d\s\+\-\(\)]+$', line)):
            result['notes'] = line[:400]
            break

    return result


@app.route('/parse-resume', methods=['POST'])
@role_required(*CAN_ADD)
def parse_resume():
    """
    Extract resume fields from an uploaded file.

    Strategy (no API key required for PDFs/DOCX):
      1. Extract plain text locally using pdfplumber / python-docx.
      2. Parse the text locally with smart regex (always works, no internet needed).
      3. If an Anthropic API key is configured AND the file is a type Claude
         understands, use Claude AI for higher accuracy (optional upgrade).
    """
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file received.'}), 400

    filename  = file.filename.lower()
    file_data = file.read()

    # ── Step 1: Extract text locally ─────────────────────────────────────────
    try:
        resume_text = _extract_text_from_file(file_data, filename)
    except Exception as e:
        resume_text = ''

    # ── Step 2: Local smart parse (works for every PDF / DOCX) ───────────────
    if resume_text.strip():
        result = _smart_parse(resume_text)
        result['_method'] = 'local'
        return jsonify(result)

    # ── Step 3: Image files — need OCR (handled by Claude AI if key exists) ──
    is_image = filename.endswith(('.jpg','.jpeg','.png','.gif','.webp','.bmp','.tiff','.tif'))

    if is_image and ANTHROPIC_API_KEY:
        try:
            import anthropic, io
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

            if filename.endswith(('.bmp', '.tiff', '.tif')):
                from PIL import Image
                img = Image.open(io.BytesIO(file_data))
                buf = io.BytesIO()
                img.convert('RGB').save(buf, format='PNG')
                file_data = buf.getvalue()
                media_type = 'image/png'
            else:
                ext_map = {'jpg':'image/jpeg','jpeg':'image/jpeg',
                           'png':'image/png','gif':'image/gif','webp':'image/webp'}
                media_type = ext_map.get(filename.rsplit('.',1)[-1], 'image/jpeg')

            message = client.messages.create(
                model='claude-haiku-4-5-20251001',
                max_tokens=1024,
                messages=[{'role':'user','content':[
                    {'type':'image','source':{'type':'base64',
                     'media_type': media_type,
                     'data': base64.standard_b64encode(file_data).decode()}},
                    {'type':'text','text': PARSE_PROMPT},
                ]}],
            )
            raw = message.content[0].text.strip()
            if raw.startswith('```'):
                raw = raw.split('```')[1]
                if raw.startswith('json'):
                    raw = raw[4:]
            result = json.loads(raw.strip())
            try:
                result['years_experience'] = int(result.get('years_experience', 0))
            except (ValueError, TypeError):
                result['years_experience'] = 0
            result['_method'] = 'ai'
            return jsonify(result)

        except Exception as e:
            return jsonify({'error': f'Image parsing failed: {str(e)}. '
                            'Try converting the image to PDF and uploading again.'}), 500

    if is_image:
        return jsonify({'error':
            'Scanned image / photo resumes cannot be read without an AI key. '
            'Please convert your resume to PDF or Word format and try again — '
            'those work automatically with no setup required.'}), 400

    if filename.endswith('.doc'):
        return jsonify({'error':
            'Old .doc format cannot be read automatically. '
            'Please open it in Microsoft Word, save as PDF or DOCX, then try again.'}), 400

    return jsonify({'error': 'Could not read any text from this file. '
                    'Please try a different PDF or Word document.'}), 400


# Re-Analyze routes removed — the _auto_reanalyze_on_startup() background
# thread already re-parses every resume file each time the program starts,
# applying the latest parsing logic automatically.  No manual button needed.


@app.route('/open-config', methods=['POST'])
@role_required(*CAN_USERS)
def open_config():
    """Open config.py in Notepad so the user can paste their API key.
    Local Windows desktop only — disabled on Linux / cloud hosts where
    notepad.exe doesn't exist and config.py isn't even present."""
    if os.name != 'nt':
        return jsonify({'status': 'unsupported',
                        'message': 'Use environment variables on cloud hosts.'}), 400
    import subprocess
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.py')
    try:
        subprocess.Popen(['notepad.exe', config_path])
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── Staff Directory ───────────────────────────────────────────────────────────

@app.route('/staff')
@role_required(*CAN_VIEW)
def staff_list():
    with get_db() as conn:
        staff = conn.execute(
            'SELECT * FROM staff ORDER BY name COLLATE NOCASE ASC'
        ).fetchall()
    can_staff = _has_role(*CAN_STAFF)
    return render_template('staff.html', staff=staff, can_staff=can_staff)


@app.route('/staff/add', methods=['POST'])
@role_required(*CAN_STAFF)
def staff_add():
    name        = request.form.get('name', '').strip()
    email       = request.form.get('email', '').strip()
    designation = request.form.get('designation', '').strip()
    department  = request.form.get('department', '').strip()
    if not name:
        flash('Name is required.', 'error')
        return redirect(url_for('staff_list'))
    with get_db() as conn:
        conn.execute(
            'INSERT INTO staff (name, email, designation, department) VALUES (?,?,?,?)',
            (name, email, designation, department)
        )
        conn.commit()
    flash(f'{name} added to staff directory.', 'success')
    return redirect(url_for('staff_list'))


@app.route('/staff/edit/<int:staff_id>', methods=['POST'])
@role_required(*CAN_STAFF)
def staff_edit(staff_id):
    name        = request.form.get('name', '').strip()
    email       = request.form.get('email', '').strip()
    designation = request.form.get('designation', '').strip()
    department  = request.form.get('department', '').strip()
    if not name:
        flash('Name is required.', 'error')
        return redirect(url_for('staff_list'))
    with get_db() as conn:
        conn.execute(
            'UPDATE staff SET name=?, email=?, designation=?, department=? WHERE id=?',
            (name, email, designation, department, staff_id)
        )
        conn.commit()
    flash(f'{name} updated successfully.', 'success')
    return redirect(url_for('staff_list'))


@app.route('/staff/delete/<int:staff_id>', methods=['POST'])
@role_required(*CAN_STAFF)
def staff_delete(staff_id):
    with get_db() as conn:
        row = conn.execute('SELECT name FROM staff WHERE id=?', (staff_id,)).fetchone()
        if row:
            conn.execute('DELETE FROM staff WHERE id=?', (staff_id,))
            conn.commit()
            flash(f'{row["name"]} removed from staff directory.', 'success')
    return redirect(url_for('staff_list'))


@app.route('/api/staff')
@role_required(*CAN_VIEW)
def api_staff():
    """Return staff list as JSON for autocomplete."""
    with get_db() as conn:
        rows = conn.execute(
            'SELECT name, email, designation FROM staff ORDER BY name COLLATE NOCASE ASC'
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# ─── Public Careers API ───────────────────────────────────────────────────────
#  This endpoint accepts career applications submitted from the company website
#  (transcrypts.com).  It is INTENTIONALLY public — anyone applying for a job
#  needs to be able to POST without an admin account.
#
#  Security model:
#    • Optional shared API key  (CAREERS_API_KEY env var). If set, the website
#      must include it in the X-API-Key header.  Stops random spammers.
#    • Per-IP rate limit            — 5 submissions per IP per hour
#    • File-type / size validation  — same rules as the regular upload form
#    • All submissions land in the audit log
#
#  Required form fields (multipart/form-data):
#    resume     — the actual file (PDF or DOCX)
#    name       — applicant's full name
#    email      — applicant's email address
#  Optional fields:
#    phone, position, cover_letter, linkedin_url
#
#  CORS: enabled for any origin so the JS form on transcrypts.com can POST.
#  ────────────────────────────────────────────────────────────────────────────

# Simple in-memory rate-limit store: { 'ip': [datetime, datetime, ...] }
_RATE_LIMIT_STORE: dict[str, list[datetime]] = {}
_RATE_LIMIT_MAX_PER_HOUR = 5


def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is within the rate limit, False if exceeded."""
    now = datetime.now()
    cutoff = now - timedelta(hours=1)
    hits = _RATE_LIMIT_STORE.get(ip, [])
    hits = [t for t in hits if t > cutoff]
    if len(hits) >= _RATE_LIMIT_MAX_PER_HOUR:
        _RATE_LIMIT_STORE[ip] = hits
        return False
    hits.append(now)
    _RATE_LIMIT_STORE[ip] = hits
    return True


@app.after_request
def _add_cors_headers(response):
    """Allow cross-origin POSTs from the company website."""
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    return response


@app.route('/api/careers/apply', methods=['POST', 'OPTIONS'])
def api_careers_apply():
    """
    Public endpoint — receives a career application from the website.
    Returns JSON {ok: bool, applicant_id: int, message: str}.
    """
    # Browser CORS pre-flight
    if request.method == 'OPTIONS':
        return ('', 204)

    # ── Optional API key check ───────────────────────────────────────────────
    expected_key = os.environ.get('CAREERS_API_KEY', '').strip()
    if expected_key:
        provided = request.headers.get('X-API-Key', '').strip()
        if provided != expected_key:
            return jsonify({'ok': False,
                            'message': 'Unauthorized — invalid API key.'}), 401

    # ── Rate limit by IP ─────────────────────────────────────────────────────
    client_ip = request.headers.get('X-Forwarded-For',
                                     request.remote_addr or '0.0.0.0').split(',')[0].strip()
    if not _check_rate_limit(client_ip):
        return jsonify({'ok': False,
                        'message': 'Too many submissions. Please try again later.'}), 429

    # ── Resume file is the one truly required input ──────────────────────────
    file = request.files.get('resume')
    if not file or not file.filename:
        return jsonify({'ok': False,
                        'message': 'Resume file is required.'}), 400

    if not allowed_file(file.filename):
        return jsonify({'ok': False,
                        'message': 'Resume must be a PDF or DOCX file.'}), 400

    # Form fields are now treated as candidate-supplied HINTS. The resume
    # itself is the authoritative source of identity (name/email/phone).
    form_name    = (request.form.get('name')         or '').strip()
    form_email   = (request.form.get('email')        or '').strip()
    form_phone   = (request.form.get('phone')        or '').strip()
    position     = (request.form.get('position')     or '').strip()
    cover_letter = (request.form.get('cover_letter') or '').strip()
    linkedin_url = (request.form.get('linkedin_url') or '').strip()
    github_url   = (request.form.get('github_url')   or '').strip()

    # ── Save the file with a unique filename ────────────────────────────────
    raw = file.read()
    file.seek(0)
    file_hash = hashlib.md5(raw).hexdigest()
    text_hash = compute_text_hash(raw, file.filename or '')
    safe_name = secure_filename(file.filename)
    base, ext = os.path.splitext(safe_name)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_name = f"CareerApp_{base[:40]}_{timestamp}{ext}"
    _storage.save_file(final_name, raw,
                       file.mimetype or 'application/octet-stream')

    # ── Parse resume FIRST — its content drives identity & dedup ────────────
    parsed = {}
    parsed_text_value = None
    try:
        text = _extract_text_from_file(raw, final_name.lower())
        if text and text.strip():
            parsed = _smart_parse(text) or {}
            parsed_text_value = text   # cache full text for the job-matcher
    except Exception:
        parsed = {}

    parsed_name  = (parsed.get('name')  or '').strip()
    parsed_email = (parsed.get('email') or '').strip()
    parsed_phone = (parsed.get('phone') or '').strip()

    # Effective identity: prefer what's in the resume, fall back to form input.
    name  = parsed_name  or form_name
    email = parsed_email or form_email
    phone = parsed_phone or form_phone

    # If we have neither a parsed name/email NOR form name/email, we can't
    # create a usable record. Ask the candidate to provide readable contact info.
    if not name or not email:
        return jsonify({
            'ok': False,
            'message': ('We could not read the contact information from your '
                        'resume. Please make sure your name and email appear '
                        'as selectable text (not just inside an image) and '
                        'try again.'),
        }), 400

    # Flag mismatches between what the candidate typed and what's in the resume.
    # HR sees this so they can investigate possible fraud or wrong-file uploads.
    discrepancy_notes = []
    if form_name  and parsed_name  and form_name.lower()  != parsed_name.lower():
        discrepancy_notes.append(
            f'Submitted as "{form_name}" but resume parses as "{parsed_name}".')
    if form_email and parsed_email and form_email.lower() != parsed_email.lower():
        discrepancy_notes.append(
            f'Form email "{form_email}" differs from resume email "{parsed_email}".')

    # Position → display label
    position_label   = position or 'Open Application — Suitable Position'
    source_label     = 'Career Website' + (f' — {position}' if position else ' — Open Application')

    # ── Insert into DB ───────────────────────────────────────────────────────
    with get_db() as conn:
        # ── De-dupe ───────────────────────────────────────────────────────────
        # Identity comes from the RESUME, not the form, so a candidate cannot
        # bypass dedup by typing a different name/email at submission time.
        # We check (in order):
        #   1. EMAIL match on the effective email (parsed → form). Catches the
        #      common case of the same person re-applying, even if they used a
        #      different file or typed something different in the form.
        #   2. FILE-HASH match. Byte-identical resume on file already.
        #   3. NAME + PHONE match. Catches a re-application with a different
        #      email but the same resume content.
        existing_by_email = conn.execute(
            'SELECT id, applied_position FROM applicants '
            'WHERE LOWER(email) = LOWER(?)', (email,)
        ).fetchone()
        if existing_by_email:
            # Track the new position they applied for
            old_pos = existing_by_email['applied_position'] or ''
            new_positions = old_pos
            if position and position not in old_pos:
                new_positions = (old_pos + ' | ' + position).strip(' |') if old_pos else position
            try:
                conn.execute(
                    "UPDATE applicants SET applied_position = ?, "
                    "source = ? WHERE id = ?",
                    (new_positions, source_label, existing_by_email['id'])
                )
                conn.commit()
            except Exception:
                pass
            log_action('CAREER APPLICATION (DUP)', name,
                       f'Already on file as id={existing_by_email["id"]}. '
                       f'Added position: {position or "Open"} | IP: {client_ip}'
                       + (f' | {" ".join(discrepancy_notes)}' if discrepancy_notes else ''))
            return jsonify({
                'ok': True,
                'applicant_id': existing_by_email['id'],
                'duplicate': True,
                'message': (
                    "We already have your application on file — thank you! "
                    f"We've noted your interest in {position or 'this opportunity'} "
                    "and our team will be in touch."
                ),
            })

        existing_by_hash = conn.execute(
            'SELECT id FROM applicants WHERE file_hash=?', (file_hash,)
        ).fetchone()
        if existing_by_hash:
            log_action('CAREER APPLICATION (DUP)', name,
                       f'Same resume as id={existing_by_hash["id"]}. IP: {client_ip}'
                       + (f' | {" ".join(discrepancy_notes)}' if discrepancy_notes else ''))
            return jsonify({
                'ok': True,
                'applicant_id': existing_by_hash['id'],
                'duplicate': True,
                'message': ("We already have this resume on file — we'll "
                            "review it for this position. Thank you!"),
            })

        # Text-content match — catches "same resume re-exported" / different
        # bytes but identical content. text_hash is empty when text extraction
        # failed (scanned PDF without OCR), so we skip the check in that case.
        if text_hash:
            existing_by_text = conn.execute(
                'SELECT id, name FROM applicants WHERE text_hash=?',
                (text_hash,)
            ).fetchone()
            if existing_by_text:
                log_action('CAREER APPLICATION (DUP)', name,
                           f'Same resume CONTENT as id={existing_by_text["id"]} '
                           f'({existing_by_text["name"]}). IP: {client_ip}'
                           + (f' | {" ".join(discrepancy_notes)}' if discrepancy_notes else ''))
                return jsonify({
                    'ok': True,
                    'applicant_id': existing_by_text['id'],
                    'duplicate': True,
                    'message': ("We already have this resume on file — we'll "
                                "review it for this position. Thank you!"),
                })

        # Name + phone match — catches the same person re-applying with a
        # different email but the same resume content.
        if name and phone:
            existing_by_name_phone = conn.execute(
                'SELECT id FROM applicants '
                'WHERE LOWER(name) = LOWER(?) AND phone = ?',
                (name, phone)
            ).fetchone()
            if existing_by_name_phone:
                log_action('CAREER APPLICATION (DUP)', name,
                           f'Name+phone match id={existing_by_name_phone["id"]}. '
                           f'IP: {client_ip}'
                           + (f' | {" ".join(discrepancy_notes)}' if discrepancy_notes else ''))
                return jsonify({
                    'ok': True,
                    'applicant_id': existing_by_name_phone['id'],
                    'duplicate': True,
                    'message': ("We already have your application on file — "
                                "thank you! Our team will be in touch."),
                })

        # Build the notes field: parsed resume notes + any discrepancy flags.
        notes_parts = []
        if parsed.get('notes'):
            notes_parts.append(parsed['notes'])
        if discrepancy_notes:
            notes_parts.append('⚠ ' + ' '.join(discrepancy_notes))
        combined_notes = '\n\n'.join(notes_parts)

        cur = conn.execute(
            '''INSERT INTO applicants
               (name, email, phone, specialty, years_experience, highest_education,
                skills, resume_filename, notes, date_added, hiring_status,
                linkedin_url, github_url, file_hash, text_hash, source,
                applied_position, cover_letter, parsed_text)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (
                name, email, phone,
                parsed.get('specialty', position or ''),
                _safe_int(parsed.get('years_experience'), 0),
                parsed.get('highest_education', ''),
                parsed.get('skills', ''),
                final_name,
                combined_notes,
                datetime.now().isoformat(timespec='seconds'),
                'Under Review',
                linkedin_url or parsed.get('linkedin_url', ''),
                github_url   or parsed.get('github_url',   ''),
                file_hash,
                text_hash,
                source_label,
                position_label,
                cover_letter,
                parsed_text_value,
            )
        )
        applicant_id = cur.lastrowid
        conn.commit()

    log_action('CAREER APPLICATION', name,
               f'Position: {position_label} | IP: {client_ip}'
               + (f' | {" ".join(discrepancy_notes)}' if discrepancy_notes else ''))

    return jsonify({
        'ok': True,
        'applicant_id': applicant_id,
        'message': ("Thank you for applying! We've received your application "
                    "and our team will review it shortly."),
    })


@app.route('/api/careers/health')
def api_careers_health():
    """Lightweight health check the website can call to verify the API is up."""
    return jsonify({'ok': True, 'service': 'TransCrypts Resume DB',
                    'careers_api': 'online'})


# ──────────────────────────────────────────────────────────────────────────────
#  Admin: content-duplicate cleanup
# ──────────────────────────────────────────────────────────────────────────────
#  text_hash was added later, so existing rows have NULL there. This endpoint
#  re-reads each stored resume file, extracts text, computes the hash, and
#  fills the column. After backfill it identifies groups of records that
#  share the same text_hash and offers to delete the newer ones (keeping the
#  oldest record in each group, which has the most history attached to it).
#
#  Two-step UX so no data is lost by accident:
#    GET  /admin/cleanup-content-duplicates              → preview only
#    POST /admin/cleanup-content-duplicates?execute=1    → actually delete
# ──────────────────────────────────────────────────────────────────────────────
_DUPLICATES_PAGE_TMPL = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Find Duplicates — Resume Database</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link href="{{ url_for('static', filename='css/style.css') }}" rel="stylesheet">
<style>
  .keep-row   { background:#e8f5e9; }
  .remove-row { background:#ffebee; }
  .hash-cell  { font-family: monospace; font-size:.75rem; color:#6c757d; }
</style>
</head><body>
<nav class="navbar navbar-dark bg-primary shadow-sm">
  <div class="container-fluid px-4">
    <a class="navbar-brand" href="{{ url_for('index') }}">
      <i class="bi bi-arrow-left me-1"></i> TransCrypts Resume DB
    </a>
    <a href="{{ url_for('index') }}" class="btn btn-outline-light btn-sm">
      <i class="bi bi-house-fill me-1"></i> Home
    </a>
  </div>
</nav>

<div class="container-fluid px-4 py-4">
  <h2 class="mb-1"><i class="bi bi-files me-2"></i>Find Duplicates</h2>
  <p class="text-muted">
    Scans every applicant's resume content (not just file bytes) and groups
    records that share the same content. The oldest record in each group is
    kept; the newer ones are flagged for removal.
  </p>

  <div class="alert alert-info py-2 small">
    <strong>Scan summary:</strong>
    backfilled <strong>{{ backfilled }}</strong> missing content hash(es),
    skipped <strong>{{ skipped }}</strong> file(s) we could not read.
  </div>

  {% if deleted %}
    <div class="alert alert-success">
      <i class="bi bi-check-circle-fill me-1"></i>
      Removed {{ deleted|length }} duplicate record(s):
      <ul class="mb-0 mt-1">
        {% for d in deleted %}
          <li>{{ d.name or '(no name)' }} (id #{{ d.id }})</li>
        {% endfor %}
      </ul>
    </div>
  {% endif %}

  {% if not duplicate_groups %}
    <div class="alert alert-success">
      <i class="bi bi-check-circle me-1"></i>
      No content-duplicates found. Every resume in the database has unique text.
    </div>
  {% else %}
    <form method="POST" action="{{ url_for('admin_cleanup_content_duplicates') }}?execute=1"
          onsubmit="return confirm('Delete {{ will_delete_count }} duplicate record(s)? The oldest record in each group is kept. This cannot be undone.');">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <div>Found <strong>{{ duplicate_groups|length }}</strong> duplicate group(s)
             — <strong>{{ will_delete_count }}</strong> record(s) will be removed.</div>
        <button class="btn btn-danger" type="submit">
          <i class="bi bi-trash3-fill me-1"></i> Delete {{ will_delete_count }} duplicate(s)
        </button>
      </div>

      {% for g in duplicate_groups %}
        <div class="card mb-3 shadow-sm">
          <div class="card-header py-2 d-flex justify-content-between">
            <span>Group <span class="hash-cell">{{ g.text_hash[:12] }}…</span></span>
            <span class="text-muted small">{{ g.remove|length }} duplicate(s)</span>
          </div>
          <div class="table-responsive">
            <table class="table table-sm mb-0">
              <thead class="table-light">
                <tr><th>Status</th><th>ID</th><th>Name</th><th>Email</th>
                    <th>Source</th><th>Date added</th><th></th></tr>
              </thead>
              <tbody>
                <tr class="keep-row">
                  <td><span class="badge bg-success">KEEP (oldest)</span></td>
                  <td>#{{ g.keep.id }}</td>
                  <td><strong>{{ g.keep.name or '(no name)' }}</strong></td>
                  <td>{{ g.keep.email or '—' }}</td>
                  <td>{{ g.keep.source or '—' }}</td>
                  <td>{{ g.keep.date_added or '—' }}</td>
                  <td><a class="btn btn-sm btn-outline-secondary"
                         href="{{ url_for('view_resume', applicant_id=g.keep.id) }}">View</a></td>
                </tr>
                {% for m in g.remove %}
                <tr class="remove-row">
                  <td><span class="badge bg-danger">REMOVE</span></td>
                  <td>#{{ m.id }}</td>
                  <td>{{ m.name or '(no name)' }}</td>
                  <td>{{ m.email or '—' }}</td>
                  <td>{{ m.source or '—' }}</td>
                  <td>{{ m.date_added or '—' }}</td>
                  <td><a class="btn btn-sm btn-outline-secondary"
                         href="{{ url_for('view_resume', applicant_id=m.id) }}">View</a></td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      {% endfor %}
    </form>
  {% endif %}
</div>
</body></html>
"""


@app.route('/admin/cleanup-content-duplicates', methods=['GET', 'POST'])
@role_required(*CAN_USERS)
def admin_cleanup_content_duplicates():
    """
    Two-step UX so no data is lost by accident:
      GET                                          → backfill + preview page
      POST /…?execute=1                            → actually delete

    JSON variant for API/curl usage:
      GET /…?format=json
      POST /…?execute=1&format=json
    """
    execute    = (request.args.get('execute') or '').strip() == '1' \
                 and request.method == 'POST'
    want_json  = (request.args.get('format') or '').strip().lower() == 'json'

    # ── 1. Backfill missing text_hash values ────────────────────────────────
    # We also opportunistically backfill parsed_text from the SAME extraction
    # pass so the job-matcher gets the cached text "for free" — saving a
    # repeat extraction later.
    backfilled = 0
    skipped    = 0
    with get_db() as conn:
        rows = conn.execute(
            'SELECT id, resume_filename FROM applicants '
            "WHERE (text_hash IS NULL OR text_hash = '') "
            "  AND resume_filename IS NOT NULL "
            "  AND resume_filename != ''"
        ).fetchall()

    for r in rows:
        try:
            data = _storage.read_file(r['resume_filename'])
            if not data:
                skipped += 1
                continue
            # Extract once, derive both text_hash and parsed_text from it.
            try:
                full_text = _extract_text_from_file(data, (r['resume_filename'] or '').lower())
            except Exception:
                full_text = ''
            th = ''
            if full_text:
                norm = _normalize_resume_text(full_text)
                if norm and len(norm) >= 50:
                    th = hashlib.md5(norm.encode('utf-8')).hexdigest()
            if not th:
                skipped += 1
                continue
            with get_db() as conn:
                conn.execute(
                    'UPDATE applicants SET text_hash=?, parsed_text=? WHERE id=?',
                    (th, full_text or None, r['id'])
                )
                conn.commit()
            backfilled += 1
        except Exception:
            skipped += 1

    # ── 2. Find duplicate groups ────────────────────────────────────────────
    with get_db() as conn:
        groups_rows = conn.execute(
            "SELECT text_hash, COUNT(*) AS n FROM applicants "
            "WHERE text_hash IS NOT NULL AND text_hash != '' "
            "GROUP BY text_hash HAVING COUNT(*) > 1"
        ).fetchall()

    duplicate_groups = []
    ids_to_delete    = []
    for g in groups_rows:
        with get_db() as conn:
            members = conn.execute(
                'SELECT id, name, email, date_added, resume_filename, source '
                'FROM applicants WHERE text_hash=? '
                'ORDER BY date_added ASC, id ASC',
                (g['text_hash'],)
            ).fetchall()
        if len(members) < 2:
            continue
        keep    = members[0]
        remove  = members[1:]
        duplicate_groups.append({
            'text_hash': g['text_hash'],
            'keep':      dict(keep) if not isinstance(keep, dict) else dict(keep),
            'remove':    [dict(m) for m in remove],
        })
        ids_to_delete.extend([m['id'] for m in remove])

    # ── 3. Execute deletions (only on POST + ?execute=1) ────────────────────
    deleted = []
    if execute and ids_to_delete:
        with get_db() as conn:
            for did in ids_to_delete:
                row = conn.execute(
                    'SELECT name, resume_filename FROM applicants WHERE id=?',
                    (did,)
                ).fetchone()
                if not row:
                    continue
                try:
                    if row['resume_filename']:
                        _storage.delete_file(row['resume_filename'])
                except Exception:
                    pass
                conn.execute('DELETE FROM applicants WHERE id=?', (did,))
                conn.commit()
                deleted.append({'id': did, 'name': row['name']})
                log_action('DUPLICATE REMOVED', row['name'] or f'id={did}',
                           f'Removed via content-duplicate cleanup (id={did})')

        # After deleting, the previously-detected groups are stale. Re-scan so
        # the page now shows "no duplicates" (or any leftovers) accurately.
        with get_db() as conn:
            groups_rows = conn.execute(
                "SELECT text_hash, COUNT(*) AS n FROM applicants "
                "WHERE text_hash IS NOT NULL AND text_hash != '' "
                "GROUP BY text_hash HAVING COUNT(*) > 1"
            ).fetchall()
        duplicate_groups = []
        ids_to_delete    = []
        for g in groups_rows:
            with get_db() as conn:
                members = conn.execute(
                    'SELECT id, name, email, date_added, resume_filename, source '
                    'FROM applicants WHERE text_hash=? '
                    'ORDER BY date_added ASC, id ASC',
                    (g['text_hash'],)
                ).fetchall()
            if len(members) < 2:
                continue
            duplicate_groups.append({
                'text_hash': g['text_hash'],
                'keep':      dict(members[0]),
                'remove':    [dict(m) for m in members[1:]],
            })
            ids_to_delete.extend([m['id'] for m in members[1:]])

    if want_json:
        return jsonify({
            'ok':          True,
            'mode':        'executed' if execute else 'preview',
            'backfilled':  backfilled,
            'skipped':     skipped,
            'duplicate_groups': duplicate_groups,
            'will_delete_ids':  ids_to_delete if not execute else [],
            'deleted':     deleted,
        })

    return render_template_string(
        _DUPLICATES_PAGE_TMPL,
        backfilled        = backfilled,
        skipped           = skipped,
        duplicate_groups  = duplicate_groups,
        will_delete_count = len(ids_to_delete),
        deleted           = deleted,
    )


@app.route('/api-status', methods=['GET'])
@role_required(*CAN_ADD)
def api_status():
    """Check whether the AI API key is configured."""
    configured = bool(ANTHROPIC_API_KEY and ANTHROPIC_API_KEY != 'your-api-key-here')
    return jsonify({'configured': configured})


@app.route('/admin/email/dns-records')
def admin_email_dns_records():
    """
    Fetch DNS records from Resend so the user knows EXACTLY what to add to
    Squarespace. Uses the Resend API key already configured on the server,
    so no extra credentials needed.

    Auto-adds the domain if it doesn't exist yet, then lists the DNS records
    Resend wants. Returns a single page with copy-paste-ready values.
    """
    import urllib.request, urllib.error, json as _json

    creds   = _email_credentials()
    api_key = (os.environ.get('RESEND_API_KEY') or '').strip() or creds.get('password', '')
    if not api_key:
        return ('<h2>No Resend API key configured</h2>'
                '<p>Set MAIL_PASSWORD or RESEND_API_KEY env var on Render.</p>'), 400

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type':  'application/json',
        'User-Agent':    'TransCrypts-Resume-DB/1.0',
        'Accept':        'application/json',
    }
    # Prefer explicit RESEND_DOMAIN env var; else accept any transcrypts.com
    # apex or subdomain found in the account.
    preferred_name = (os.environ.get('RESEND_DOMAIN') or '').strip().lower()

    # 1. List existing domains
    try:
        req = urllib.request.Request('https://api.resend.com/domains',
                                      headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            raw_body = r.read()
            list_result = _json.loads(raw_body)
        # Resend's response shape varies across versions — handle both
        #   {"data": [...]}  AND  bare [...]
        if isinstance(list_result, dict):
            domains = list_result.get('data') or list_result.get('domains') or []
        elif isinstance(list_result, list):
            domains = list_result
        else:
            domains = []
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')[:500]
        # 401 with "restricted_api_key" means the Sending key can't list domains.
        # Tell the user how to fix it (generate Full Access key) AND give them
        # the manual fallback.
        if e.code == 401 and 'restricted' in body.lower():
            return f'''<!DOCTYPE html><html><head>
<title>Resend API key needs Full Access</title>
<style>body{{font-family:system-ui,sans-serif;max-width:780px;margin:30px auto;padding:0 20px;line-height:1.6}}
code{{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:14px}}
.box{{padding:14px 18px;border-radius:8px;margin:14px 0}}
.warn{{background:#fef3c7;border-left:4px solid #f59e0b}}
.ok{{background:#d1fae5;border-left:4px solid #10b981}}
</style></head><body>
<h1>Resend API key needs upgrading</h1>
<div class="warn">
  <strong>Current API key has "Sending Access" only.</strong> It can send emails
  (which is why interview emails work), but can't read/manage domains, so
  this auto-fetch endpoint can't pull DNS records for you.
</div>

<h2>Easiest path (1 minute, no env var changes):</h2>
<ol>
  <li>Open <a href="https://resend.com/domains" target="_blank">resend.com/domains</a></li>
  <li>Click on the <strong>transcrypts.com</strong> row in the list</li>
  <li>The page that opens shows the 3 DNS records — copy them into Squarespace at
      <a href="https://domains.squarespace.com/" target="_blank">domains.squarespace.com</a></li>
</ol>

<h2>Alternative — give me API access and I'll fetch + display them here:</h2>
<ol>
  <li>Open <a href="https://resend.com/api-keys" target="_blank">resend.com/api-keys</a></li>
  <li>Click <strong>Create API Key</strong></li>
  <li>Name: <code>transcrypts-admin</code> &nbsp; Permission: <strong>Full Access</strong></li>
  <li>Copy the new key (starts with <code>re_</code>)</li>
  <li>Render → Environment → add <code>RESEND_API_KEY</code> = the new key → Save</li>
  <li>After redeploy (~3 min), refresh THIS page — DNS records will auto-display.</li>
</ol>

<div class="ok">
  <strong>Either way</strong>: the email pipeline works for the account owner today
  ({creds.get('username') or 'syed@transcrypts.com'}). DNS verification only
  unlocks sending to other recipients.
</div>
</body></html>''', 401
        return f'<pre>Resend list domains failed: HTTP {e.code}\n{body}</pre>', 500

    domain_id = None
    domain_status = 'unknown'
    domain_name   = ''
    # If RESEND_DOMAIN env var is set, pick that exact name; otherwise prefer
    # any transcrypts.com-related domain (apex OR subdomain like mail.transcrypts.com).
    transcrypts_matches = []
    for d in domains:
        nm = (d.get('name') or '').lower()
        if preferred_name and nm == preferred_name:
            domain_id     = d.get('id')
            domain_status = d.get('status', 'unknown')
            domain_name   = nm
            break
        if 'transcrypts.com' in nm:
            transcrypts_matches.append(d)
    # If no exact preferred match, take the first transcrypts.com-related domain
    if not domain_id and transcrypts_matches:
        d = transcrypts_matches[0]
        domain_id     = d.get('id')
        domain_status = d.get('status', 'unknown')
        domain_name   = (d.get('name') or '').lower()

    # 2. Auto-add if missing
    if not domain_id:
        domain_name = preferred_name or 'mail.transcrypts.com'
        try:
            req = urllib.request.Request(
                'https://api.resend.com/domains',
                data=_json.dumps({'name': domain_name, 'region': 'us-east-1'}).encode(),
                headers=headers, method='POST')
            with urllib.request.urlopen(req, timeout=15) as r:
                created = _json.loads(r.read())
                domain_id = created.get('id')
                domain_status = 'pending'
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', 'replace')[:500]
            # If the domain "has been registered already", we can't have parsed
            # it from the list. Show the raw list response so we can debug.
            if 'registered already' in body.lower():
                return ('<h2>Domain already exists but couldn\'t be parsed from list</h2>'
                        f'<p>Raw LIST response (paste the URL again to retry):</p>'
                        f'<pre>{raw_body.decode("utf-8", "replace")[:2000]}</pre>'
                        f'<p>POST error: {body}</p>'), 500
            return f'<pre>Could not auto-add domain (need Full Access API key): HTTP {e.code}\n{body}</pre>', 500

    # 3. Get full DNS records
    try:
        req = urllib.request.Request(
            f'https://api.resend.com/domains/{domain_id}',
            headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            details = _json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', 'replace')[:500]
        return f'<pre>Get domain details failed: HTTP {e.code}\n{body}</pre>', 500

    records = details.get('records', [])
    status  = details.get('status', domain_status)

    # 4. Render a clean copy-friendly page
    rows = []
    for rec in records:
        rec_type   = rec.get('type', '')
        host       = rec.get('name', '').replace(f'.{domain_name}', '').replace(domain_name, '@')
        value      = rec.get('value', '')
        priority   = rec.get('priority', '')
        ttl        = rec.get('ttl', 'auto')
        rec_status = rec.get('status', '')
        status_color = {'verified':'#16a34a', 'not_started':'#dc2626',
                        'pending':'#d97706'}.get(rec_status.lower(), '#6b7280')
        rows.append(f'''
        <tr>
          <td style="padding:10px;border:1px solid #ddd;font-weight:600">{rec_type}</td>
          <td style="padding:10px;border:1px solid #ddd"><code style="font-size:13px">{host}</code></td>
          <td style="padding:10px;border:1px solid #ddd"><code style="font-size:11px;word-break:break-all">{value}</code></td>
          <td style="padding:10px;border:1px solid #ddd;text-align:center">{priority or '-'}</td>
          <td style="padding:10px;border:1px solid #ddd;text-align:center">{ttl}</td>
          <td style="padding:10px;border:1px solid #ddd;color:{status_color};font-weight:700">{rec_status}</td>
        </tr>''')

    overall_color = {'verified':'#16a34a', 'not_started':'#dc2626',
                     'pending':'#d97706'}.get(status.lower(), '#6b7280')
    rows_html = ''.join(rows) if rows else '<tr><td colspan="6" style="padding:20px;text-align:center">No records found</td></tr>'

    return f'''<!DOCTYPE html>
<html><head><title>Resend DNS Records — transcrypts.com</title>
<style>body {{font-family: system-ui,sans-serif; max-width: 1100px; margin: 30px auto; padding: 0 20px}}</style>
</head><body>
<h1>Resend DNS Records for <code>transcrypts.com</code></h1>
<p>Domain status:
   <strong style="color:{overall_color};text-transform:uppercase">{status}</strong>
</p>
<p>Add these 3 records in Squarespace Domains:
   <a href="https://domains.squarespace.com/" target="_blank">domains.squarespace.com</a></p>

<table style="border-collapse:collapse;width:100%;margin-top:20px;font-size:14px">
  <thead style="background:#f3f4f6">
    <tr>
      <th style="padding:10px;border:1px solid #ddd;text-align:left">Type</th>
      <th style="padding:10px;border:1px solid #ddd;text-align:left">Host / Name</th>
      <th style="padding:10px;border:1px solid #ddd;text-align:left">Value</th>
      <th style="padding:10px;border:1px solid #ddd">Priority</th>
      <th style="padding:10px;border:1px solid #ddd">TTL</th>
      <th style="padding:10px;border:1px solid #ddd">Status</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>

<h2 style="margin-top:40px">Squarespace DNS — step by step</h2>
<ol style="line-height:1.8">
  <li>Open <a href="https://domains.squarespace.com/" target="_blank">domains.squarespace.com</a> and sign in</li>
  <li>Click <strong>transcrypts.com</strong></li>
  <li>Left sidebar: <strong>DNS Settings</strong> (or <strong>Custom Records</strong>)</li>
  <li>For EACH row above, click "Add Record" and copy the values from this page</li>
  <li>Save</li>
  <li>Wait 5 to 10 minutes</li>
  <li>Refresh THIS page — when every record shows <span style="color:#16a34a;font-weight:700">verified</span>, you are done.</li>
</ol>

<p style="margin-top:30px;padding:12px 16px;background:#fef3c7;border-radius:8px;color:#78350f">
  Once all rows show <strong>verified</strong>, candidate emails will start delivering.
  No code change needed.
</p>
</body></html>'''


@app.route('/admin/email/preview/<kind>')
@role_required(*CAN_USERS)
def admin_email_preview(kind):
    """
    Render the full candidate or interviewer email HTML in the browser so
    you can see exactly what gets sent — without scheduling a fake interview
    or waiting for SMTP delivery.

    Use:
      /admin/email/preview/candidate?type=In-Person
      /admin/email/preview/candidate?type=Video
      /admin/email/preview/interviewer?type=In-Person
    """
    fake_applicant = {
        'name':            'Sample Candidate',
        'email':           'sample@example.com',
        'specialty':       'Software Engineer',
        'resume_filename': None,
    }
    iv_type  = (request.args.get('type') or 'In-Person').strip()
    position = 'Senior Software Engineer'
    contact  = 'Mr. Mesum Rizvi'
    meet     = ''
    if iv_type == 'Video':
        meet = _generate_jitsi_link(0, position)

    if kind == 'candidate':
        html = _candidate_email_html(
            fake_applicant, '2026-05-15', '10:00 AM',
            iv_type, position, contact, meet)
    elif kind == 'interviewer':
        html = _interviewer_email_html(
            fake_applicant, position, '2026-05-15', '10:00 AM',
            iv_type, 'Sample Interviewer', contact, meet)
    else:
        return ('Unknown preview kind. Use "candidate" or "interviewer".', 400)
    return html


@app.route('/admin/email/test', methods=['GET', 'POST'])
@role_required(*CAN_USERS)
def admin_email_test():
    """
    Test the SMTP configuration by sending a small email to a target address.
    GET /admin/email/test?to=you@example.com  →  JSON with ok / err
    POST /admin/email/test (form: to=…)       →  same

    Useful for diagnosing Render env var setup without scheduling a fake
    interview. Returns the actual SMTP error string when sending fails so
    you can see exactly what the SMTP server complained about.
    """
    to = (request.values.get('to') or '').strip()
    if not to:
        creds = _email_credentials()
        return jsonify({
            'ok':         False,
            'message':    'Pass ?to=you@example.com to test email sending',
            'config_seen': {
                'server':   creds.get('server'),
                'port':     creds.get('port'),
                'username': creds.get('username'),
                'from':     creds.get('from'),
                'password_set': bool(creds.get('password')),
            },
        })
    html = (f'<p>This is a test email from the TransCrypts Resume Database.</p>'
            f'<p>If you received this, your SMTP env vars on the host are working.</p>'
            f'<p style="color:#6b7280;font-size:12px">Sent at '
            f'{datetime.now().isoformat(timespec="seconds")}.</p>')
    ok, err = _send_email(to, 'TransCrypts: SMTP test email', html)
    return jsonify({'ok': ok, 'message': err if not ok else f'Sent to {to}'})


# ── Indeed inbox ingestion ──────────────────────────────────────────────────
# Polls the configured IMAP mailbox for UNSEEN messages from Indeed and turns
# each one into an applicant record using the existing parsing pipeline.
# Triggered by an external cron (e.g. cron-job.org) hitting the poll endpoint
# with the configured token. Designed so the entire feature is a no-op until
# INDEED_IMAP_HOST + INDEED_IMAP_USER are set on the host.

_INDEED_NAME_RE  = re.compile(r'(?:Candidate(?:\sname)?|Name|Applicant)\s*[:\-]\s*([A-Z][A-Za-z\'\-\. ]{1,80})')
_INDEED_PHONE_RE = re.compile(r'(?:\+?\d[\d\-\s\(\)]{6,}\d)')
_INDEED_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_INDEED_SUBJ_NAME_RE = re.compile(
    r'^(?:\s*\[?indeed\]?\s*[:\-]?\s*)?'             # optional "[Indeed]" prefix
    r'(?:new\s+candidate(?:\s+for)?|new\s+application(?:\s+for)?)?\s*'
    r'([A-Z][A-Za-z\'\-\. ]{1,80}?)'                 # candidate name
    r'\s+applied\s+to\s+(?:your\s+)?(.+?)(?:\s+job)?\s*$',
    re.IGNORECASE,
)
_INDEED_SUBJ_POS_RE = re.compile(
    r'(?:new\s+candidate\s+for|new\s+application\s+for|for\s+your)\s+(.+?)\s*$',
    re.IGNORECASE,
)
_INDEED_LINK_LABEL_RE = re.compile(
    r'(?:download|view|see)\s+(?:the\s+)?(?:full\s+)?(?:resume|cv|attachment|application)',
    re.IGNORECASE,
)


def _strip_html(html):
    """Crude tag-stripper for the rare email that has no plain-text part.
    Drops <script>/<style> blocks, replaces <br>/<p>/<div> with newlines,
    then strips remaining tags. Good enough for regex extraction; we never
    show this text to a user.
    """
    if not html:
        return ''
    try:
        s = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', html)
        s = re.sub(r'(?i)<br\s*/?>', '\n', s)
        s = re.sub(r'(?i)</(p|div|li|tr|h[1-6])\s*>', '\n', s)
        s = re.sub(r'<[^>]+>', ' ', s)
        # Decode the most common HTML entities without pulling in extra deps.
        try:
            import html as _htmllib
            s = _htmllib.unescape(s)
        except Exception:
            pass
        s = re.sub(r'[ \t]+', ' ', s)
        s = re.sub(r'\n{2,}', '\n\n', s)
        return s.strip()
    except Exception:
        return html or ''


def _email_address_domain(addr):
    """Return the lowercased domain part of an email address (or '')."""
    if not addr:
        return ''
    m = _INDEED_EMAIL_RE.search(addr)
    if not m:
        return ''
    return m.group(0).rsplit('@', 1)[-1].lower()


def _decode_email_part(part):
    """Decode a single email body part into a unicode string. Best-effort —
    falls back to latin-1 if the declared charset is missing or wrong."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ''
        charset = part.get_content_charset() or 'utf-8'
        try:
            return payload.decode(charset, errors='replace')
        except (LookupError, TypeError):
            return payload.decode('utf-8', errors='replace')
    except Exception:
        return ''


def _extract_indeed_email_content(msg):
    """Walk an email.Message and return (text_body, html_body, attachments,
    reply_to_email). Attachments come back as a list of (filename, bytes,
    content_type) tuples — only those that look like resume files are kept."""
    text_body = ''
    html_body = ''
    attachments = []

    for part in msg.walk():
        ctype = (part.get_content_type() or '').lower()
        disposition = (part.get('Content-Disposition') or '').lower()
        filename = part.get_filename() or ''
        if filename:
            # Some clients send the filename RFC2047-encoded
            try:
                from email.header import decode_header, make_header
                filename = str(make_header(decode_header(filename)))
            except Exception:
                pass
        is_attachment = ('attachment' in disposition) or bool(filename)

        if is_attachment and filename:
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext in ('pdf', 'doc', 'docx'):
                try:
                    data = part.get_payload(decode=True) or b''
                except Exception:
                    data = b''
                if data:
                    attachments.append((filename, data, ctype or 'application/octet-stream'))
            continue

        if ctype == 'text/plain' and not text_body:
            text_body = _decode_email_part(part)
        elif ctype == 'text/html' and not html_body:
            html_body = _decode_email_part(part)

    # Reply-To is often the candidate's real email on Indeed messages.
    reply_to_email = ''
    rt_header = msg.get('Reply-To') or msg.get('Return-Path') or ''
    if rt_header:
        m = _INDEED_EMAIL_RE.search(rt_header)
        if m:
            reply_to_email = m.group(0)

    return text_body, html_body, attachments, reply_to_email


def _parse_indeed_email_fields(subject, text_body, html_body, reply_to_email):
    """Extract candidate name / email / phone / applied position from an
    Indeed email. All return values are stripped strings (possibly empty).
    """
    body_text = text_body or _strip_html(html_body) or ''
    subject = (subject or '').strip()

    # ── Position ─────────────────────────────────────────────────────────────
    position = ''
    m = _INDEED_SUBJ_NAME_RE.match(subject)
    if m:
        position = m.group(2).strip()
    else:
        m = _INDEED_SUBJ_POS_RE.search(subject)
        if m:
            position = m.group(1).strip()
    # Common cleanup: strip trailing " job" / quotes / Indeed boilerplate
    position = re.sub(r'(?i)\s+job\s*$', '', position).strip(' "\'')
    if not position:
        # Try body line like "Position: X" or "applied to the X position"
        bm = re.search(r'(?im)^\s*(?:position|job\s*title|role)\s*[:\-]\s*(.+)$', body_text)
        if bm:
            position = bm.group(1).strip()
        else:
            bm = re.search(r'(?i)applied\s+(?:to|for)\s+(?:the\s+|your\s+)?(.+?)(?:\s+position|\s+role|\.|$)',
                            body_text[:600])
            if bm:
                position = bm.group(1).strip()
    if not position:
        position = 'Indeed Application'

    # ── Name ─────────────────────────────────────────────────────────────────
    name = ''
    m = _INDEED_SUBJ_NAME_RE.match(subject)
    if m:
        name = m.group(1).strip()
    if not name:
        bm = _INDEED_NAME_RE.search(body_text[:2000])
        if bm:
            name = bm.group(1).strip()
    if not name:
        # Heuristic: the first short ALL-OR-Title-Case line near the top of
        # the body that's not an Indeed boilerplate phrase.
        for ln in (body_text.splitlines()[:25] if body_text else []):
            s = ln.strip()
            if not s or len(s) > 60:
                continue
            if re.search(r'(?i)indeed|application|candidate|resume|view|download|reply|new', s):
                continue
            if re.match(r'^[A-Z][A-Za-z\'\-\.]+(?:\s+[A-Z][A-Za-z\'\-\.]+){1,3}$', s):
                name = s
                break

    # ── Email ────────────────────────────────────────────────────────────────
    # Strongly prefer Reply-To since Indeed sets that to the candidate's
    # actual email. Fall back to the first email in the body that is NOT
    # an Indeed domain.
    email_addr = ''
    if reply_to_email and 'indeed.com' not in reply_to_email.lower() \
                     and 'indeedemail.com' not in reply_to_email.lower():
        email_addr = reply_to_email.strip()
    if not email_addr:
        for em in _INDEED_EMAIL_RE.findall(body_text or ''):
            lo = em.lower()
            if 'indeed.com' in lo or 'indeedemail.com' in lo or 'noreply' in lo or 'no-reply' in lo:
                continue
            email_addr = em
            break

    # ── Phone ────────────────────────────────────────────────────────────────
    phone = ''
    bm = _INDEED_PHONE_RE.search(body_text or '')
    if bm:
        phone = bm.group(0).strip()

    return {
        'name':     name,
        'email':    email_addr,
        'phone':    phone,
        'position': position,
    }


def _find_indeed_resume_link(text_body, html_body):
    """Return the first URL in the email body that looks like a 'Download
    resume' or 'View attachment' link — or '' if none found. We scan the
    HTML for anchor tags with matching labels first (more reliable), then
    fall back to a plain-text URL scan."""
    if html_body:
        # Find each <a href="...">label</a> and pick one whose label matches.
        for m in re.finditer(r'(?is)<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                              html_body):
            href = m.group(1)
            label = _strip_html(m.group(2)) or ''
            if _INDEED_LINK_LABEL_RE.search(label):
                return href
    # Plain-text fallback
    body = text_body or _strip_html(html_body) or ''
    for line in body.splitlines():
        if _INDEED_LINK_LABEL_RE.search(line):
            urls = re.findall(r'https?://\S+', line)
            if urls:
                return urls[0].rstrip('.,)>"\'')
    return ''


def _try_download_resume(url, timeout=10):
    """Best-effort: GET the URL and return (filename, bytes, content_type)
    if it looks like a PDF/DOC/DOCX. Returns None for HTML / login pages /
    timeouts / unrecognised types — the caller treats this as 'no resume'.
    """
    if not url:
        return None
    try:
        import requests as _rq
        resp = _rq.get(url, timeout=timeout, allow_redirects=True,
                       headers={'User-Agent': 'Mozilla/5.0 TransCrypts-ResumeDB'})
    except Exception:
        return None
    if resp.status_code != 200 or not resp.content:
        return None
    ctype = (resp.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
    if ctype in ('application/pdf',):
        ext = 'pdf'
    elif ctype in ('application/msword',):
        ext = 'doc'
    elif ctype in ('application/vnd.openxmlformats-officedocument.wordprocessingml.document',):
        ext = 'docx'
    else:
        # Sniff the first bytes — Indeed sometimes serves PDFs as
        # application/octet-stream.
        head = resp.content[:8]
        if head.startswith(b'%PDF'):
            ext = 'pdf'
        elif head.startswith(b'PK\x03\x04'):
            # DOCX is a ZIP. Could also be XLSX/PPTX, but for an Indeed
            # resume link it's overwhelmingly DOCX.
            ext = 'docx'
        else:
            return None
    # Try to recover the candidate filename from Content-Disposition
    cd = resp.headers.get('Content-Disposition') or ''
    fn_match = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^;"\']+)', cd)
    if fn_match:
        filename = fn_match.group(1).strip()
        if not filename.lower().endswith('.' + ext):
            filename = filename.rsplit('.', 1)[0] + '.' + ext
    else:
        filename = f'IndeedResume.{ext}'
    return (filename, resp.content, ctype or f'application/{ext}')


def _ingest_indeed_email(msg, settings):
    """Process a single email.Message and either create or dedupe an
    applicant. Returns one of: 'created', 'duplicate', 'error:<reason>'.
    """
    from email.header import decode_header, make_header
    try:
        subject_raw = msg.get('Subject') or ''
        try:
            subject = str(make_header(decode_header(subject_raw)))
        except Exception:
            subject = subject_raw

        text_body, html_body, attachments, reply_to_email = \
            _extract_indeed_email_content(msg)
        fields = _parse_indeed_email_fields(subject, text_body, html_body, reply_to_email)
        cand_name     = fields['name']
        cand_email    = fields['email']
        cand_phone    = fields['phone']
        cand_position = fields['position']

        # ── Resume file ──────────────────────────────────────────────────────
        resume_filename = None
        file_hash = None
        text_hash = None
        parsed_text = None
        parsed = {}
        resume_note = ''

        chosen = None
        if attachments:
            chosen = attachments[0]                # (name, bytes, ctype)
        else:
            link = _find_indeed_resume_link(text_body, html_body)
            if link:
                chosen = _try_download_resume(link, timeout=10)
                if not chosen:
                    resume_note = ('Resume only available in Indeed dashboard '
                                   '— log in to download.')
            else:
                resume_note = ('Resume only available in Indeed dashboard '
                               '— log in to download.')

        if chosen:
            attach_name, raw_bytes, ctype = chosen
            # Compute hashes
            try:
                file_hash = hashlib.sha256(raw_bytes).hexdigest()
            except Exception:
                file_hash = None
            try:
                text_hash = compute_text_hash(raw_bytes, attach_name)
            except Exception:
                text_hash = None
            try:
                parsed = parse_resume_bytes(raw_bytes, attach_name) or {}
            except Exception:
                parsed = {}
            try:
                _txt = _extract_text_from_file(raw_bytes, (attach_name or '').lower())
                if _txt and _txt.strip():
                    parsed_text = _txt
            except Exception:
                parsed_text = None

            # Save the file using the existing storage abstraction
            try:
                resume_filename = make_unique_filename(attach_name or 'IndeedResume.pdf')
                _storage.save_file(resume_filename, raw_bytes,
                                   ctype or 'application/octet-stream')
            except Exception as e:
                resume_filename = None
                resume_note = (resume_note + ' ' if resume_note else '') + \
                              f'(Failed to save attachment: {type(e).__name__})'

        # ── Identity match (prefer parsed-from-resume identity) ──────────────
        effective_name  = (parsed.get('name')  or '').strip() or cand_name
        effective_email = (parsed.get('email') or '').strip() or cand_email
        effective_phone = (parsed.get('phone') or '').strip() or cand_phone

        match = find_identity_match(name=effective_name, email=effective_email,
                                    phone=effective_phone)
        if match:
            # Update applied_position on the existing record if the email
            # mentions a different position than what we already track.
            try:
                with get_db() as conn:
                    row = conn.execute(
                        'SELECT applied_position FROM applicants WHERE id=?',
                        (match['id'],)
                    ).fetchone()
                    old_pos = (row['applied_position'] if row else '') or ''
                    if cand_position and cand_position.lower() not in old_pos.lower():
                        new_pos = (old_pos + ' | ' + cand_position).strip(' |') \
                                  if old_pos else cand_position
                        conn.execute(
                            'UPDATE applicants SET applied_position=? WHERE id=?',
                            (new_pos, match['id'])
                        )
                        conn.commit()
            except Exception:
                pass
            log_action('INDEED INGEST (DUP)', effective_name or cand_name or '(unknown)',
                       f'Already on file as id={match["id"]}. '
                       f'Position: {cand_position}')
            return 'duplicate'

        # ── Build the row ───────────────────────────────────────────────────
        final_name = effective_name or 'Indeed Applicant'
        final_specialty = (parsed.get('specialty') or '').strip() or \
                          (cand_position or 'Indeed Application')
        years   = _safe_int(parsed.get('years_experience'), 0)
        edu     = (parsed.get('highest_education') or '').strip()
        skills  = (parsed.get('skills') or '').strip()
        notes_parts = []
        if parsed.get('notes'):
            notes_parts.append(parsed['notes'])
        if resume_note:
            notes_parts.append(resume_note)
        notes_combined = '\n\n'.join(notes_parts)
        linkedin = (parsed.get('linkedin_url') or '').strip()
        github   = (parsed.get('github_url')   or '').strip()

        with get_db() as conn:
            conn.execute(
                '''INSERT INTO applicants
                   (name, email, phone, specialty, years_experience,
                    highest_education, skills, resume_filename, notes,
                    date_added, hiring_status, linkedin_url, github_url,
                    file_hash, text_hash, source, applied_position,
                    parsed_text)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    final_name,
                    effective_email,
                    effective_phone,
                    final_specialty,
                    years,
                    edu,
                    skills,
                    resume_filename,
                    notes_combined,
                    datetime.now().isoformat(timespec='seconds'),
                    'Under Review',
                    linkedin,
                    github,
                    file_hash,
                    text_hash,
                    'Indeed',
                    cand_position,
                    parsed_text,
                )
            )
            conn.commit()
        log_action('INDEED INGEST', final_name,
                   f'Position: {cand_position}'
                   + (' | no resume file' if not resume_filename else ''))
        return 'created'
    except Exception as e:
        return f'error:{type(e).__name__}: {str(e)[:200]}'


def _upsert_indeed_poll_status(processed, created, duplicates, errors_text):
    """Write the latest poll outcome into the single-row status table."""
    try:
        ts = datetime.now().isoformat(timespec='seconds')
        with get_db() as conn:
            # Single row with id=1 — try UPDATE, then INSERT if no row exists.
            cur = conn.execute(
                'UPDATE indeed_poll_status SET last_run=?, processed=?, '
                'created=?, duplicates=?, errors=? WHERE id=1',
                (ts, processed, created, duplicates, errors_text)
            )
            affected = getattr(cur, 'rowcount', 0) or 0
            if not affected:
                conn.execute(
                    'INSERT INTO indeed_poll_status '
                    '(id, last_run, processed, created, duplicates, errors) '
                    'VALUES (1, ?, ?, ?, ?, ?)',
                    (ts, processed, created, duplicates, errors_text)
                )
            conn.commit()
    except Exception:
        pass


def _get_indeed_poll_status():
    """Return the single status row as a dict, or None if no poll has run yet."""
    try:
        with get_db() as conn:
            row = conn.execute(
                'SELECT last_run, processed, created, duplicates, errors '
                'FROM indeed_poll_status WHERE id=1'
            ).fetchone()
            if not row:
                return None
            return dict(row) if not isinstance(row, dict) else row
    except Exception:
        return None


def _run_indeed_poll(settings):
    """Connect to the configured IMAP mailbox, ingest UNSEEN messages from
    the allowed sender domains, mark them as Seen, and return a result dict.

    On any unexpected error (auth failure, network, etc.) returns
    {ok: False, error: '…'} without raising.
    """
    import imaplib, email as _emaillib
    result = {
        'ok':         True,
        'processed':  0,
        'created':    0,
        'duplicates': 0,
        'errors':     [],
        'last_run':   datetime.now().isoformat(timespec='seconds'),
    }
    M = None
    try:
        if settings['use_ssl']:
            M = imaplib.IMAP4_SSL(settings['host'], settings['port'], timeout=20)
        else:
            M = imaplib.IMAP4(settings['host'], settings['port'], timeout=20)
            try:
                M.starttls()
            except Exception:
                # Some servers (Proton Bridge plaintext on 143) don't offer STARTTLS
                pass
        M.login(settings['user'], settings['password'])
        M.select(settings['folder'])

        # Build an IMAP search query — unseen messages whose From contains
        # any allowed Indeed domain. IMAP can OR multiple FROM filters.
        domains = list(settings['sender_domains']) or ['indeed.com']
        # Search per-domain and union the result UIDs; some servers don't
        # like deeply-nested OR queries, so this is safer.
        uid_set = set()
        for dom in domains:
            try:
                typ, data = M.uid('search', None, 'UNSEEN', 'FROM', f'"{dom}"')
                if typ == 'OK' and data and data[0]:
                    for uid in data[0].split():
                        uid_set.add(uid)
            except Exception as e:
                result['errors'].append(f'Search failed for {dom}: {type(e).__name__}')

        for uid in sorted(uid_set):
            try:
                typ, data = M.uid('fetch', uid, '(RFC822)')
                if typ != 'OK' or not data or not data[0]:
                    result['errors'].append(f'Fetch failed for UID {uid.decode() if isinstance(uid, bytes) else uid}')
                    continue
                raw = data[0][1]
                msg = _emaillib.message_from_bytes(raw)
                outcome = _ingest_indeed_email(msg, settings)
                result['processed'] += 1
                if outcome == 'created':
                    result['created'] += 1
                elif outcome == 'duplicate':
                    result['duplicates'] += 1
                elif outcome.startswith('error:'):
                    result['errors'].append(outcome[6:])
            except Exception as e:
                result['errors'].append(f'UID {uid}: {type(e).__name__}: {str(e)[:120]}')
            finally:
                # Always mark as Seen so a poison message doesn't get retried
                # forever. The audit log preserves the per-message outcome.
                try:
                    M.uid('store', uid, '+FLAGS', '\\Seen')
                except Exception:
                    pass
    except Exception as e:
        result['ok']    = False
        result['error'] = f'{type(e).__name__}: {str(e)[:200]}'
    finally:
        if M is not None:
            try: M.close()
            except Exception: pass
            try: M.logout()
            except Exception: pass

    # Persist the outcome
    err_text = '; '.join(result['errors'])[:2000] if result['errors'] else ''
    if not result.get('ok') and result.get('error'):
        err_text = (err_text + ' | ' if err_text else '') + result['error']
    _upsert_indeed_poll_status(result['processed'], result['created'],
                                result['duplicates'], err_text)
    return result


def _valid_indeed_token(provided, expected):
    """Constant-time token comparison. Empty / mismatched tokens reject."""
    if not expected or not provided:
        return False
    try:
        return hmac.compare_digest(str(provided), str(expected))
    except Exception:
        return False


@app.route('/admin/poll-indeed', methods=['GET', 'POST'])
def admin_poll_indeed():
    """Public endpoint hit by an external cron service. Token-protected so
    it can be called without an authenticated session. GET is allowed as an
    alias so simple URL pingers (cron-job.org) work."""
    token = request.args.get('token') or request.form.get('token') or ''
    settings = _indeed_settings()
    if not _valid_indeed_token(token, settings['cron_token']):
        return jsonify({'ok': False, 'error': 'Invalid or missing token.'}), 401
    if not settings['is_configured']:
        return jsonify({
            'ok':       False,
            'error':    'Indeed inbox not configured.',
            'missing':  settings['missing'],
        }), 503
    if not settings['password']:
        return jsonify({
            'ok':       False,
            'error':    'INDEED_IMAP_PASSWORD is not set.',
        }), 503
    result = _run_indeed_poll(settings)
    return jsonify(result), (200 if result.get('ok') else 502)


@app.route('/admin/poll-indeed/manual', methods=['POST'])
@role_required(*CAN_USERS)
def admin_poll_indeed_manual():
    """Admin-only 'Poll Now' button on the Indeed inbox page. Uses the
    logged-in session for auth so the user doesn't have to handle the
    cron token in the browser."""
    settings = _indeed_settings()
    if not settings['is_configured']:
        flash('Indeed inbox is not configured — set INDEED_IMAP_HOST and '
              'INDEED_IMAP_USER on the host first.', 'error')
        return redirect(url_for('admin_indeed_inbox'))
    if not settings['password']:
        flash('INDEED_IMAP_PASSWORD is missing. Set it on the host and '
              'redeploy before polling.', 'error')
        return redirect(url_for('admin_indeed_inbox'))
    result = _run_indeed_poll(settings)
    if result.get('ok'):
        flash(
            f'Poll complete — processed {result["processed"]}, '
            f'created {result["created"]}, duplicates {result["duplicates"]}'
            + (f', errors: {len(result["errors"])}' if result.get('errors') else ''),
            'success'
        )
    else:
        flash(f'Poll failed: {result.get("error", "unknown error")}', 'error')
    return redirect(url_for('admin_indeed_inbox'))


@app.route('/admin/indeed-inbox')
@role_required(*CAN_USERS)
def admin_indeed_inbox():
    """Admin page: shows config status, last-run stats, and recent Indeed
    applicants. Never exposes IMAP credentials."""
    settings = _indeed_settings()
    status = _get_indeed_poll_status()

    recent = []
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, name, email, applied_position, date_added "
                "FROM applicants "
                "WHERE COALESCE(source, '') = 'Indeed' "
                "ORDER BY date_added DESC, id DESC LIMIT 20"
            ).fetchall()
            recent = [dict(r) for r in rows]
    except Exception:
        recent = []

    # Build the cron URL the user copy-pastes into cron-job.org. Use the
    # incoming request's host so it works in both local and production.
    cron_url = ''
    if settings['cron_token']:
        cron_url = (request.url_root.rstrip('/')
                    + url_for('admin_poll_indeed')
                    + f'?token={settings["cron_token"]}')

    # Don't echo the token back into a publicly-visible place — only show it
    # via the cron URL, which the admin uses once and stores in cron-job.org.
    return render_template(
        'indeed_inbox.html',
        configured       = settings['is_configured'],
        poll_ready       = settings['is_poll_ready'],
        missing          = settings['missing_for_poll'],
        imap_host        = settings['host'],
        imap_user        = settings['user'],
        imap_folder      = settings['folder'],
        imap_port        = settings['port'],
        imap_ssl         = settings['use_ssl'],
        sender_domains   = ', '.join(settings['sender_domains']),
        status           = status,
        recent           = recent,
        cron_url         = cron_url,
        has_token        = bool(settings['cron_token']),
    )


# ── Indeed bookmarklet (single-click candidate import from Indeed) ─────────
# The HR user drags a small bookmarklet into their bookmarks bar. While
# viewing a candidate's profile on Indeed Resume Search they click the
# bookmarklet; it extracts name / email / phone / position / resume link
# from the current page DOM and POSTs them to /api/indeed/import with a
# pre-shared bearer key baked into the bookmarklet itself. The endpoint
# reuses the standard parse_resume_bytes + find_identity_match + storage
# pipeline so imported candidates land in the same place as everything else.

@app.route('/api/indeed/import', methods=['POST', 'OPTIONS'])
def api_indeed_import():
    """Public token-authenticated endpoint for the Indeed bookmarklet.

    No Flask session is involved — the request comes from indeed.com via
    `fetch` so we authenticate with an API key (the INDEED_BOOKMARKLET_KEY
    env var, compared with hmac.compare_digest). The existing
    `_add_cors_headers` after_request hook already emits the necessary
    CORS headers; we still respond to the OPTIONS preflight here.

    Body (JSON):
        api_key, name, email, phone, position, summary, skills,
        resume_url, source_url, raw_html_text.

    Returns JSON {ok, applicant_id?, duplicate?, message}.
    """
    if request.method == 'OPTIONS':
        return ('', 204)

    cfg = _indeed_bookmarklet_settings()
    expected_key = cfg['api_key']

    # ── Auth ─────────────────────────────────────────────────────────────
    # Fail-closed when the key isn't configured on the host — that way a
    # missing env var doesn't open the endpoint to the public internet.
    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}

    provided_key = (payload.get('api_key') or
                    request.headers.get('X-API-Key') or '').strip()
    if not expected_key or not provided_key or \
       not hmac.compare_digest(str(provided_key), str(expected_key)):
        return jsonify({'ok': False,
                        'message': 'Unauthorized — invalid or missing API key.'}), 401

    # ── Extract / sanitize fields ────────────────────────────────────────
    def _s(v, limit=2000):
        if v is None:
            return ''
        try:
            return str(v).strip()[:limit]
        except Exception:
            return ''

    name          = _s(payload.get('name'),          300)
    email         = _s(payload.get('email'),         300)
    phone         = _s(payload.get('phone'),         100)
    position      = _s(payload.get('position'),      500)
    summary       = _s(payload.get('summary'),       4000)
    skills        = _s(payload.get('skills'),        2000)
    resume_url    = _s(payload.get('resume_url'),    2000)
    source_url    = _s(payload.get('source_url'),    2000)
    raw_html_text = _s(payload.get('raw_html_text'), 8000)

    if not (name or email):
        return jsonify({'ok': False,
                        'message': 'Need at least a name or an email '
                                   'to import. Try opening the candidate '
                                   'profile and clicking the bookmark again.'}), 400

    # ── Try to download the resume file when a URL is supplied ──────────
    resume_filename = None
    file_hash       = None
    text_hash       = None
    parsed_text     = None
    parsed          = {}
    resume_note     = ''

    if resume_url:
        chosen = None
        try:
            import requests as _rq
            resp = _rq.get(
                resume_url, timeout=10, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 TransCrypts-ResumeDB-Bookmarklet'},
            )
            if resp.status_code == 200 and resp.content and len(resp.content) < 10 * 1024 * 1024:
                ctype = (resp.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
                if ('pdf' in ctype) or ('msword' in ctype) or \
                   ('officedocument' in ctype) or ('octet-stream' in ctype):
                    head = resp.content[:8]
                    if 'pdf' in ctype or head.startswith(b'%PDF'):
                        ext = 'pdf'
                    elif 'msword' in ctype:
                        ext = 'doc'
                    elif 'officedocument' in ctype or head.startswith(b'PK\x03\x04'):
                        ext = 'docx'
                    else:
                        ext = None
                    if ext:
                        # Recover filename from Content-Disposition if possible
                        cd = resp.headers.get('Content-Disposition') or ''
                        fn_match = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^;"\']+)', cd)
                        if fn_match:
                            fname = fn_match.group(1).strip()
                            if not fname.lower().endswith('.' + ext):
                                fname = fname.rsplit('.', 1)[0] + '.' + ext
                        else:
                            fname = f'IndeedResume.{ext}'
                        chosen = (fname, resp.content, ctype or f'application/{ext}')
        except Exception:
            chosen = None

        if chosen:
            attach_name, raw_bytes, ctype = chosen
            try:
                file_hash = hashlib.sha256(raw_bytes).hexdigest()
            except Exception:
                file_hash = None
            try:
                text_hash = compute_text_hash(raw_bytes, attach_name)
            except Exception:
                text_hash = None
            try:
                parsed = parse_resume_bytes(raw_bytes, attach_name) or {}
            except Exception:
                parsed = {}
            try:
                _txt = _extract_text_from_file(raw_bytes, (attach_name or '').lower())
                if _txt and _txt.strip():
                    parsed_text = _txt
            except Exception:
                parsed_text = None
            try:
                resume_filename = make_unique_filename(attach_name or 'IndeedResume.pdf')
                _storage.save_file(resume_filename, raw_bytes,
                                   ctype or 'application/octet-stream')
            except Exception as e:
                resume_filename = None
                resume_note = (resume_note + ' ' if resume_note else '') + \
                              f'(Failed to save resume file: {type(e).__name__})'
        else:
            resume_note = ('Resume file not directly downloadable — open '
                           'the source link on Indeed to grab it manually.')

    # If we don't have a real file, fall back to the page text the
    # bookmarklet captured so the job-matcher can still find this person.
    if not parsed_text and raw_html_text:
        parsed_text = raw_html_text

    # ── Identity match (parsed values win over what the page yielded) ───
    effective_name  = (parsed.get('name')  or '').strip() or name
    effective_email = (parsed.get('email') or '').strip() or email
    effective_phone = (parsed.get('phone') or '').strip() or phone

    try:
        match = find_identity_match(name=effective_name,
                                    email=effective_email,
                                    phone=effective_phone)
    except Exception:
        match = None

    final_position = position or 'Indeed Profile'

    try:
        if match:
            # Append the new position context to the existing row
            try:
                with get_db() as conn:
                    row = conn.execute(
                        'SELECT applied_position FROM applicants WHERE id=?',
                        (match['id'],)
                    ).fetchone()
                    old_pos = (row['applied_position'] if row else '') or ''
                    if final_position and final_position.lower() not in old_pos.lower():
                        new_pos = (old_pos + ' | ' + final_position).strip(' |') \
                                  if old_pos else final_position
                        conn.execute(
                            'UPDATE applicants SET applied_position=? WHERE id=?',
                            (new_pos, match['id'])
                        )
                        conn.commit()
            except Exception:
                pass
            log_action('INDEED IMPORT (DUP)',
                       effective_name or '(unknown)',
                       f'Already on file as id={match["id"]}. '
                       f'IMPORT-SRC=bookmarklet | Position: {final_position} | '
                       f'Source: {source_url[:200]}')
            return jsonify({
                'ok':           True,
                'duplicate':    True,
                'applicant_id': match['id'],
                'message':      f'Already on file as {match.get("name") or "this candidate"}.',
            })

        # ── Insert a new applicant ───────────────────────────────────────
        final_name = effective_name or 'Indeed Candidate'
        final_specialty = (parsed.get('specialty') or '').strip() or \
                          (final_position or 'Indeed Profile')
        years   = _safe_int(parsed.get('years_experience'), 0)
        edu     = (parsed.get('highest_education') or '').strip()
        merged_skills = (parsed.get('skills') or '').strip() or skills
        notes_parts = []
        if summary:
            notes_parts.append(summary)
        if parsed.get('notes'):
            notes_parts.append(parsed['notes'])
        if source_url:
            notes_parts.append(f'Imported from Indeed via bookmarklet — source: {source_url}')
        if resume_note:
            notes_parts.append(resume_note)
        notes_combined = '\n\n'.join(notes_parts)
        linkedin = (parsed.get('linkedin_url') or '').strip()
        github   = (parsed.get('github_url')   or '').strip()

        with get_db() as conn:
            cur = conn.execute(
                '''INSERT INTO applicants
                   (name, email, phone, specialty, years_experience,
                    highest_education, skills, resume_filename, notes,
                    date_added, hiring_status, linkedin_url, github_url,
                    file_hash, text_hash, source, applied_position,
                    parsed_text)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    final_name,
                    effective_email,
                    effective_phone,
                    final_specialty,
                    years,
                    edu,
                    merged_skills,
                    resume_filename,
                    notes_combined,
                    datetime.now().isoformat(timespec='seconds'),
                    'Under Review',
                    linkedin,
                    github,
                    file_hash,
                    text_hash,
                    'Indeed',
                    final_position,
                    parsed_text,
                )
            )
            new_id = getattr(cur, 'lastrowid', None)
            if new_id is None:
                # Postgres path (psycopg2) — re-query the new id
                try:
                    row = conn.execute(
                        'SELECT id FROM applicants WHERE name=? AND '
                        'COALESCE(email,\'\')=COALESCE(?,\'\') '
                        'ORDER BY id DESC LIMIT 1',
                        (final_name, effective_email)
                    ).fetchone()
                    new_id = row['id'] if row else None
                except Exception:
                    new_id = None
            conn.commit()
        log_action('INDEED IMPORT',
                   final_name,
                   f'IMPORT-SRC=bookmarklet | Position: {final_position} | '
                   f'Source: {source_url[:200]}'
                   + ('' if resume_filename else ' | no resume file'))
        return jsonify({
            'ok':           True,
            'duplicate':    False,
            'applicant_id': new_id,
            'message':      f'Saved {final_name} to TransCrypts.',
        })
    except Exception as e:
        try:
            log_action('INDEED IMPORT ERROR',
                       effective_name or '(unknown)',
                       f'{type(e).__name__}: {str(e)[:300]}')
        except Exception:
            pass
        return jsonify({
            'ok':      False,
            'message': 'Server error while saving — please try again or '
                       'add the candidate manually.',
        }), 500


# Bookmarklet JS source. Two placeholders __API_URL__ and __API_KEY__ are
# substituted server-side; the result is then URL-quoted and stuffed into
# the href="javascript:..." of a draggable link. Keep this as one logical
# block of statements; the build step joins it onto a single line so it
# survives copy-paste into a bookmark.
_INDEED_BOOKMARKLET_JS = r"""(function(){var __SHIFT__=!!(window.event&&window.event.shiftKey);var __URL__='__API_URL__';var __KEY__='__API_KEY__';function txt(el){return el?(el.innerText||el.textContent||'').trim():'';}function pickEmail(){var a=document.querySelector('a[href^=\"mailto:\"]');if(a){var v=a.getAttribute('href').replace(/^mailto:/i,'').split('?')[0].trim();if(v)return v;}var m=document.body.innerText.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);return m?m[0]:'';}function pickPhone(){var a=document.querySelector('a[href^=\"tel:\"]');if(a){var v=a.getAttribute('href').replace(/^tel:/i,'').trim();if(v)return v;}var m=document.body.innerText.match(/\+?\d[\d\-\s().]{7,}\d/);return m?m[0].trim():'';}function pickName(){var t=(document.title||'').replace(/\s*-\s*Indeed.*$/i,'').replace(/\s*\|\s*Indeed.*$/i,'').trim();var h1=document.querySelector('h1');if(h1){var v=txt(h1);if(v&&v.length<120)return v;}if(t&&t.length<120)return t;var h2=document.querySelector('h2');return h2?txt(h2).slice(0,120):'';}function pickPosition(){var sels=['[data-testid*=\"jobTitle\"]','[data-testid*=\"headline\"]','[class*=\"headline\"]','[class*=\"JobTitle\"]','[class*=\"jobTitle\"]','h2'];for(var i=0;i<sels.length;i++){var el=document.querySelector(sels[i]);if(el){var v=txt(el);if(v&&v.length<200&&!/indeed/i.test(v))return v;}}var t=(document.title||'');var m=t.match(/-\s*([^|\-]{3,80})\s*-\s*Indeed/i);return m?m[1].trim():'';}function pickResume(){var as=document.querySelectorAll('a');for(var i=0;i<as.length;i++){var a=as[i];var label=((a.innerText||a.textContent||'')+' '+(a.getAttribute('href')||'')+' '+(a.getAttribute('aria-label')||'')).toLowerCase();if(/(resume|\bcv\b|download)/.test(label)){var h=a.getAttribute('href');if(h)return new URL(h,location.href).href;}}return '';}function pickSkills(){var out=[];var nodes=document.querySelectorAll('[class*=\"skill\" i], [data-testid*=\"skill\" i]');for(var i=0;i<nodes.length&&out.length<40;i++){var v=txt(nodes[i]);if(v&&v.length<80&&out.indexOf(v)<0)out.push(v);}return out.join(', ');}function pickSummary(){var sels=['[data-testid*=\"summary\" i]','[class*=\"summary\" i]','[class*=\"about\" i]'];for(var i=0;i<sels.length;i++){var el=document.querySelector(sels[i]);if(el){var v=txt(el);if(v&&v.length>40)return v.slice(0,2000);}}return '';}var data={api_key:__KEY__,name:pickName(),email:pickEmail(),phone:pickPhone(),position:pickPosition(),summary:pickSummary(),skills:pickSkills(),resume_url:pickResume(),source_url:location.href,raw_html_text:(document.body.innerText||'').slice(0,2000)};function toast(msg,kind){var bg=kind==='error'?'#dc2626':(kind==='dup'?'#d97706':'#059669');var d=document.createElement('div');d.style.cssText='position:fixed;bottom:18px;right:18px;background:'+bg+';color:#fff;padding:12px 16px;border-radius:8px;font:600 14px/1.3 system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 4px 12px rgba(0,0,0,.25);z-index:2147483647;max-width:360px;';d.textContent=msg;document.body.appendChild(d);setTimeout(function(){d.style.opacity='0';d.style.transition='opacity .4s';},3600);setTimeout(function(){d.remove();},4200);}function send(payload){return fetch(__URL__,{method:'POST',mode:'cors',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}).then(function(r){return r.json().then(function(j){return{status:r.status,body:j};}).catch(function(){return{status:r.status,body:{ok:false,message:'Bad JSON from server'}};});});}function fire(payload){send(payload).then(function(res){if(res.status===200&&res.body.ok){toast(res.body.message||'Saved.',res.body.duplicate?'dup':'ok');}else{toast((res.body&&res.body.message)||('Error ('+res.status+')'),'error');}}).catch(function(e){toast('Network error: '+(e&&e.message||e),'error');});}if(__SHIFT__){fire(data);return;}var existing=document.getElementById('__tc_indeed_modal__');if(existing)existing.remove();var overlay=document.createElement('div');overlay.id='__tc_indeed_modal__';overlay.style.cssText='position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:2147483646;display:flex;align-items:center;justify-content:center;font:14px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;';var modal=document.createElement('div');modal.style.cssText='background:#fff;width:min(520px,94vw);max-height:88vh;overflow:auto;border-radius:12px;box-shadow:0 12px 30px rgba(0,0,0,.3);padding:18px 20px;';modal.innerHTML='<div style=\"display:flex;align-items:center;gap:8px;margin-bottom:8px\"><div style=\"width:28px;height:28px;border-radius:8px;background:#6DC49A;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700\">TC</div><h3 style=\"margin:0;font-size:16px;color:#0f172a\">Save to TransCrypts</h3></div><p style=\"margin:6px 0 12px;color:#64748b\">Review the parsed fields, then click Save.</p>';var grid=document.createElement('div');grid.style.cssText='display:grid;grid-template-columns:120px 1fr;gap:6px 10px;font-size:13px;';function row(label,val){var k=document.createElement('div');k.style.cssText='color:#64748b;font-weight:600';k.textContent=label;var v=document.createElement('div');v.style.cssText='color:#0f172a;word-break:break-word';v.textContent=val||'(none found)';grid.appendChild(k);grid.appendChild(v);}row('Name',data.name);row('Email',data.email);row('Phone',data.phone);row('Position',data.position);row('Resume URL',data.resume_url);row('Skills',data.skills);modal.appendChild(grid);var btns=document.createElement('div');btns.style.cssText='display:flex;gap:8px;justify-content:flex-end;margin-top:16px;';var cancel=document.createElement('button');cancel.textContent='Cancel';cancel.style.cssText='padding:8px 14px;border:1px solid #cbd5e1;background:#fff;color:#0f172a;border-radius:6px;cursor:pointer;font-weight:600';cancel.onclick=function(){overlay.remove();};var save=document.createElement('button');save.textContent='Save';save.style.cssText='padding:8px 16px;border:0;background:#6DC49A;color:#fff;border-radius:6px;cursor:pointer;font-weight:700';save.onclick=function(){save.disabled=true;save.textContent='Saving...';fire(data);overlay.remove();};btns.appendChild(cancel);btns.appendChild(save);modal.appendChild(btns);overlay.appendChild(modal);overlay.addEventListener('click',function(e){if(e.target===overlay)overlay.remove();});document.body.appendChild(overlay);})();"""


def _build_indeed_bookmarklet(api_url, api_key):
    """Return a fully-encoded `javascript:...` href for the bookmarklet.

    api_key is embedded as a JS string literal — never logged. The caller
    feeds the result straight into a Jinja `{{ ... }}` slot inside an
    `<a href="..." />` tag.
    """
    from urllib.parse import quote as _q
    # Escape any backslash / single-quote in the key before inlining
    safe_key = (api_key or '').replace('\\', '\\\\').replace("'", "\\'")
    js = _INDEED_BOOKMARKLET_JS.replace('__API_URL__', api_url).replace('__API_KEY__', safe_key)
    # URL-encode aggressively so " < > # % { } | etc. all survive the href.
    return 'javascript:' + _q(js, safe='')


@app.route('/admin/indeed-bookmarklet')
@role_required(*CAN_USERS)
def admin_indeed_bookmarklet():
    """Admin page: shows the draggable bookmarklet + how-to + recent imports.
    The API key never appears in the page body as bare text — only as a
    JS string literal inside the bookmarklet href.
    """
    cfg = _indeed_bookmarklet_settings()

    # API base URL — prefer PUBLIC_BASE_URL when set so the bookmarklet
    # works even if the admin happens to view the page on a preview/staging
    # host. Fall back to whatever scheme/host the user used to reach us.
    base = cfg['public_base'] or request.url_root.rstrip('/')
    api_url = base + url_for('api_indeed_import')

    bookmarklet_href = ''
    if cfg['is_configured']:
        bookmarklet_href = _build_indeed_bookmarklet(api_url, cfg['api_key'])

    recent = []
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, name, email, applied_position, date_added "
                "FROM applicants "
                "WHERE COALESCE(source, '') = 'Indeed' "
                "ORDER BY date_added DESC, id DESC LIMIT 20"
            ).fetchall()
            recent = [dict(r) for r in rows]
    except Exception:
        recent = []

    return render_template(
        'indeed_bookmarklet.html',
        configured       = cfg['is_configured'],
        api_url          = api_url,
        bookmarklet_href = bookmarklet_href,
        recent           = recent,
    )


@app.route('/admin/indeed-bookmarklet/regenerate-key', methods=['POST'])
@role_required(*CAN_USERS)
def admin_indeed_bookmarklet_regenerate_key():
    """Placeholder — actual rotation happens on the host (Render env vars),
    not in code. We just remind the admin where to go."""
    flash('To rotate the key, change INDEED_BOOKMARKLET_KEY on Render '
          'and redeploy. The bookmarklet must then be re-dragged to your '
          'bookmarks bar so it picks up the new key.', 'success')
    return redirect(url_for('admin_indeed_bookmarklet'))


@app.route('/shutdown', methods=['POST'])
@role_required(*CAN_SHUTDOWN)
def shutdown():
    """Safely shut down the Flask server after confirming all data is committed.

    DESKTOP ONLY — disabled on cloud hosts because killing the gunicorn
    worker on Render would just cause a crash/restart cycle and exposes
    a DoS vector on misconfigured deploys.
    """
    if (os.environ.get('DATABASE_URL') or '').strip():
        return jsonify({
            'status': 'disabled',
            'message': 'Shutdown is disabled on cloud deployments. '
                       'Use the hosting provider\'s dashboard to stop/restart.'
        }), 400

    def _stop():
        # Brief pause so the response reaches the browser before the process exits
        import time
        time.sleep(0.8)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_stop, daemon=True).start()
    return jsonify({'status': 'ok', 'message': 'Server shutting down. All data saved.'})


# ─── Entry point ──────────────────────────────────────────────────────────────

def _auto_reanalyze_on_startup():
    """
    Silently re-analyze every saved resume file in the background
    each time the app starts. This ensures any improvements to the
    parsing logic are automatically applied to all existing records —
    no user action required.
    """
    import time
    time.sleep(2)          # let Flask finish starting before we hit the DB
    try:
        with get_db() as conn:
            all_applicants = conn.execute('SELECT * FROM applicants').fetchall()

        updated = 0
        for applicant in all_applicants:
            if not applicant['resume_filename']:
                continue
            parsed = _parse_saved_file(applicant['resume_filename'])
            if not parsed:
                continue

            def pick(pv, ev):
                v = str(pv).strip() if pv is not None else ''
                return v if v else (ev or '')

            # For the name field: NEVER overwrite a good existing name.
            # Only replace if the stored name is blank, is the placeholder,
            # or clearly fails our own name-validity check.
            existing_name = (applicant['name'] or '').strip()
            new_name      = (parsed.get('name') or '').strip()
            existing_name_bad = (
                not existing_name
                or existing_name == 'Please Edit Name'
                or not _looks_like_name(existing_name)
            )
            if existing_name_bad and new_name:
                name_to_save = new_name
            else:
                name_to_save = existing_name or new_name or 'Please Edit Name'

            with get_db() as conn:
                conn.execute('''
                    UPDATE applicants
                       SET name=?, email=?, phone=?, linkedin_url=?, github_url=?,
                           specialty=?, years_experience=?, highest_education=?, skills=?
                     WHERE id=?
                ''', (
                    name_to_save,
                    pick(parsed.get('email'),             applicant['email']),
                    pick(parsed.get('phone'),             applicant['phone']),
                    pick(parsed.get('linkedin_url'),      applicant['linkedin_url']),
                    pick(parsed.get('github_url'),        applicant['github_url']),
                    pick(parsed.get('specialty'),         applicant['specialty']),
                    _safe_int(parsed.get('years_experience'), _safe_int(applicant['years_experience'], 0)),
                    pick(parsed.get('highest_education'), applicant['highest_education']),
                    pick(parsed.get('skills'),            applicant['skills']),
                    applicant['id'],
                ))
                conn.commit()
            updated += 1

        if updated:
            print(f"   [Auto-Update] Re-analyzed {updated} resume(s) with latest parsing logic.")
    except Exception as e:
        print(f"   [Auto-Update] Warning: background re-analysis encountered an error: {e}")


def _backfill_file_hashes():
    """Compute and store SHA-256 hashes for any resume records that pre-date
    the duplicate-detection feature (file_hash IS NULL but file exists on disk).

    This runs once at startup in the background.  On subsequent startups it
    is essentially a no-op since all existing records already have a hash.
    Without this step, the duplicate check cannot detect files that were
    uploaded before the feature was added — their hash column is NULL and
    `WHERE file_hash = ?` never matches NULL, so duplicates slip through.
    """
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT id, resume_filename FROM applicants '
                'WHERE file_hash IS NULL AND resume_filename IS NOT NULL'
            ).fetchall()

        if not rows:
            return  # Nothing to do

        updated = 0
        for row in rows:
            file_data = _storage.read_file(row['resume_filename'])
            if not file_data:
                continue
            try:
                import hashlib as _hl, io as _io
                fhash = _hl.sha256(file_data).hexdigest()
                with get_db() as conn:
                    conn.execute('UPDATE applicants SET file_hash=? WHERE id=?',
                                 (fhash, row['id']))
                    conn.commit()
                updated += 1
            except Exception:
                pass   # Skip files we can't read — not fatal

        if updated:
            print(f'   [Hash Backfill] Computed missing hashes for '
                  f'{updated} existing record(s). Duplicate detection is now '
                  f'active for all records.')
    except Exception as e:
        print(f'   [Hash Backfill] Warning: {e}')


# ─── Module-level startup ────────────────────────────────────────────────────
# These run whether the app is launched directly (python app.py) OR imported
# by a WSGI server like gunicorn (the production case on Render/Railway/etc.).
# Two protection layers:
#  1. _STARTUP_DONE: prevents double-run within a single Python process
#  2. Postgres advisory lock: when running with multiple gunicorn workers,
#     only the worker that grabs the lock runs the heavy tasks
#     (re-analysis & hash backfill). Without this, every worker would
#     re-download every resume on every cold start.
_STARTUP_DONE = False

def _run_startup_tasks():
    global _STARTUP_DONE
    if _STARTUP_DONE:
        return
    _STARTUP_DONE = True
    init_db()
    create_default_admin()

    # ── Heavy tasks: only one worker should run these ────────────────────────
    def _exclusive_heavy_tasks():
        # Try to grab a Postgres advisory lock; only the winning worker runs.
        # SQLite (local dev) doesn't support advisory locks, so fall back to
        # always-run there — single process anyway.
        try:
            if _db.dialect() == 'postgres':
                with _db.get_db() as _conn:
                    cur = _conn.execute("SELECT pg_try_advisory_lock(8174_3917_2024)")
                    got = cur.fetchone()
                    got = got[0] if got else False
                if not got:
                    return       # another worker has the lock, skip
        except Exception:
            pass                  # if locking fails, run anyway — at-most-twice is OK
        try:
            _auto_reanalyze_on_startup()
        except Exception as e:
            print(f'[startup] re-analyze failed: {e}')
        try:
            _backfill_file_hashes()
        except Exception as e:
            print(f'[startup] hash backfill failed: {e}')

    threading.Thread(target=_exclusive_heavy_tasks, daemon=True).start()

_run_startup_tasks()


if __name__ == '__main__':
    # Local dev: read PORT from env (Render sets it; locally defaults to 5000)
    port = int(os.environ.get('PORT', 5000))
    print()
    print("=" * 55)
    print("   RESUME DATABASE — Starting up...")
    print(f"   Open your browser and visit:")
    print(f"   --> http://localhost:{port}")
    print("=" * 55)
    print()
    app.run(debug=False, host='0.0.0.0', port=port)
