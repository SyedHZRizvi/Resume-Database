"""
Resume Database Application
Run this file with Python to start the app: python app.py
Then open your browser at: http://localhost:5000
"""

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, session
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

# ── Anthropic API key resolution ───────────────────────────────────────────
# Priority 1: config.py (user-supplied key)
# Priority 2: ANTHROPIC_API_KEY environment variable
# Priority 3: Claude Code managed auth (ANTHROPIC_BASE_URL set by host, no key needed)
try:
    from config import ANTHROPIC_API_KEY as _cfg_key
    ANTHROPIC_API_KEY = _cfg_key if _cfg_key != 'your-api-key-here' else ''
except ImportError:
    ANTHROPIC_API_KEY = ''

# ── Login on/off switch + security settings (set in config.py) ───────────
try:
    from config import REQUIRE_LOGIN as _require_login
    REQUIRE_LOGIN = bool(_require_login)
except ImportError:
    REQUIRE_LOGIN = False

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
OFFICE_ADDRESS       = _cfg('OFFICE_ADDRESS',        '1 Front Street, Toronto, ON M5J 2X5')
OFFICE_FLOOR_ROOM    = _cfg('OFFICE_FLOOR_ROOM',     '')
OFFICE_CONTACT_NAME  = _cfg('OFFICE_CONTACT_NAME',  'Reception')
OFFICE_CONTACT_PHONE = _cfg('OFFICE_CONTACT_PHONE', '')
# When Claude Code manages auth, the base URL is set and the key may be empty
CLAUDE_CODE_MANAGED = bool(os.environ.get('CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST', ''))
from datetime import datetime, timedelta

app = Flask(__name__)

# ── Persistent secret key ─────────────────────────────────────────────────
# Lookup order:
#   1. FLASK_SECRET_KEY environment variable  (production — Render/Railway)
#   2. .secret_key file in the app folder      (local dev)
#   3. Auto-generate and save to file          (first run, local)
# Setting FLASK_SECRET_KEY in production keeps logins alive across redeploys.
_env_secret = os.environ.get('FLASK_SECRET_KEY', '').strip()
if _env_secret:
    app.secret_key = _env_secret
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
            # Read-only filesystem (e.g. some hosted environments) — that's OK,
            # we just won't persist the key. Sessions reset on redeploy until
            # FLASK_SECRET_KEY env var is set.
            pass
        app.secret_key = _sk

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif'}
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resumes.db')

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
    Every important action (add/edit/delete/login/logout) calls this function.
    It records who did it, when, and what. Because it's a separate table that
    only ever gets rows appended (never deleted), it is tamper-evident —
    you always know what happened even if resume data is changed later.

    In local mode (REQUIRE_LOGIN=False) we skip logging since there are no
    named users — everything is done by the single operator.
    """
    if not REQUIRE_LOGIN:
        return
    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO audit_log (username, user_role, action, target, details) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    session.get('username', 'system'),
                    session.get('user_role', ''),
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
        idle_minutes = (datetime.now() - datetime.fromisoformat(last)).seconds / 60
        if idle_minutes > SESSION_TIMEOUT_MINUTES:
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
                session.permanent = True
                session['user_id']          = user['id']
                session['username']         = user['username']
                session['full_name']        = user['full_name'] or user['username']
                session['user_role']        = user['role']
                session['last_activity']    = datetime.now().isoformat()
                session['must_change_pw']   = bool(user['must_change_password'])
                log_action('LOGIN', user['username'],
                           f'Role: {ROLES.get(user["role"], user["role"])}')
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
    role      = request.form.get('role', 'viewer')

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('manage_users'))
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(f'Password must be at least {PASSWORD_MIN_LENGTH} characters.', 'error')
        return redirect(url_for('manage_users'))
    if role not in ROLES:
        role = 'viewer'

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

    with get_db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM applicants').fetchone()[0]

        # Unique specialty values for the dropdown
        specialties = [
            row[0] for row in conn.execute(
                "SELECT DISTINCT specialty FROM applicants WHERE specialty != '' ORDER BY specialty"
            ).fetchall()
        ]

        if conditions:
            sql = ('SELECT * FROM applicants WHERE '
                   + ' AND '.join(conditions)
                   + ' ORDER BY name COLLATE NOCASE ASC')
            applicants = conn.execute(sql, params).fetchall()
        else:
            applicants = conn.execute(
                'SELECT * FROM applicants ORDER BY name COLLATE NOCASE ASC'
            ).fetchall()

    any_filter = bool(q or f_specialty or f_skills or f_education
                      or f_exp_min or f_exp_max or f_has_file
                      or f_linkedin or f_github or f_status)

    return render_template(
        'index.html',
        applicants=applicants,
        total=total,
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
        any_filter=any_filter,
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

            # Compute hash — check it is not already on a DIFFERENT record
            new_hash = compute_file_hash(file)
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

            # Delete old file
            if existing['resume_filename']:
                _storage.delete_file(existing['resume_filename'])

            # Save new file via storage abstraction (Supabase or local)
            new_filename = make_unique_filename(file.filename)
            _file_bytes = file.read()
            _storage.save_file(new_filename, _file_bytes,
                               file.mimetype or 'application/octet-stream')

            # Re-parse new file — use parsed values where available, fall back
            # to whatever is already stored so we never blank-out a field
            parsed = _parse_saved_file(new_filename) or {}

            def _pick(pv, ev):
                v = str(pv).strip() if pv is not None else ''
                return v if v else (ev or '')

            with get_db() as conn:
                conn.execute('''
                    UPDATE applicants
                       SET resume_filename=?, file_hash=?,
                           name=?, email=?, phone=?,
                           specialty=?, years_experience=?,
                           highest_education=?, skills=?
                     WHERE id=?
                ''', (
                    new_filename, new_hash,
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
        file = request.files.get('resume_file')
        if file and file.filename:
            if allowed_file(file.filename):
                # ── Server-side hash duplicate check (always blocks — no override) ─
                file_hash = compute_file_hash(file)
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

                resume_filename = make_unique_filename(file.filename)
                _storage.save_file(resume_filename, file.read(),
                                   file.mimetype or 'application/octet-stream')
            else:
                flash('Only PDF, DOC, and DOCX files are allowed.', 'error')
                return render_template('add_resume.html', form=request.form)

        with get_db() as conn:
            conn.execute('''
                INSERT INTO applicants
                    (name, email, phone, linkedin_url, github_url,
                     specialty, years_experience, highest_education,
                     skills, resume_filename, notes, file_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, email, phone, linkedin_url, github_url,
                  specialty, years_experience, highest_education,
                  skills, resume_filename, notes, file_hash))
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

            # ── Compute hash in memory BEFORE saving ────────────────────────
            try:
                fhash = compute_file_hash(file)
            except Exception as e:
                failed.append({'filename': file.filename, 'reason': f'Could not hash file: {e}'})
                continue

            # ── Block if exact duplicate already exists ───────────────────────
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

            # Save the file via storage abstraction (works with Supabase or local)
            filename = make_unique_filename(file.filename)
            try:
                file.seek(0)
                _storage.save_file(filename, file.read(),
                                   file.mimetype or 'application/octet-stream')
            except Exception as e:
                failed.append({'filename': file.filename, 'reason': f'Could not save: {e}'})
                continue

            # Auto-parse (same logic used on startup)
            parsed = _parse_saved_file(filename) or {}

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

            try:
                with get_db() as conn:
                    conn.execute('''
                        INSERT INTO applicants
                            (name, email, phone, linkedin_url, github_url,
                             specialty, years_experience,
                             highest_education, skills, resume_filename, file_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                          fhash))
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
        file = request.files.get('resume_file')
        if file and file.filename:
            if allowed_file(file.filename):
                # ── Hash check: block if replacing with an exact duplicate ───
                new_file_hash = compute_file_hash(file)
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

                # Delete old file first
                if resume_filename:
                    _storage.delete_file(resume_filename)
                resume_filename = make_unique_filename(file.filename)
                file.seek(0)
                _storage.save_file(resume_filename, file.read(),
                                   file.mimetype or 'application/octet-stream')
            else:
                flash('Only PDF, DOC, and DOCX files are allowed.', 'error')
                return render_template('edit_resume.html', applicant=applicant)

        # Handle file removal
        if request.form.get('remove_file') == '1':
            if resume_filename:
                _storage.delete_file(resume_filename)
            resume_filename  = None
            new_file_hash    = None

        with get_db() as conn:
            conn.execute('''
                UPDATE applicants
                SET name=?, email=?, phone=?, linkedin_url=?, github_url=?,
                    specialty=?, years_experience=?, highest_education=?,
                    skills=?, resume_filename=?, notes=?, file_hash=?
                WHERE id=?
            ''', (name, email, phone, linkedin_url, github_url,
                  specialty, years_experience, highest_education,
                  skills, resume_filename, notes, new_file_hash, applicant_id))
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
    """Read email credentials fresh from config.py each time — no restart needed."""
    try:
        import importlib, config as _c
        importlib.reload(_c)
        return {
            'server':   getattr(_c, 'MAIL_SERVER',   '127.0.0.1'),
            'port':     int(getattr(_c, 'MAIL_PORT', 1025)),
            'username': getattr(_c, 'MAIL_USERNAME', ''),
            'password': getattr(_c, 'MAIL_PASSWORD', ''),
            'from':     getattr(_c, 'MAIL_FROM',     ''),
        }
    except Exception:
        return {'server': MAIL_SERVER, 'port': MAIL_PORT,
                'username': MAIL_USERNAME, 'password': MAIL_PASSWORD,
                'from': MAIL_FROM}


def _email_enabled():
    creds = _email_credentials()
    return bool(creds['username'] and creds['password'])


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
    if not (creds['username'] and creds['password']):
        return False, ('Email not configured. Set MAIL_USERNAME, MAIL_PASSWORD, '
                       'MAIL_SERVER (e.g. smtp.gmail.com), MAIL_PORT (587), and '
                       'MAIL_FROM as environment variables on the host.')

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
        # Proton Mail Bridge (127.0.0.1) uses plain SMTP locally — no TLS needed.
        # All other servers (Gmail, Outlook, etc.) use STARTTLS.
        if creds['server'] == '127.0.0.1':
            with smtplib.SMTP(creds['server'], creds['port'], timeout=15) as s:
                s.ehlo()
                s.login(creds['username'], creds['password'])
                s.sendmail(creds['username'], to_addr, msg.as_bytes())
        else:
            with smtplib.SMTP(creds['server'], creds['port'], timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.login(creds['username'], creds['password'])
                s.sendmail(creds['username'], to_addr, msg.as_bytes())
        return True, ''
    except Exception as exc:
        return False, str(exc)


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

    # Real location: office address for in-person, meeting link for virtual.
    # contact_person is the reception greeter (NOT the location itself).
    if interview_type == 'In-Person':
        loc_str = OFFICE_ADDRESS
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

    position     = interview_position or (applicant['specialty'] or 'the open position').strip()
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
        email_results.append(
            f"Candidate ({applicant['email']}): {'sent ✓' if ok else f'FAILED — {err}'}")
    elif send_candidate and not applicant['email']:
        email_results.append('Candidate email not sent — no email address on record.')

    # ── Email to each interviewer ─────────────────────────────────────────────
    if send_interviewer:
        for iv_name, iv_desig, iv_email in interviewers:
            if not iv_email:
                email_results.append(
                    f'Interviewer {iv_name}: no email address — notification skipped.')
                continue

            html = _interviewer_email_html(
                applicant, position, interview_date, interview_time,
                interview_type, iv_name,
                contact_person, meeting_link)

            attachments = []
            # Attach the resume file (read via storage abstraction so it works
            # whether the file lives on local disk or in Supabase Storage)
            if applicant['resume_filename']:
                resume_data = _storage.read_file(applicant['resume_filename'])
                if resume_data:
                    ext = applicant['resume_filename'].rsplit('.', 1)[-1].lower()
                    mime_map = {
                        'pdf':  'application/pdf',
                        'docx': 'application/vnd.openxmlformats-officedocument'
                                '.wordprocessingml.document',
                        'doc':  'application/msword'
                    }
                    attachments.append((
                        f"{applicant['name']} — Resume.{ext}",
                        resume_data,
                        mime_map.get(ext, 'application/octet-stream')
                    ))

            # Attach ICS calendar invite personalised to this interviewer
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
            email_results.append(
                f"Interviewer {iv_name} ({iv_email}): "
                f"{'sent ✓' if ok else f'FAILED — {err}'}")

    iv_names_str = ', '.join(iv[0] for iv in interviewers)
    log_action('INTERVIEW ADDED', applicant['name'],
               f'Interviewers: {iv_names_str} — {interview_type} — Outcome: {outcome}')

    if email_results:
        for msg in email_results:
            flash(f'Email — {msg}', 'success' if '✓' in msg else 'warning')
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
    """Open config.py in Notepad so the user can paste their API key."""
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

    # ── Validate required fields ─────────────────────────────────────────────
    name  = (request.form.get('name')  or '').strip()
    email = (request.form.get('email') or '').strip()
    if not name or not email:
        return jsonify({'ok': False,
                        'message': 'Name and email are required.'}), 400

    file = request.files.get('resume')
    if not file or not file.filename:
        return jsonify({'ok': False,
                        'message': 'Resume file is required.'}), 400

    if not allowed_file(file.filename):
        return jsonify({'ok': False,
                        'message': 'Resume must be a PDF or DOCX file.'}), 400

    # Optional fields
    phone        = (request.form.get('phone')        or '').strip()
    position     = (request.form.get('position')     or '').strip()
    cover_letter = (request.form.get('cover_letter') or '').strip()
    linkedin_url = (request.form.get('linkedin_url') or '').strip()
    github_url   = (request.form.get('github_url')   or '').strip()

    # ── Save the file with a unique filename ────────────────────────────────
    raw = file.read()
    file.seek(0)
    file_hash = hashlib.md5(raw).hexdigest()
    safe_name = secure_filename(file.filename)
    base, ext = os.path.splitext(safe_name)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_name = f"CareerApp_{base[:40]}_{timestamp}{ext}"
    _storage.save_file(final_name, raw,
                       file.mimetype or 'application/octet-stream')

    # ── Try to parse the resume in the background to enrich the record ──────
    parsed = {}
    try:
        text = _extract_text_from_file(raw, final_name.lower())
        if text and text.strip():
            parsed = _smart_parse(text) or {}
    except Exception:
        parsed = {}

    # Position → display label
    position_label   = position or 'Open Application — Suitable Position'
    source_label     = 'Career Website' + (f' — {position}' if position else ' — Open Application')

    # ── Insert into DB ───────────────────────────────────────────────────────
    with get_db() as conn:
        # De-dupe: if the same file_hash already exists, return that record
        existing = conn.execute(
            'SELECT id FROM applicants WHERE file_hash=?', (file_hash,)
        ).fetchone()
        if existing:
            return jsonify({
                'ok': True,
                'applicant_id': existing['id'],
                'duplicate': True,
                'message': ("We already have your resume on file — we'll review "
                            "it for this position. Thank you!"),
            })

        cur = conn.execute(
            '''INSERT INTO applicants
               (name, email, phone, specialty, years_experience, highest_education,
                skills, resume_filename, notes, date_added, hiring_status,
                linkedin_url, github_url, file_hash, source, applied_position,
                cover_letter)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (
                name, email, phone or parsed.get('phone', ''),
                parsed.get('specialty', position or ''),
                _safe_int(parsed.get('years_experience'), 0),
                parsed.get('highest_education', ''),
                parsed.get('skills', ''),
                final_name,
                parsed.get('notes', ''),
                datetime.now().isoformat(timespec='seconds'),
                'Under Review',
                linkedin_url or parsed.get('linkedin_url', ''),
                github_url   or parsed.get('github_url',   ''),
                file_hash,
                source_label,
                position_label,
                cover_letter,
            )
        )
        applicant_id = cur.lastrowid
        conn.commit()

    log_action('CAREER APPLICATION', name,
               f'Position: {position_label} | IP: {client_ip}')

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


@app.route('/api-status', methods=['GET'])
@role_required(*CAN_ADD)
def api_status():
    """Check whether the AI API key is configured."""
    configured = bool(ANTHROPIC_API_KEY and ANTHROPIC_API_KEY != 'your-api-key-here')
    return jsonify({'configured': configured})


@app.route('/shutdown', methods=['POST'])
@role_required(*CAN_SHUTDOWN)
def shutdown():
    """Safely shut down the Flask server after confirming all data is committed."""
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
# The double-run guard via _STARTUP_DONE prevents repeated init in dev reload.
_STARTUP_DONE = False

def _run_startup_tasks():
    global _STARTUP_DONE
    if _STARTUP_DONE:
        return
    _STARTUP_DONE = True
    init_db()
    create_default_admin()
    # Background re-analysis & hash backfill — daemons, won't block shutdown
    threading.Thread(target=_auto_reanalyze_on_startup, daemon=True).start()
    threading.Thread(target=_backfill_file_hashes,        daemon=True).start()

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
