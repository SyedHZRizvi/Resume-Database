# ═══════════════════════════════════════════════════════════════════════════════
#  TransCrypts Resume Database — Configuration TEMPLATE
# ═══════════════════════════════════════════════════════════════════════════════
#  ┌─────────────────────────────────────────────────────────────────────────┐
#  │  HOW TO USE                                                             │
#  │  1. Copy this file to "config.py"                                       │
#  │       Windows : copy config.example.py config.py                        │
#  │       Mac/Lnx : cp   config.example.py config.py                        │
#  │  2. Fill in the values below (API key, email password, etc.)            │
#  │  3. Save it.  config.py is in .gitignore so it never gets pushed.       │
#  └─────────────────────────────────────────────────────────────────────────┘


# ─────────────────────────────────────────────────────────────────────────────
#  LOGIN / AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────
#  False → No login screen. Opens straight into the database.
#          Use this on your local development laptop.
#
#  True  → Everyone must sign in. Roles and permissions are enforced.
#          Use this when running on the company central server.
# ─────────────────────────────────────────────────────────────────────────────

REQUIRE_LOGIN = False        # ← Change to True when moving to central server


# ─────────────────────────────────────────────────────────────────────────────
#  SESSION SECURITY
# ─────────────────────────────────────────────────────────────────────────────

SESSION_TIMEOUT_MINUTES = 30
MAX_LOGIN_ATTEMPTS      = 5
PASSWORD_MIN_LENGTH     = 8


# ─────────────────────────────────────────────────────────────────────────────
#  AI AUTO-FILL (OPTIONAL — only needed for scanned image resumes)
# ─────────────────────────────────────────────────────────────────────────────
#  Get a free key at  https://console.anthropic.com/  →  API Keys → Create Key
#  Paste below (starts with: sk-ant-...).  Leave the placeholder if not used.

ANTHROPIC_API_KEY = "your-api-key-here"


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL / INTERVIEW NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────
#  Leave MAIL_USERNAME blank to disable email entirely.
#
#  Proton Mail (via Proton Bridge desktop app)  ────────────────────────────
#    Download:  https://proton.me/mail/bridge   (paid Proton plan required)
#    Bridge → click your account → "SMTP Configuration" → copy port & password
#
#  Gmail   ──────────────────────────────────────────────────────────────────
#    MAIL_SERVER='smtp.gmail.com', MAIL_PORT=587, password = App Password
#    https://myaccount.google.com/apppasswords
#
#  Outlook / M365 ───────────────────────────────────────────────────────────
#    MAIL_SERVER='smtp.office365.com', MAIL_PORT=587

MAIL_SERVER   = '127.0.0.1'                        # Proton Bridge runs locally
MAIL_PORT     = 1025                                # confirm in Bridge app
MAIL_USERNAME = 'hr@your-company.com'
MAIL_PASSWORD = 'your-mail-password-or-bridge-password'
MAIL_FROM     = 'Your Company HR <hr@your-company.com>'


# ─────────────────────────────────────────────────────────────────────────────
#  OFFICE / COMPANY INFO  (appears in interview invitation emails)
# ─────────────────────────────────────────────────────────────────────────────

COMPANY_NAME         = 'Your Company'
OFFICE_ADDRESS       = '123 Main Street, City, Province/State, Postal Code'
OFFICE_FLOOR_ROOM    = 'Office 100, 1st Floor'
OFFICE_CONTACT_NAME  = 'Reception Desk'
OFFICE_CONTACT_PHONE = ''                           # optional, e.g. "(416) 555-0100"
