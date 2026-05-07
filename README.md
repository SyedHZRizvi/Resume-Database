# TransCrypts Resume Database

Internal HR application for managing applicant resumes, scheduling interviews,
and tracking hiring decisions end-to-end.

## Features

- Resume upload, storage, and search (PDF, DOCX, image-OCR via Claude)
- Auto-parsing of candidate fields from raw resume text
- Staff directory with role-based access control
- Interview scheduling with multi-interviewer support
- Automated email notifications to candidates and interviewers
- Calendar invites (.ics) with proper timezone handling
- Auto-generated Jitsi Meet rooms for video interviews
- Audit logging for every important action
- Hiring status workflow (Under Review → Interview Scheduled → Hired/Rejected)

## Tech Stack

- **Backend**: Python 3 + Flask
- **Database**: SQLite (single file, easy to back up)
- **AI**: Anthropic Claude (resume parsing, optional)
- **Email**: SMTP via Proton Mail Bridge / Gmail / Outlook
- **Video**: Jitsi Meet (no API key required)

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/SyedHZRizvi/Resume-Database.git
cd Resume-Database

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up your config (copy template, then edit)
copy config.example.py config.py        # Windows
# cp   config.example.py config.py      # Mac/Linux

# 4. Open config.py and fill in:
#    - ANTHROPIC_API_KEY   (optional — only for image resumes)
#    - MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM
#    - COMPANY_NAME, OFFICE_ADDRESS, etc.

# 5. Run the app
python app.py
# Open http://localhost:5000
```

## Configuration

All settings live in `config.py` (which is **NOT** committed). A safe template
with placeholders is provided as `config.example.py`. Copy it to `config.py`
and fill in real values.

| Setting | Purpose |
|---|---|
| `REQUIRE_LOGIN` | `False` for local dev, `True` on shared servers |
| `SESSION_TIMEOUT_MINUTES` | Auto sign-out after inactivity |
| `ANTHROPIC_API_KEY` | Claude API key for parsing scanned image resumes |
| `MAIL_*` | SMTP server, port, credentials, From address |
| `COMPANY_NAME`, `OFFICE_*` | Branding for email invitations |

## Project Structure

```
.
├── app.py                  Main Flask application
├── config.example.py       Configuration template (safe to commit)
├── config.py               Real configuration with secrets (NOT committed)
├── start_desktop.py        Desktop launcher (opens in dedicated browser window)
├── launcher.py             Windows shortcut launcher (no console window)
├── requirements.txt        Python dependencies
├── static/
│   ├── css/style.css       App stylesheet
│   └── img/                Logo and brand assets
├── templates/              Jinja2 HTML templates (all pages)
├── uploads/                Uploaded resume files (NOT committed — PII)
└── resumes.db              SQLite database (NOT committed — PII)
```

## Security Notes

- `config.py`, `*.db`, `uploads/`, and `*.log` are all gitignored — they
  contain personal data and credentials.
- Passwords are hashed with `werkzeug.security` (PBKDF2 by default).
- Login attempts are rate-limited (`MAX_LOGIN_ATTEMPTS`).
- Sessions auto-expire after `SESSION_TIMEOUT_MINUTES` of inactivity.

## License

Internal — TransCrypts proprietary.
