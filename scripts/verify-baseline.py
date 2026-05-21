#!/usr/bin/env python3
"""
verify-baseline.py — assert today's invariants from CLAUDE.md hold.

Run from the repo root:
    python3 scripts/verify-baseline.py

Exit code:
    0  → every invariant holds. Safe to push.
    1  → something has drifted from the locked baseline. Output explains what.

This script reads source files as text (no runtime imports of app.py) so it
works on any machine with just Python 3, no project deps required. It is
intentionally additive: when CLAUDE.md adds a new rule, add a new check
function below and call it from main().
"""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path

# ── Locate repo root from the script's own location ──────────────────────────
ROOT = Path(__file__).resolve().parent.parent
APP_PY     = ROOT / 'app.py'
DB_PY      = ROOT / 'db.py'
CSS        = ROOT / 'static' / 'css' / 'style.css'
TEMPLATES  = ROOT / 'templates'
CLAUDE_MD  = ROOT / 'CLAUDE.md'
REQS       = ROOT / 'requirements.txt'

# ── Output helpers ───────────────────────────────────────────────────────────
RESET = '\033[0m'
GREEN = '\033[32m'
RED   = '\033[31m'
DIM   = '\033[2m'
BOLD  = '\033[1m'

_failures: list[str] = []


def section(title: str) -> None:
    print(f'\n{BOLD}── {title} ──{RESET}')


def ok(msg: str) -> None:
    print(f'  {GREEN}✓{RESET} {msg}')


def fail(msg: str) -> None:
    print(f'  {RED}✗{RESET} {msg}')
    _failures.append(msg)


def must_match(haystack: str, needle: str, what: str) -> None:
    if needle in haystack:
        ok(what)
    else:
        fail(f'{what} — missing: {needle!r}')


def must_regex(haystack: str, pattern: str, what: str, flags: int = 0) -> None:
    if re.search(pattern, haystack, flags):
        ok(what)
    else:
        fail(f'{what} — no match for /{pattern}/')


def must_not_match(haystack: str, needle: str, what: str) -> None:
    if needle not in haystack:
        ok(what)
    else:
        fail(f'{what} — unexpectedly contains: {needle!r}')


def read(p: Path) -> str:
    if not p.exists():
        fail(f'Missing file: {p.relative_to(ROOT)}')
        return ''
    return p.read_text(encoding='utf-8')


# ─────────────────────────────────────────────────────────────────────────────
# §1  Security middleware is wired up
# ─────────────────────────────────────────────────────────────────────────────
def check_middleware(app_src: str) -> None:
    section('Security middleware')
    must_match(app_src, 'from werkzeug.middleware.proxy_fix import ProxyFix',
               'ProxyFix imported')
    must_match(app_src, 'ProxyFix(app.wsgi_app',
               'ProxyFix wraps app.wsgi_app (production only)')
    must_match(app_src, 'from flask_wtf.csrf import CSRFProtect',
               'flask-wtf CSRFProtect imported')
    must_match(app_src, 'csrf = CSRFProtect(app)',
               'CSRFProtect initialised on app')
    must_match(app_src, 'from flask_limiter import Limiter',
               'flask-limiter imported')
    must_match(app_src, 'limiter = Limiter(',
               'Limiter initialised')


# ─────────────────────────────────────────────────────────────────────────────
# §2  Session cookies and security headers
# ─────────────────────────────────────────────────────────────────────────────
def check_session_cookies(app_src: str) -> None:
    section('Session cookie flags')
    must_match(app_src, 'SESSION_COOKIE_HTTPONLY=True',
               'SESSION_COOKIE_HTTPONLY = True')
    must_match(app_src, "SESSION_COOKIE_SAMESITE='Lax'",
               "SESSION_COOKIE_SAMESITE = 'Lax'")
    must_match(app_src, 'SESSION_COOKIE_SECURE=_IS_PROD',
               'SESSION_COOKIE_SECURE bound to _IS_PROD')


def check_security_headers(app_src: str) -> None:
    section('Security headers (after_request hook)')
    must_match(app_src, '_add_security_and_cors_headers',
               'after_request hook name unchanged')
    must_match(app_src, 'Strict-Transport-Security',
               'HSTS header set')
    must_match(app_src, "'X-Frame-Options',        'DENY'",
               'X-Frame-Options = DENY')
    must_match(app_src, "'X-Content-Type-Options', 'nosniff'",
               'X-Content-Type-Options = nosniff')
    must_match(app_src, "'Referrer-Policy',        'same-origin'",
               'Referrer-Policy = same-origin')
    must_match(app_src, "'Permissions-Policy'",
               'Permissions-Policy header present')


# ─────────────────────────────────────────────────────────────────────────────
# §3  CORS is scoped, not global
# ─────────────────────────────────────────────────────────────────────────────
def check_cors_scope(app_src: str) -> None:
    section('CORS scope (must not be global)')
    must_match(app_src, "request.path.startswith('/api/careers/')",
               'CORS allowed on /api/careers/')
    must_match(app_src, "request.path.startswith('/api/indeed/')",
               'CORS allowed on /api/indeed/')
    # Make sure the OLD permissive wildcard pattern (Allow-Origin '*' unconditionally)
    # isn't outside that guarded branch.
    pre_guard = app_src.split("if (request.path.startswith('/api/careers/')")[0]
    if "'Access-Control-Allow-Origin']  = '*'" in pre_guard:
        fail('CORS Allow-Origin: * is set outside the /api/careers|indeed guard')
    else:
        ok('No unguarded Allow-Origin: * wildcard')


# ─────────────────────────────────────────────────────────────────────────────
# §4  Login route hardening
# ─────────────────────────────────────────────────────────────────────────────
def check_login(app_src: str) -> None:
    section('Login route hardening')
    must_match(app_src,
               "@limiter.limit('10/minute;100/hour', methods=['POST'])",
               'Rate limit decorator on /login')
    must_match(app_src, '_GENERIC_LOGIN_ERROR',
               'Generic login error constant defined')
    # The old enumeration messages must NOT be reintroduced
    must_not_match(app_src, 'attempt(s) remaining',
                   'No "N attempts remaining" message (would enumerate users)')
    must_not_match(app_src, 'Account is locked after too many failed attempts',
                   'No pre-auth lockout disclosure')
    must_match(app_src, '_is_safe_next_url',
               'Open-redirect guard _is_safe_next_url() present')


# ─────────────────────────────────────────────────────────────────────────────
# §5  Default admin guard
# ─────────────────────────────────────────────────────────────────────────────
def check_default_admin(app_src: str) -> None:
    section('Default admin / first-run guard')
    must_match(app_src, "os.environ.get('ALLOW_DEFAULT_ADMIN'",
               'ALLOW_DEFAULT_ADMIN env var gate present')
    must_match(app_src, 'must_change_password=1',
               'Default admin is created with must_change_password=1')


# ─────────────────────────────────────────────────────────────────────────────
# §6  Database init: RLS + audit-log trigger
# ─────────────────────────────────────────────────────────────────────────────
def check_db_init(app_src: str) -> None:
    section('Database init — RLS + audit-log trigger')
    rls_tables = ('applicants', 'users', 'audit_log',
                  'interviews', 'staff', 'indeed_poll_status')
    rls_tuple_re = re.search(r"_rls_tables\s*=\s*\(([^)]+)\)", app_src)
    if not rls_tuple_re:
        fail('_rls_tables tuple missing from init_db()')
    else:
        listed = rls_tuple_re.group(1)
        for t in rls_tables:
            if f"'{t}'" in listed:
                ok(f'RLS enabled on `{t}`')
            else:
                fail(f'RLS missing for `{t}`')
    must_match(app_src, 'ENABLE ROW LEVEL SECURITY',
               'ENABLE ROW LEVEL SECURITY ALTER statement present')
    must_match(app_src, 'reject_audit_log_change',
               'Audit-log trigger function defined')
    must_match(app_src, 'BEFORE UPDATE OR DELETE ON audit_log',
               'Audit-log trigger fires on UPDATE/DELETE')
    must_match(app_src, '_db.dialect()',
               'dialect() used (NOT db_dialect() — that name does not exist)')


# ─────────────────────────────────────────────────────────────────────────────
# §7  Public-API CSRF exemptions
# ─────────────────────────────────────────────────────────────────────────────
def check_csrf_exempts(app_src: str) -> None:
    section('CSRF exemptions for public API-key endpoints')
    must_regex(app_src,
               r"@app\.route\('/api/careers/apply'.*?\)\s*\n@csrf\.exempt",
               '/api/careers/apply is @csrf.exempt')
    must_regex(app_src,
               r"@app\.route\('/api/indeed/import'.*?\)\s*\n@csrf\.exempt",
               '/api/indeed/import is @csrf.exempt')


# ─────────────────────────────────────────────────────────────────────────────
# §8  Resume download serves as attachment
# ─────────────────────────────────────────────────────────────────────────────
def check_resume_download(app_src: str) -> None:
    section('Resume download served as attachment')
    must_match(app_src, 'as_attachment=True',
               'send_from_directory uses as_attachment=True')
    must_match(app_src, 'download=1',
               'Supabase signed URL gets download=1 query')


# ─────────────────────────────────────────────────────────────────────────────
# §9  Permission groups still defined
# ─────────────────────────────────────────────────────────────────────────────
def check_permissions(app_src: str) -> None:
    section('Permission tuples')
    for name in ('CAN_VIEW', 'CAN_ADD', 'CAN_EDIT', 'CAN_NOTES', 'CAN_DELETE',
                 'CAN_DOWNLOAD', 'CAN_AUDIT', 'CAN_STAFF', 'CAN_USERS',
                 'CAN_SHUTDOWN'):
        must_regex(app_src, rf'^{name}\s*=\s*\(', f'{name} tuple defined',
                   flags=re.MULTILINE)


# ─────────────────────────────────────────────────────────────────────────────
# §10  Staff directory new columns + chip UI
# ─────────────────────────────────────────────────────────────────────────────
def check_staff_columns(app_src: str) -> None:
    section('Staff directory schema additions')
    must_match(app_src, "'company_property'",
               'company_property column migration in init_db')
    must_match(app_src, "'notes',            'TEXT'",
               'notes column migration in init_db')
    must_match(app_src, '_clean_property_list',
               'Property normaliser _clean_property_list() defined')


# ─────────────────────────────────────────────────────────────────────────────
# §11  CSS — required design-token classes
# ─────────────────────────────────────────────────────────────────────────────
def check_css(css_src: str) -> None:
    section('CSS design tokens')
    for cls in ('.tc-nav-icon', '.tc-tooltip', '.tc-chip',
                '.tc-property-badge', '.tc-property-chips',
                '.tc-notes-cell'):
        must_match(css_src, cls, f'{cls} class defined')


# ─────────────────────────────────────────────────────────────────────────────
# §12  Template invariants — navbar + CSRF + role badge gone
# ─────────────────────────────────────────────────────────────────────────────
def check_templates() -> None:
    section('Templates — navbar pattern, CSRF, no role badge')
    if not TEMPLATES.exists():
        fail('templates/ directory missing')
        return

    # The ROLE_LABEL badge in the navbar is deliberately removed; only the
    # change_password page body still shows it as plain text — that one
    # body usage is allowed.
    forbidden_badge = '<span class="badge bg-warning text-dark'
    found_in_navbar = []
    for tpl in sorted(TEMPLATES.glob('*.html')):
        src = tpl.read_text(encoding='utf-8')
        # POST form must carry csrf_token
        for m in re.finditer(
            r'<form\b[^>]*\bmethod\s*=\s*["\']?[Pp][Oo][Ss][Tt]["\']?[^>]*>',
            src,
        ):
            # Check the next ~400 chars for csrf_token hidden input
            tail = src[m.end():m.end() + 600]
            if 'csrf_token' not in tail:
                fail(f'{tpl.name}: POST form without csrf_token hidden input')
                break
        # If the file has a navbar, it must use tc-nav-icon (icon-only pattern)
        if '<nav class="navbar' in src:
            if 'tc-nav-icon' not in src:
                fail(f'{tpl.name}: navbar present but tc-nav-icon class missing')
            if '/*tooltip-init*/' not in src:
                fail(f'{tpl.name}: tooltip-init script missing')
        # No ROLE_LABEL badge inside the <nav> block
        nav_block = re.search(r'<nav\b[^>]*>.*?</nav>', src, re.DOTALL)
        if nav_block and forbidden_badge in nav_block.group(0):
            if 'ROLE_LABEL' in nav_block.group(0):
                found_in_navbar.append(tpl.name)

    if found_in_navbar:
        for n in found_in_navbar:
            fail(f'{n}: ROLE_LABEL badge re-appeared in <nav>')
    else:
        ok('No ROLE_LABEL badge in any navbar')

    # Meta tag for CSRF must exist on every page that uses fetch()
    for tpl in sorted(TEMPLATES.glob('*.html')):
        src = tpl.read_text(encoding='utf-8')
        if 'fetch(' in src and 'name="csrf-token"' not in src:
            fail(f'{tpl.name}: uses fetch() but missing <meta name="csrf-token">')
    ok('Every fetch()-using template has <meta name="csrf-token">')


# ─────────────────────────────────────────────────────────────────────────────
# §13  Dependencies pinned
# ─────────────────────────────────────────────────────────────────────────────
def check_requirements(reqs_src: str) -> None:
    section('requirements.txt — security deps present')
    for pkg in ('flask>=', 'flask-wtf>=', 'flask-limiter>=',
                'werkzeug>=', 'psycopg2-binary>='):
        if pkg in reqs_src:
            ok(f'{pkg} present')
        else:
            fail(f'{pkg} missing from requirements.txt')


# ─────────────────────────────────────────────────────────────────────────────
# §14  CLAUDE.md is present and has expected sections
# ─────────────────────────────────────────────────────────────────────────────
def check_claude_md(md_src: str) -> None:
    section('CLAUDE.md baseline doc')
    for marker in (
        '## 1. What this app is',
        '## 2. Hard rules',
        '### 2.1 Visual structure',
        '### 2.2 Security baseline',
        '### 2.3 Role / permission model',
        '### 2.4 Staff directory schema',
        '## 3. Design tokens',
        '## 4. How to add a new feature',
        '## 5. Things explicitly NOT to do',
    ):
        if marker in md_src:
            ok(f'Section present: {marker.strip("# ").strip()}')
        else:
            fail(f'CLAUDE.md missing section: {marker!r}')


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> int:
    print(f'{BOLD}Verifying Resume-Database baseline against CLAUDE.md…{RESET}')
    print(f'{DIM}Repo root: {ROOT}{RESET}')

    app_src  = read(APP_PY)
    css_src  = read(CSS)
    reqs_src = read(REQS)
    md_src   = read(CLAUDE_MD)

    if app_src:
        check_middleware(app_src)
        check_session_cookies(app_src)
        check_security_headers(app_src)
        check_cors_scope(app_src)
        check_login(app_src)
        check_default_admin(app_src)
        check_db_init(app_src)
        check_csrf_exempts(app_src)
        check_resume_download(app_src)
        check_permissions(app_src)
        check_staff_columns(app_src)
    if css_src:
        check_css(css_src)
    check_templates()
    if reqs_src:
        check_requirements(reqs_src)
    if md_src:
        check_claude_md(md_src)

    print()
    if _failures:
        print(f'{RED}{BOLD}FAILED{RESET} — {len(_failures)} invariant(s) drifted:')
        for f in _failures:
            print(f'  {RED}•{RESET} {f}')
        print()
        print(f'{DIM}Fix the drift, or if the change is intentional, update '
              f'CLAUDE.md and this script in the same commit.{RESET}')
        return 1

    print(f'{GREEN}{BOLD}PASS{RESET} — every baseline invariant holds. '
          f'Safe to push.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
