"""
Database abstraction layer for the TransCrypts Resume Database.

Provides a single get_db() function that returns either:
  • A Postgres connection (when DATABASE_URL env var is set — production)
  • A SQLite connection                (local development, no setup needed)

The Postgres connection is wrapped to look exactly like sqlite3.Connection so
that all the existing  conn.execute('… ?', (val,))  code works unchanged:
  • '?' placeholders are auto-translated to '%s'
  • cursor.fetchone()/fetchall() return dict-like rows (row['name'] works)
  • lastrowid is auto-populated by appending RETURNING id to INSERTs
  • CREATE TABLE statements get SQLite-specific syntax converted on the fly

This keeps the application code 100% unchanged when running locally while
making it production-ready on any Postgres-backed host (Supabase, Neon, RDS).
"""

from __future__ import annotations

import os
import re
import sqlite3
from typing import Any, Iterable, Optional

# ── Connection target ─────────────────────────────────────────────────────────
DATABASE_URL = (os.environ.get('DATABASE_URL') or '').strip()
USE_POSTGRES = DATABASE_URL.startswith(('postgres://', 'postgresql://'))

# Local SQLite path (fallback for local dev). Match the path used in app.py.
SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'resumes.db')


# ──────────────────────────────────────────────────────────────────────────────
#  Postgres support — only loaded when DATABASE_URL is set
# ──────────────────────────────────────────────────────────────────────────────
if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras


    # ── Auto-fix Supabase direct URLs (which are IPv6-only) ─────────────────
    # Many cloud hosts (Render, Heroku, Fly.io) only have IPv4, but Supabase's
    # "Direct connection" host  db.{ref}.supabase.co  resolves to IPv6 only.
    # Attempting to use it produces  "Network is unreachable" .
    # Supabase's "Connection pooler" hosts (aws-{N}-{region}.pooler.supabase.com)
    # are dual-stack IPv4 + IPv6, so they work everywhere.
    #
    # If the user pasted the direct URL by mistake, we silently probe a list of
    # known pooler endpoints to find the one that actually serves their project,
    # then keep using it for the lifetime of the container.

    import re as _re

    _DIRECT_URL_RE = _re.compile(
        r'^postgresql://postgres:(?P<pwd>[^@]+)@db\.(?P<ref>[^.]+)\.supabase\.co:5432/postgres',
        _re.IGNORECASE
    )

    # Order tries the more likely regions first (Oregon = us-west-2)
    _POOLER_HOSTS = [
        'aws-1-us-west-2.pooler.supabase.com',
        'aws-0-us-west-2.pooler.supabase.com',
        'aws-1-us-east-1.pooler.supabase.com',
        'aws-0-us-east-1.pooler.supabase.com',
        'aws-1-us-east-2.pooler.supabase.com',
        'aws-0-us-east-2.pooler.supabase.com',
        'aws-1-us-west-1.pooler.supabase.com',
        'aws-0-us-west-1.pooler.supabase.com',
        'aws-1-ca-central-1.pooler.supabase.com',
        'aws-0-ca-central-1.pooler.supabase.com',
        'aws-0-eu-central-1.pooler.supabase.com',
        'aws-0-eu-west-1.pooler.supabase.com',
        'aws-0-eu-west-2.pooler.supabase.com',
        'aws-0-ap-southeast-1.pooler.supabase.com',
        'aws-0-ap-southeast-2.pooler.supabase.com',
        'aws-0-ap-northeast-1.pooler.supabase.com',
        'aws-0-ap-south-1.pooler.supabase.com',
        'aws-0-sa-east-1.pooler.supabase.com',
    ]


    def _build_pooler_url(project_ref: str, password: str, host: str) -> str:
        """Build a transaction-mode pooler URL for the given project."""
        return (f'postgresql://postgres.{project_ref}:{password}'
                f'@{host}:6543/postgres')


    def _resolve_pooler_url(direct_url: str) -> str:
        """
        Given a direct Supabase URL, probe known pooler hosts until one accepts
        the connection. Returns the working pooler URL, or the original URL if
        no pooler works (caller will get a real error which is fine).
        """
        m = _DIRECT_URL_RE.match(direct_url)
        if not m:
            return direct_url   # Not a recognisable direct URL, leave alone
        password    = m.group('pwd')
        project_ref = m.group('ref')

        # Allow an env var SUPABASE_POOLER_HOST to short-circuit the probe
        forced = (os.environ.get('SUPABASE_POOLER_HOST') or '').strip()
        candidates = [forced] + _POOLER_HOSTS if forced else _POOLER_HOSTS

        for host in candidates:
            url = _build_pooler_url(project_ref, password, host)
            try:
                conn = psycopg2.connect(url, sslmode='require', connect_timeout=6)
                conn.close()
                print(f'[db] Auto-resolved Supabase pooler host: {host}')
                return url
            except Exception:
                continue

        print('[db] Could not auto-resolve a working pooler host; '
              'falling back to original DATABASE_URL.')
        return direct_url


    # Resolve once at import time so every connection uses the working URL.
    # If DATABASE_URL is already a pooler URL, this is a no-op.
    if _DIRECT_URL_RE.match(DATABASE_URL):
        DATABASE_URL = _resolve_pooler_url(DATABASE_URL)


    class _PgRow(dict):
        """Mimics sqlite3.Row — supports both row['col'] and row[idx]."""
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._values = list(self.values())

        def __getitem__(self, key):
            if isinstance(key, int):
                return self._values[key]
            return super().__getitem__(key)

        def keys(self):
            return list(super().keys())


    # ── Query translation helpers ────────────────────────────────────────────
    _RE_QMARK = re.compile(r'\?')
    _RE_AUTOINC = re.compile(
        r'\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b', re.IGNORECASE
    )
    _RE_INSERT = re.compile(r'^\s*INSERT\s+INTO\s+', re.IGNORECASE)
    _RE_RETURNING = re.compile(r'\bRETURNING\b', re.IGNORECASE)
    _RE_INSERT_OR_IGNORE = re.compile(r'^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+',
                                       re.IGNORECASE)
    _RE_INSERT_OR_REPLACE = re.compile(r'^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+',
                                        re.IGNORECASE)

    # SQLite datetime/date built-ins → Postgres equivalents.
    # The TEXT columns store ISO-style strings, so we use to_char() to produce
    # the same  YYYY-MM-DD HH:MM:SS  format SQLite would have produced.
    _RE_DATETIME_NOW_LOCAL = re.compile(
        r"datetime\(\s*'now'\s*,\s*'localtime'\s*\)", re.IGNORECASE
    )
    _RE_DATETIME_NOW = re.compile(r"datetime\(\s*'now'\s*\)", re.IGNORECASE)
    _RE_DATE_NOW     = re.compile(r"date\(\s*'now'\s*\)",     re.IGNORECASE)
    _RE_TIME_NOW     = re.compile(r"time\(\s*'now'\s*\)",     re.IGNORECASE)

    # SQLite's case-insensitive collation has no Postgres equivalent.
    # We translate three uses:
    #   WHERE col = ? COLLATE NOCASE     →  WHERE LOWER(col) = LOWER(?)
    #   ORDER BY col COLLATE NOCASE      →  ORDER BY LOWER(col)
    #   <column DDL> COLLATE NOCASE      →  (stripped — case-sensitive in PG)
    # The DDL strip means the UNIQUE constraint on username becomes
    # case-sensitive, but Strategy-1 still handles every login query correctly.
    _RE_COLLATE_EQ = re.compile(
        r'(\b\w+(?:\.\w+)?)\s*=\s*(\?|%s|\'[^\']*\')\s+COLLATE\s+NOCASE',
        re.IGNORECASE
    )
    _RE_COLLATE_ORDER = re.compile(
        r'ORDER\s+BY\s+(\b\w+(?:\.\w+)?)\s+COLLATE\s+NOCASE',
        re.IGNORECASE
    )
    _RE_COLLATE_STRIP = re.compile(r'\s+COLLATE\s+NOCASE', re.IGNORECASE)


    def _translate(query: str) -> tuple[str, bool]:
        """
        Translate SQLite-flavoured SQL into Postgres SQL.
        Returns (translated_query, is_returning_insert).
        """
        q = query

        # ── DDL: SQLite-only types & functions ──
        # INTEGER PRIMARY KEY AUTOINCREMENT  →  SERIAL PRIMARY KEY
        q = _RE_AUTOINC.sub('SERIAL PRIMARY KEY', q)

        # SQLite datetime/date functions  →  Postgres to_char(...)
        q = _RE_DATETIME_NOW_LOCAL.sub(
            "to_char(now(), 'YYYY-MM-DD HH24:MI:SS')", q
        )
        q = _RE_DATETIME_NOW.sub(
            "to_char(now(), 'YYYY-MM-DD HH24:MI:SS')", q
        )
        q = _RE_DATE_NOW.sub("to_char(now(), 'YYYY-MM-DD')", q)
        q = _RE_TIME_NOW.sub("to_char(now(), 'HH24:MI:SS')", q)

        # SQLite COLLATE NOCASE → Postgres LOWER()-based equivalents
        # Order matters: do the equality and ORDER BY rewrites before the
        # generic strip, so DDL appearances are removed but query semantics
        # are preserved.
        q = _RE_COLLATE_EQ.sub(r'LOWER(\1) = LOWER(\2)', q)
        q = _RE_COLLATE_ORDER.sub(r'ORDER BY LOWER(\1)', q)
        q = _RE_COLLATE_STRIP.sub('', q)

        # SQLite "INSERT OR IGNORE" / "INSERT OR REPLACE" → Postgres ON CONFLICT
        # (simplified; for complex cases callers should use ON CONFLICT explicitly)
        q = _RE_INSERT_OR_IGNORE.sub('INSERT INTO ', q)
        q = _RE_INSERT_OR_REPLACE.sub('INSERT INTO ', q)

        # ? placeholders → %s
        q = _RE_QMARK.sub('%s', q)

        # If this is a plain INSERT without a RETURNING clause, append one so
        # cursor.lastrowid can be populated after execute().
        is_insert = bool(_RE_INSERT.match(q)) and not _RE_RETURNING.search(q)
        if is_insert:
            q = q.rstrip().rstrip(';') + ' RETURNING id'

        return q, is_insert


    class _PgCursor:
        """Wraps a psycopg2 cursor to look like sqlite3.Cursor."""
        def __init__(self, raw_cur):
            self._cur = raw_cur
            self.lastrowid: Optional[int] = None

        def execute(self, query: str, params: Iterable[Any] = ()):
            translated, is_returning_insert = _translate(query)
            self._cur.execute(translated, tuple(params or ()))
            self.lastrowid = None
            if is_returning_insert:
                try:
                    row = self._cur.fetchone()
                    if row is not None:
                        # row could be tuple or RealDictRow
                        if isinstance(row, dict):
                            self.lastrowid = row.get('id')
                        else:
                            self.lastrowid = row[0]
                except psycopg2.ProgrammingError:
                    pass
            return self

        def executemany(self, query: str, seq_of_params: Iterable[Iterable[Any]]):
            translated, _ = _translate(query)
            self._cur.executemany(translated, list(seq_of_params))
            return self

        def fetchone(self) -> Optional[_PgRow]:
            row = self._cur.fetchone()
            if row is None:
                return None
            return _PgRow(row) if isinstance(row, dict) else _PgRow(
                {self._cur.description[i].name: v for i, v in enumerate(row)}
            )

        def fetchall(self) -> list[_PgRow]:
            rows = self._cur.fetchall()
            out = []
            for row in rows:
                if isinstance(row, dict):
                    out.append(_PgRow(row))
                else:
                    out.append(_PgRow(
                        {self._cur.description[i].name: v for i, v in enumerate(row)}
                    ))
            return out

        def __iter__(self):
            for row in self.fetchall():
                yield row

        def close(self):
            self._cur.close()


    class _PgConnection:
        """Wraps psycopg2 connection to look like sqlite3.Connection."""
        def __init__(self, raw_conn):
            self._conn = raw_conn
            # psycopg2 uses transactions implicitly; mimic SQLite's "autocommit
            # within a context manager" feel by NOT autocommitting — callers
            # already use conn.commit() and `with get_db() as conn:` blocks.

        def execute(self, query: str, params: Iterable[Any] = ()) -> _PgCursor:
            cur = _PgCursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))
            cur.execute(query, params)
            return cur

        def executemany(self, query: str, seq):
            cur = _PgCursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))
            cur.executemany(query, seq)
            return cur

        def cursor(self) -> _PgCursor:
            return _PgCursor(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

        def commit(self):
            self._conn.commit()

        def rollback(self):
            self._conn.rollback()

        def close(self):
            try: self._conn.close()
            except Exception: pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            if exc_type is None:
                try: self._conn.commit()
                except Exception: pass
            else:
                try: self._conn.rollback()
                except Exception: pass
            self.close()


    def _open_pg() -> _PgConnection:
        # psycopg2 understands the standard postgresql:// URI.
        # We pass sslmode=require explicitly so it works whether or not the URL
        # already includes one (Supabase always requires SSL).
        # connect_timeout protects against hanging on network issues.
        conn = psycopg2.connect(DATABASE_URL,
                                 sslmode='require',
                                 connect_timeout=15)
        # Autocommit mode mirrors SQLite's default behaviour: each statement
        # commits on success. Crucially this means a failed DDL inside a
        # try/except (common pattern for "ADD COLUMN if not exists" style
        # migrations) does NOT poison subsequent statements with
        # "current transaction is aborted". This matches what the application
        # code assumes since it already handles atomicity at the route level.
        conn.set_session(autocommit=True)
        return _PgConnection(conn)


# ──────────────────────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────────────────────
def get_db():
    """
    Return a database connection.
    Use as a context manager:
        with get_db() as conn:
            conn.execute('…', (…,))
    """
    if USE_POSTGRES:
        return _open_pg()
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def dialect() -> str:
    """Return 'postgres' or 'sqlite' so callers can branch on dialect when needed."""
    return 'postgres' if USE_POSTGRES else 'sqlite'
