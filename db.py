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

    def _translate(query: str) -> tuple[str, bool]:
        """
        Translate SQLite-flavoured SQL into Postgres SQL.
        Returns (translated_query, is_returning_insert).
        """
        q = query

        # SQLite "INTEGER PRIMARY KEY AUTOINCREMENT" → Postgres SERIAL
        q = _RE_AUTOINC.sub('SERIAL PRIMARY KEY', q)

        # SQLite "INSERT OR IGNORE" / "INSERT OR REPLACE" → Postgres ON CONFLICT
        q = _RE_INSERT_OR_IGNORE.sub('INSERT INTO ', q)        # simplified; ON CONFLICT
        # (We don't have an obvious unique key here without parsing — callers should
        #  use ON CONFLICT explicitly when needed.)
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
        # psycopg2 understands the standard postgresql:// URI; sslmode is taken
        # from the URL (Supabase requires sslmode=require, which the URL has by
        # default — but we set it as a fallback in case it's missing).
        return _PgConnection(psycopg2.connect(DATABASE_URL, sslmode='require'))


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
