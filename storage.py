"""
File storage abstraction for the TransCrypts Resume Database.

Three backends, auto-selected based on env vars:

  • Supabase Storage (production)   — when SUPABASE_URL + SUPABASE_SERVICE_KEY
                                      + SUPABASE_BUCKET are all set
  • Local filesystem (development)  — fallback, uses the uploads/ folder

Public API:
    save_file(filename, data)            → stores bytes, returns final filename
    read_file(filename)                  → returns bytes (or None if missing)
    delete_file(filename)                → True on success
    file_exists(filename)                → bool
    file_url(filename, expires=3600)     → string URL (signed if private bucket)
    list_files()                         → list of filenames

The application code uses ONLY this module, so swapping backends never
requires touching the routes that upload, download, or display resumes.
"""

from __future__ import annotations

import os
import io
import time
from typing import Optional

# ── Configuration ─────────────────────────────────────────────────────────────
SUPABASE_URL          = (os.environ.get('SUPABASE_URL')         or '').strip().rstrip('/')
SUPABASE_SERVICE_KEY  = (os.environ.get('SUPABASE_SERVICE_KEY') or '').strip()
SUPABASE_BUCKET       = (os.environ.get('SUPABASE_BUCKET')      or 'resumes').strip()

USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_SERVICE_KEY and SUPABASE_BUCKET)

# Local fallback — same folder app.py has always used
_LOCAL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')


# ──────────────────────────────────────────────────────────────────────────────
#  Supabase Storage backend (HTTP)
#  Uses the standard Supabase Storage REST API:
#    POST /storage/v1/object/{bucket}/{path}
#    GET  /storage/v1/object/{bucket}/{path}
#    DELETE /storage/v1/object/{bucket}/{path}
#    POST /storage/v1/object/sign/{bucket}/{path}   (returns signed URL)
# ──────────────────────────────────────────────────────────────────────────────
def _sb_headers(extra: dict | None = None) -> dict:
    h = {
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'apikey':         SUPABASE_SERVICE_KEY,
    }
    if extra:
        h.update(extra)
    return h


def _sb_url(path: str) -> str:
    return f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{path}"


def _sb_save(filename: str, data: bytes, content_type: str = 'application/octet-stream'):
    """Upload bytes to Supabase Storage. Raises a descriptive error on failure."""
    import requests
    headers = _sb_headers({
        'Content-Type':   content_type,
        # x-upsert: replace if exists, easier than checking + deleting first
        'x-upsert':       'true',
    })
    r = requests.post(_sb_url(filename), headers=headers, data=data, timeout=60)
    if not r.ok:
        # Surface Supabase's actual error message instead of a generic
        # "400 Client Error: Bad Request" so it's diagnosable.
        try:
            body = r.json()
            detail = body.get('message') or body.get('error') or body.get('msg') or str(body)
        except Exception:
            detail = (r.text or '')[:300]
        raise RuntimeError(
            f"Supabase Storage upload failed ({r.status_code}): {detail} "
            f"[bucket={SUPABASE_BUCKET}, file={filename}]"
        )


def _sb_read(filename: str) -> Optional[bytes]:
    import requests
    r = requests.get(_sb_url(filename), headers=_sb_headers(), timeout=60)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.content


def _sb_delete(filename: str) -> bool:
    import requests
    r = requests.delete(_sb_url(filename), headers=_sb_headers(), timeout=30)
    return r.status_code in (200, 204, 404)


def _sb_exists(filename: str) -> bool:
    import requests
    # HEAD is supported on Supabase Storage and avoids downloading the file body
    r = requests.head(_sb_url(filename), headers=_sb_headers(), timeout=15)
    return r.status_code == 200


def _sb_signed_url(filename: str, expires_seconds: int = 3600) -> Optional[str]:
    import requests
    sign_path = f"{SUPABASE_URL}/storage/v1/object/sign/{SUPABASE_BUCKET}/{filename}"
    r = requests.post(sign_path,
                      headers=_sb_headers({'Content-Type': 'application/json'}),
                      json={'expiresIn': expires_seconds},
                      timeout=15)
    if r.status_code == 404:
        return None
    if not r.ok:
        try:
            body = r.json()
            detail = body.get('message') or body.get('error') or str(body)
        except Exception:
            detail = (r.text or '')[:300]
        raise RuntimeError(
            f"Supabase Storage signed-URL failed ({r.status_code}): {detail} "
            f"[bucket={SUPABASE_BUCKET}, file={filename}]"
        )
    data = r.json() or {}
    rel = data.get('signedURL') or data.get('signedUrl')
    if not rel:
        return None
    if rel.startswith('http'):
        return rel
    return f"{SUPABASE_URL}/storage/v1{rel}"


def _sb_list() -> list[str]:
    import requests
    list_url = f"{SUPABASE_URL}/storage/v1/object/list/{SUPABASE_BUCKET}"
    r = requests.post(list_url,
                      headers=_sb_headers({'Content-Type': 'application/json'}),
                      json={'limit': 1000, 'offset': 0,
                            'sortBy': {'column': 'name', 'order': 'asc'}},
                      timeout=30)
    r.raise_for_status()
    items = r.json() or []
    return [item.get('name', '') for item in items if item.get('name')]


# ──────────────────────────────────────────────────────────────────────────────
#  Local filesystem backend
# ──────────────────────────────────────────────────────────────────────────────
def _local_path(filename: str) -> str:
    return os.path.join(_LOCAL_DIR, filename)


def _local_save(filename: str, data: bytes, content_type: str = ''):
    os.makedirs(_LOCAL_DIR, exist_ok=True)
    with open(_local_path(filename), 'wb') as f:
        f.write(data)


def _local_read(filename: str) -> Optional[bytes]:
    p = _local_path(filename)
    if not os.path.isfile(p):
        return None
    with open(p, 'rb') as f:
        return f.read()


def _local_delete(filename: str) -> bool:
    p = _local_path(filename)
    if os.path.isfile(p):
        try:
            os.remove(p)
            return True
        except OSError:
            return False
    return True


def _local_exists(filename: str) -> bool:
    return os.path.isfile(_local_path(filename))


def _local_list() -> list[str]:
    if not os.path.isdir(_LOCAL_DIR):
        return []
    return sorted(os.listdir(_LOCAL_DIR))


# ──────────────────────────────────────────────────────────────────────────────
#  Public API — auto-routes to the right backend
# ──────────────────────────────────────────────────────────────────────────────
def backend() -> str:
    """Return 'supabase' or 'local' so callers can branch on backend if needed."""
    return 'supabase' if USE_SUPABASE else 'local'


def save_file(filename: str, data: bytes, content_type: str = 'application/octet-stream') -> str:
    """Persist bytes under the given filename. Returns the filename used."""
    if USE_SUPABASE:
        _sb_save(filename, data, content_type)
    else:
        _local_save(filename, data, content_type)
    return filename


def read_file(filename: str) -> Optional[bytes]:
    """Fetch bytes for the file. Returns None if not found."""
    return _sb_read(filename) if USE_SUPABASE else _local_read(filename)


def delete_file(filename: str) -> bool:
    return _sb_delete(filename) if USE_SUPABASE else _local_delete(filename)


def file_exists(filename: str) -> bool:
    return _sb_exists(filename) if USE_SUPABASE else _local_exists(filename)


def file_url(filename: str, expires: int = 3600) -> Optional[str]:
    """
    Return a URL the browser can use to download the file.
    For Supabase: returns a SIGNED URL (valid for `expires` seconds).
    For local:    returns None — the app serves files via its own /uploads route.
    """
    if USE_SUPABASE:
        return _sb_signed_url(filename, expires_seconds=expires)
    return None


def list_files() -> list[str]:
    return _sb_list() if USE_SUPABASE else _local_list()


def local_path_if_local(filename: str) -> Optional[str]:
    """Return the local filesystem path if the local backend is in use, else None.
    Useful for routes that need to send_file() directly."""
    if USE_SUPABASE:
        return None
    return _local_path(filename)
