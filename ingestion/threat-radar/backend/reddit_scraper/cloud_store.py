"""Save collected posts to Neon and image files to Backblaze B2.

The database stores text, real URLs, and the object key. Image bytes stay in the bucket.
label_status is left as not_annotated for new rows and is not changed on later saves.
"""

import base64
import hashlib
import os
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass

_CONTENT_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
}

_UPSERT = """
INSERT INTO reddit_posts (
  post_id, subreddit, collected_at, matched_keywords, title, post_text,
  post_url, urls, image_urls, image_files, label_status
) VALUES (
  %(post_id)s, %(subreddit)s, %(collected_at)s, %(matched_keywords)s, %(title)s, %(post_text)s,
  %(post_url)s, %(urls)s, %(image_urls)s, %(image_files)s, 'not_annotated'
)
ON CONFLICT (post_id) DO UPDATE SET
  subreddit = COALESCE(EXCLUDED.subreddit, reddit_posts.subreddit),
  collected_at = COALESCE(reddit_posts.collected_at, EXCLUDED.collected_at),
  matched_keywords = CASE
    WHEN cardinality(EXCLUDED.matched_keywords) > 0 THEN EXCLUDED.matched_keywords
    ELSE reddit_posts.matched_keywords END,
  title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE reddit_posts.title END,
  post_text = CASE WHEN EXCLUDED.post_text <> '' THEN EXCLUDED.post_text ELSE reddit_posts.post_text END,
  post_url = CASE WHEN EXCLUDED.post_url <> '' THEN EXCLUDED.post_url ELSE reddit_posts.post_url END,
  urls = CASE WHEN cardinality(EXCLUDED.urls) > 0 THEN EXCLUDED.urls ELSE reddit_posts.urls END,
  image_urls = CASE WHEN cardinality(EXCLUDED.image_urls) > 0 THEN EXCLUDED.image_urls ELSE reddit_posts.image_urls END,
  image_files = CASE WHEN cardinality(EXCLUDED.image_files) > 0 THEN EXCLUDED.image_files ELSE reddit_posts.image_files END
"""


def database_configured() -> bool:
    return bool((os.getenv("DATABASE_URL") or "").strip())


def backblaze_configured() -> bool:
    return all((os.getenv(name) or "").strip() for name in ("B2_KEY_ID", "B2_APPLICATION_KEY", "B2_BUCKET", "B2_ENDPOINT"))


def image_prefix() -> str:
    return (os.getenv("B2_IMAGE_PREFIX") or "images").strip().strip("/") or "images"


def cloud_key(local_ref: str, source: str = "reddit") -> str:
    name = os.path.basename(str(local_ref).replace("\\", "/"))
    return f"{image_prefix()}/{source}/{name}"


def _words(value: str) -> list[str]:
    return [part for part in (value or "").split() if part]


def _keywords(value) -> list[str]:
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    raw = (value or "").strip()
    if not raw:
        return []
    if "|" in raw:
        return [part.strip() for part in raw.split("|") if part.strip()]
    return [raw]


def _when(value: str):
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed


def _row(record: dict, image_keys: list[str]) -> dict:
    return {
        "post_id": record.get("post_id") or "",
        "subreddit": record.get("subreddit") or "",
        "collected_at": _when(record.get("date") or record.get("collected_at") or ""),
        "matched_keywords": _keywords(record.get("matched_keywords") or ""),
        "title": record.get("title") or "",
        "post_text": record.get("text") or record.get("post_text") or "",
        "post_url": record.get("post_url") or "",
        "urls": _words(record.get("urls") or ""),
        "image_urls": _words(record.get("image_urls") or ""),
        "image_files": image_keys,
    }


_auth = None
_bucket_id = None
_known_names: set[str] | None = None
_upload_state = None


def _b2_auth() -> dict:
    global _auth
    if _auth:
        return _auth
    import requests

    raw = f"{os.environ['B2_KEY_ID'].strip()}:{os.environ['B2_APPLICATION_KEY'].strip()}"
    token = base64.b64encode(raw.encode()).decode()
    resp = requests.get(
        "https://api.backblazeb2.com/b2api/v2/b2_authorize_account",
        headers={"Authorization": f"Basic {token}"},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"Backblaze login failed ({resp.status_code})")
    _auth = resp.json()
    return _auth


def _b2_bucket_id() -> str:
    global _bucket_id
    if _bucket_id:
        return _bucket_id
    import requests

    auth = _b2_auth()
    resp = requests.post(
        auth["apiUrl"] + "/b2api/v2/b2_list_buckets",
        headers={"Authorization": auth["authorizationToken"]},
        json={"accountId": auth["accountId"], "bucketName": os.environ["B2_BUCKET"].strip()},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"Backblaze bucket lookup failed ({resp.status_code})")
    buckets = resp.json().get("buckets") or []
    if not buckets:
        raise RuntimeError("Backblaze bucket name was not found")
    _bucket_id = buckets[0]["bucketId"]
    return _bucket_id


def _existing_names() -> set[str]:
    global _known_names
    if _known_names is not None:
        return _known_names
    import requests

    auth = _b2_auth()
    names: set[str] = set()
    start = None
    prefix = image_prefix() + "/"
    while True:
        body = {"bucketId": _b2_bucket_id(), "prefix": prefix, "maxFileCount": 1000}
        if start:
            body["startFileName"] = start
        resp = requests.post(
            auth["apiUrl"] + "/b2api/v2/b2_list_file_names",
            headers={"Authorization": auth["authorizationToken"]},
            json=body,
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"Backblaze file list failed ({resp.status_code})")
        data = resp.json()
        names.update(item.get("fileName") or "" for item in data.get("files") or [])
        start = data.get("nextFileName")
        if not start:
            break
    _known_names = names
    return names


def _upload_state_get() -> dict:
    global _upload_state
    if _upload_state:
        return _upload_state
    import requests

    auth = _b2_auth()
    resp = requests.post(
        auth["apiUrl"] + "/b2api/v2/b2_get_upload_url",
        headers={"Authorization": auth["authorizationToken"]},
        json={"bucketId": _b2_bucket_id()},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"Backblaze upload URL failed ({resp.status_code})")
    _upload_state = resp.json()
    return _upload_state


def upload_image(local_path: str, source: str = "reddit") -> str:
    """Upload one image file. Returns the object key stored in the database."""
    global _upload_state
    key = cloud_key(local_path, source)
    if not backblaze_configured() or not os.path.isfile(local_path):
        return ""
    if key in _existing_names():
        return key
    import requests

    ext = os.path.splitext(local_path)[1].lower()
    payload = Path(local_path).read_bytes()
    target = _upload_state_get()
    resp = requests.post(
        target["uploadUrl"],
        headers={
            "Authorization": target["authorizationToken"],
            "X-Bz-File-Name": quote(key, safe="/"),
            "Content-Type": _CONTENT_TYPES.get(ext, "application/octet-stream"),
            "X-Bz-Content-Sha1": hashlib.sha1(payload).hexdigest(),
        },
        data=payload,
        timeout=60,
    )
    if resp.status_code in (401, 503):
        _upload_state = None
        target = _upload_state_get()
        resp = requests.post(
            target["uploadUrl"],
            headers={
                "Authorization": target["authorizationToken"],
                "X-Bz-File-Name": quote(key, safe="/"),
                "Content-Type": _CONTENT_TYPES.get(ext, "application/octet-stream"),
                "X-Bz-Content-Sha1": hashlib.sha1(payload).hexdigest(),
            },
            data=payload,
            timeout=60,
        )
    if not resp.ok:
        raise RuntimeError(f"Backblaze upload failed ({resp.status_code})")
    _existing_names().add(key)
    return key


def upload_record_images(record: dict, images_dir: str) -> list[str]:
    keys: list[str] = []
    refs = _words(record.get("image_files") or "")
    if isinstance(record.get("image_files"), list):
        refs = [str(item) for item in record["image_files"] if item]
    for ref in refs:
        name = os.path.basename(str(ref).replace("\\", "/"))
        path = os.path.join(images_dir, name)
        if not os.path.isfile(path):
            continue
        key = upload_image(path)
        if key:
            keys.append(key)
    return keys


def keep_only(post_ids: list[str]) -> int:
    """Delete stored posts that are not in post_ids. Returns how many rows were removed."""
    if not database_configured():
        return 0
    import psycopg

    with psycopg.connect(os.environ["DATABASE_URL"].strip(), connect_timeout=20) as conn:
        with conn.cursor() as cur:
            if post_ids:
                cur.execute("DELETE FROM reddit_posts WHERE NOT (post_id = ANY(%s))", (post_ids,))
            else:
                cur.execute("DELETE FROM reddit_posts")
            removed = cur.rowcount
        conn.commit()
    return removed


def publish_posts(records: list[dict], images_dir: str) -> tuple[int, int]:
    """Upsert posts and upload their local image files. Returns (posts, images)."""
    if not records or not database_configured():
        return 0, 0
    import psycopg

    payload = []
    images = 0
    for record in records:
        if not record.get("post_id"):
            continue
        keys = upload_record_images(record, images_dir) if backblaze_configured() else []
        images += len(keys)
        payload.append(_row(record, keys))
    if not payload:
        return 0, 0
    with psycopg.connect(os.environ["DATABASE_URL"].strip(), connect_timeout=20) as conn:
        with conn.cursor() as cur:
            cur.executemany(_UPSERT, payload)
        conn.commit()
    return len(payload), images
