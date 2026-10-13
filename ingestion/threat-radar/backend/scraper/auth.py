"""
Telegram Auth Helper — ThreatRadar
Spawned by Node.js backend for each auth step.
Outputs a single JSON line to stdout.

Commands:
  python auth.py status
  python auth.py request-code +94771234567
  python auth.py verify-code  12345
  python auth.py verify-password  mypassword
"""

import asyncio
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.errors import (
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    SessionPasswordNeededError,
)
from telethon.errors.rpcerrorlist import AuthKeyDuplicatedError

load_dotenv(Path(__file__).parent.parent / ".env")

API_ID       = int(os.getenv("API_ID", "0"))
API_HASH     = os.getenv("API_HASH", "")
SESSION_NAME = os.getenv("TELEGRAM_SESSION_NAME", "scraper_session")
SCRAPER_DIR  = Path(__file__).parent
STATE_FILE   = SCRAPER_DIR / "auth_state.json"


def out(success: bool, **kwargs):
    """Print a single JSON line and exit."""
    print(json.dumps({"success": success, **kwargs}), flush=True)


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(data: dict):
    STATE_FILE.write_text(json.dumps(data), encoding="utf-8")


def client() -> TelegramClient:
    return TelegramClient(
        str(SCRAPER_DIR / SESSION_NAME),
        API_ID,
        API_HASH,
        connection_retries=3,
        retry_delay=1,
    )


# ── Commands ──────────────────────────────────────────────────────

def is_session_conflict_error(err: BaseException) -> bool:
    msg = str(err).lower()
    return (
        isinstance(err, AuthKeyDuplicatedError)
        or "two different ip addresses" in msg
        or ("authorization key" in msg and "simultaneously" in msg)
    )


def clear_dead_session(session_path: Path) -> bool:
    try:
        session_path.unlink(missing_ok=True)
        journal = Path(str(session_path) + "-journal")
        journal.unlink(missing_ok=True)
        return True
    except PermissionError:
        return False
    except Exception:
        return False


async def cmd_status():
    session_path = SCRAPER_DIR / f"{SESSION_NAME}.session"
    if not session_path.exists():
        out(False, step="none", message="Not logged in")
        return

    c = client()
    try:
        await asyncio.wait_for(c.connect(), timeout=12)
        if await c.is_user_authorized():
            me = await c.get_me()
            name = f"{me.first_name or ''} {me.last_name or ''}".strip()
            out(
                True,
                step="done",
                name=name,
                phone=me.phone,
                username=getattr(me, "username", None),
            )
        else:
            clear_dead_session(session_path)
            out(False, step="none", message="Session expired — please log in again")
    except AuthKeyDuplicatedError:
        cleared = clear_dead_session(session_path)
        out(
            False,
            step="none",
            message=(
                "Session invalidated. Stop the scraper, then log in again."
                if not cleared
                else "Session invalidated. Please log in again."
            ),
        )
    except asyncio.TimeoutError:
        out(False, step="error", message="Telegram unreachable (timeout)")
    except Exception as e:
        if is_session_conflict_error(e):
            cleared = clear_dead_session(session_path)
            out(
                False,
                step="none",
                message=(
                    "Session invalidated. Stop the scraper, then log in again."
                    if not cleared
                    else "Session invalidated. Please log in again."
                ),
            )
        else:
            out(False, step="error", message=str(e))
    finally:
        if c.is_connected():
            await c.disconnect()


async def cmd_request_code(phone: str):
    c = client()
    try:
        await c.connect()
        result = await c.send_code_request(phone)
        save_state({"phone": phone, "phone_code_hash": result.phone_code_hash})
        out(True, step="code_sent",
            message=f"Verification code sent to {phone}")
    except Exception as e:
        out(False, step="error", message=str(e))
    finally:
        await c.disconnect()


async def cmd_verify_code(code: str):
    state = load_state()
    phone = state.get("phone")
    phone_code_hash = state.get("phone_code_hash")

    if not phone or not phone_code_hash:
        out(False, step="error",
            message="No pending login. Send a code first.")
        return

    c = client()
    try:
        await c.connect()
        await c.sign_in(phone, code, phone_code_hash=phone_code_hash)
        STATE_FILE.unlink(missing_ok=True)
        me = await c.get_me()
        name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        out(True, step="done", message="Logged in!", name=name)

    except SessionPasswordNeededError:
        out(True, step="password_needed",
            message="2FA enabled — enter your Telegram password")

    except (PhoneCodeInvalidError, PhoneCodeExpiredError) as e:
        out(False, step="code_sent",
            message="Invalid or expired code. Try again.")

    except Exception as e:
        out(False, step="error", message=str(e))
    finally:
        await c.disconnect()


async def cmd_verify_password(password: str):
    c = client()
    try:
        await c.connect()
        await c.sign_in(password=password)
        STATE_FILE.unlink(missing_ok=True)
        me = await c.get_me()
        name = f"{me.first_name or ''} {me.last_name or ''}".strip()
        out(True, step="done", message="Logged in!", name=name)
    except Exception as e:
        out(False, step="error", message=str(e))
    finally:
        await c.disconnect()


async def cmd_logout():
    c = client()
    try:
        await c.connect()
        await c.log_out()
    except Exception:
        pass
    finally:
        await c.disconnect()
    session_path = SCRAPER_DIR / f"{SESSION_NAME}.session"
    session_path.unlink(missing_ok=True)
    STATE_FILE.unlink(missing_ok=True)
    out(True, step="none", message="Logged out")


# ── Entry point ───────────────────────────────────────────────────

async def main():
    if not API_ID or not API_HASH:
        out(False, step="error",
            message="API_ID / API_HASH not set in backend/.env")
        return

    cmd  = sys.argv[1] if len(sys.argv) > 1 else "status"
    arg  = sys.argv[2] if len(sys.argv) > 2 else ""

    if   cmd == "status":           await cmd_status()
    elif cmd == "request-code":     await cmd_request_code(arg)
    elif cmd == "verify-code":      await cmd_verify_code(arg)
    elif cmd == "verify-password":  await cmd_verify_password(arg)
    elif cmd == "logout":           await cmd_logout()
    else:
        out(False, step="error", message=f"Unknown command: {cmd}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        out(False, step="error", message=str(e))
