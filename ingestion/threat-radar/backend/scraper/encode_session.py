"""
Generate TELEGRAM_SESSION_B64 value for Render deployment.
Run this locally after authenticating with scrape.py at least once.

Usage:
  cd backend/scraper
  python encode_session.py
"""

import base64
import sys
from pathlib import Path

session_name = "scraper_session"
session_file = Path(__file__).parent / f"{session_name}.session"

# Also check project root (created when running from project root)
if not session_file.exists():
    session_file = Path(__file__).parent.parent.parent / f"{session_name}.session"

if not session_file.exists():
    print("ERROR: No session file found.")
    print("Run 'python scrape.py batch' locally first to log in.")
    sys.exit(1)

b64 = base64.b64encode(session_file.read_bytes()).decode()

print("\n" + "="*60)
print("Copy the value below into Render → Environment variables")
print("Key:   TELEGRAM_SESSION_B64")
print("="*60)
print(b64)
print("="*60 + "\n")
print(f"(Source: {session_file})")
