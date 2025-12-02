"""
Encrypt legacy plaintext exports into the new zero-knowledge import format.

What it does:
- Loads the per-user salt from the database (by email).
- Prompts for the user's master password locally.
- Derives the vault key client-style (PBKDF2-SHA256, 120k iterations, 32-byte AES-GCM).
- Encrypts each legacy entry into `encrypted_payload` and writes an import-ready JSON.

Inputs:
- LEGACY_FILE (env, optional): path to legacy_plain_export.csv or legacy_plain_export.json
  Defaults to ./legacy_plain_export.csv
- USER_EMAIL (env, required): email of the user whose vault you're encrypting

Output:
- passwords_export_encrypted.json in the project root (same shape as the app's encrypted export).

Usage:
    USER_EMAIL="you@example.com" python encrypt_legacy_to_import.py

Safety:
- Master password is requested via getpass; nothing is sent over the network.
- Existing database data is not modified.
"""
from __future__ import annotations

import base64
import csv
import json
import os
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from project import create_app, db
from project.models import Users


def load_salt(email: str) -> str:
    user = db.session.execute(db.select(Users).where(Users.email == email.lower().strip())).scalar_one_or_none()
    if not user:
        raise SystemExit(f"No user found with email {email}")
    return user.encryption_salt


def derive_key(password: str, salt_b64: str) -> bytes:
    salt = base64.b64decode(salt_b64.encode())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=120_000,
    )
    return kdf.derive(password.encode())


def encrypt_payload(key: bytes, payload: dict) -> str:
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, json.dumps(payload).encode(), associated_data=None)
    return f"{base64.b64encode(iv).decode()}:{base64.b64encode(ct).decode()}"


def parse_additional_fields(raw: str) -> list[dict[str, str]]:
    fields = []
    if not raw:
        return fields
    for part in raw.split(";"):
        if ":" in part:
            label, value = part.split(":", 1)
            label = label.strip()
            value = value.strip()
            if label and value:
                fields.append({"label": label, "value": value})
    return fields


def load_legacy(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("passwords") or data

    rows = []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def main():
    legacy_path = Path(os.getenv("LEGACY_FILE", "legacy_plain_export.csv")).resolve()
    if not legacy_path.exists():
        raise SystemExit(f"Legacy file not found: {legacy_path}")

    user_email = os.getenv("USER_EMAIL")
    if not user_email:
        raise SystemExit("USER_EMAIL env var is required (which user's vault to encrypt)")

    password = getpass(f"Enter master password for {user_email} (not stored): ")
    if not password:
        raise SystemExit("No password provided.")

    app = create_app()
    with app.app_context():
        salt = load_salt(user_email)
        key = derive_key(password, salt)

        legacy_rows = load_legacy(legacy_path)
        export_payloads = []
        for idx, row in enumerate(legacy_rows, start=1):
            site = (row.get("site") or row.get("Site") or "").strip()
            username = (row.get("username") or row.get("Username") or "").strip()
            pwd = (row.get("password") or row.get("Password") or "").strip()
            additional_raw = row.get("additional_fields") or row.get("Additional Fields") or ""
            additional_fields = row.get("additional_fields") if isinstance(row.get("additional_fields"), list) else parse_additional_fields(additional_raw)

            payload = {
                "site": site,
                "username": username,
                "password": pwd,
                "additional_fields": additional_fields,
                "categories": [],
            }
            encrypted_payload = encrypt_payload(key, payload)
            export_payloads.append(
                {
                    "id": idx,
                    "encrypted_payload": encrypted_payload,
                    "categories": [],
                    "date_added": datetime.now(timezone.utc).isoformat(),
                }
            )

        out_path = Path(__file__).resolve().parent / "passwords_export_encrypted.json"
        out_path.write_text(json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(), "passwords": export_payloads}, indent=2), encoding="utf-8")
        print(f"Wrote {len(export_payloads)} encrypted records to {out_path}")
        print("Import this via the app's Import flow (encrypted JSON).")


if __name__ == "__main__":
    main()
