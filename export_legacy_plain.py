"""
One-off helper to export legacy password entries that were stored with the old
server-side Fernet key. This produces plaintext JSON and CSV locally so you can
re-enter them in the new zero-knowledge UI and get them re-encrypted client-side.

Usage:
    python export_legacy_plain.py

Outputs (in project root):
    legacy_plain_export.json
    legacy_plain_export.csv

Safety:
    - Reads using the old ENCRYPTION_KEY from your .env; does not modify the database.
    - Delete the generated files after you re-import via the UI.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

from project import create_app, db
from project.models import Passwords


def _normalize_to_bytes(token: Any) -> bytes | None:
    if token is None:
        return None
    if isinstance(token, bytes):
        return token
    if isinstance(token, memoryview):
        return bytes(token)
    if isinstance(token, str) and token.startswith("\\x") and len(token) > 2:
        try:
            return bytes.fromhex(token[2:])
        except ValueError:
            return token.encode()
    return str(token).encode()


def decrypt_or_plain(cipher: Fernet, token: Any) -> str:
    token_bytes = _normalize_to_bytes(token)
    if token_bytes is None:
        return ""
    try:
        return cipher.decrypt(token_bytes).decode()
    except InvalidToken:
        try:
            return token_bytes.decode(errors="ignore")
        except Exception:
            return str(token)


def decrypt_json_or_empty(cipher: Fernet, token: Any) -> list[dict[str, str]]:
    token_bytes = _normalize_to_bytes(token)
    if token_bytes is None:
        return []
    try:
        decrypted = cipher.decrypt(token_bytes).decode()
        return json.loads(decrypted)
    except Exception:
        return []


def export_legacy(cipher: Fernet):
    entries = db.session.execute(db.select(Passwords)).scalars().all()
    exported = []
    for entry in entries:
        # Only consider rows that still have legacy plaintext/fernet columns populated
        if entry.encrypted_payload:
            continue

        exported.append(
            {
                "id": entry.id,
                "site": entry.site or "",
                "username": decrypt_or_plain(cipher, entry.username),
                "password": decrypt_or_plain(cipher, entry.password),
                "additional_fields": decrypt_json_or_empty(cipher, entry.additional_fields),
            }
        )
    return exported


def write_json(path: Path, data: list[dict]):
    path.write_text(json.dumps({"passwords": data, "count": len(data)}, indent=2), encoding="utf-8")


def write_csv(path: Path, data: list[dict]):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Site", "Username", "Password", "Additional Fields"])
        for row in data:
            fields = row.get("additional_fields") or []
            fields_str = "; ".join(f"{field.get('label')}: {field.get('value')}" for field in fields)
            writer.writerow([row.get("site", ""), row.get("username", ""), row.get("password", ""), fields_str])


def main():
    load_dotenv()
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        raise SystemExit("ENCRYPTION_KEY not set in environment/.env")

    cipher = Fernet(key.encode())
    app = create_app()

    root = Path(__file__).resolve().parent
    json_path = root / "legacy_plain_export.json"
    csv_path = root / "legacy_plain_export.csv"

    with app.app_context():
        data = export_legacy(cipher)
        write_json(json_path, data)
        write_csv(csv_path, data)
        print(f"Exported {len(data)} legacy rows to:")
        print(f"  {json_path}")
        print(f"  {csv_path}")
        print("Delete these files after re-importing/re-entering data via the UI.")


if __name__ == "__main__":
    main()
