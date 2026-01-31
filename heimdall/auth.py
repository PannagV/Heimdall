import hashlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import bcrypt
import jwt

from .config import DEFAULT_CONFIG

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(ts: Optional[datetime] = None) -> str:
    ts = ts or now_utc()
    return ts.isoformat().replace("+00:00", "Z")


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, role: str) -> str:
    issued_at = int(time.time())
    lifetime = int(DEFAULT_CONFIG["access_token_minutes"]) * 60
    payload = {
        "sub": user_id,
        "role": role,
        "iat": issued_at,
        "exp": issued_at + lifetime,
        "iss": DEFAULT_CONFIG["jwt_issuer"],
    }
    return jwt.encode(payload, DEFAULT_CONFIG["jwt_secret"], algorithm="HS256")


def hash_refresh_token(token: str) -> str:
    raw = f"{token}{DEFAULT_CONFIG['refresh_token_secret']}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def issue_tokens(user_id: str, role: str) -> TokenPair:
    access_token = create_access_token(user_id, role)
    refresh_token = generate_refresh_token()
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


def store_refresh_token(refresh_collection, user_id: str, refresh_token: str) -> None:
    expires_at = now_utc() + timedelta(days=int(DEFAULT_CONFIG["refresh_token_days"]))
    refresh_collection.insert_one(
        {
            "token_hash": hash_refresh_token(refresh_token),
            "user_id": user_id,
            "created_at": utc_iso(),
            "expires_at": utc_iso(expires_at),
            "revoked": False,
            "last_used_at": None,
        }
    )


def rotate_refresh_token(refresh_collection, token_hash: str) -> str:
    refresh_collection.update_one(
        {"token_hash": token_hash},
        {"$set": {"revoked": True, "revoked_at": utc_iso()}},
    )
    new_token = generate_refresh_token()
    return new_token


def is_role_allowed(user_role: str, required_role: str) -> bool:
    return ROLE_ORDER.get(user_role, 0) >= ROLE_ORDER.get(required_role, 0)


def log_auth_event(audit_collection, user_id: Optional[str], action: str, success: bool, source_ip: str) -> None:
    if audit_collection is None:
        return
    audit_collection.insert_one(
        {
            "user_id": user_id,
            "action": action,
            "success": success,
            "source_ip": source_ip,
            "timestamp": utc_iso(),
        }
    )


def get_user_by_refresh(refresh_collection, users_collection, refresh_token: str) -> Optional[Dict]:
    token_hash = hash_refresh_token(refresh_token)
    record = refresh_collection.find_one({"token_hash": token_hash, "revoked": False})
    if not record:
        return None
    expires_at = record.get("expires_at")
    if expires_at and expires_at < utc_iso():
        return None
    user_id = record.get("user_id")
    if not user_id:
        return None
    user = users_collection.find_one({"user_id": user_id})
    return user


def validate_jwt(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(
            token,
            DEFAULT_CONFIG["jwt_secret"],
            algorithms=["HS256"],
            issuer=DEFAULT_CONFIG["jwt_issuer"],
        )
        return payload
    except Exception:
        return None
