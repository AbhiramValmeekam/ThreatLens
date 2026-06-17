# ============================================================
# Authentication Utilities — Cryptography & Tokens
# ============================================================
"""
Provides password hashing and custom signed session token generation
using standard library functions to avoid external dependencies.
"""

import os
import hmac
import hashlib
import base64
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# JWT-like signed token secrets
SECRET_KEY = os.environ.get(
    "JWT_SECRET_KEY", "threatlens-super-secure-jwt-key-9876543210-abcdef"
)
ITERATIONS = 100000


# ─── Password Hashing ─────────────────────────────────────────

def hash_password(password: str) -> str:
    """
    Hash password using PBKDF2-SHA256.
    Returns: string format "pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>"
    """
    salt = os.urandom(16)
    salt_hex = salt.hex()
    pwd_bytes = password.encode("utf-8")
    
    dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, ITERATIONS)
    hash_hex = dk.hex()
    
    return f"pbkdf2_sha256${ITERATIONS}${salt_hex}${hash_hex}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a raw password against the stored PBKDF2 hash."""
    try:
        if not hashed.startswith("pbkdf2_sha256$"):
            return False
            
        parts = hashed.split("$")
        if len(parts) != 4:
            return False
            
        _, iterations_str, salt_hex, hash_hex = parts
        iterations = int(iterations_str)
        
        salt = bytes.fromhex(salt_hex)
        target_hash = bytes.fromhex(hash_hex)
        pwd_bytes = password.encode("utf-8")
        
        # Hash user input using same parameters
        dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations)
        
        # Time-constant comparison to prevent timing attacks
        return hmac.compare_digest(dk, target_hash)
    except Exception:
        return False


# ─── Custom Stateless Tokens ──────────────────────────────────

def create_access_token(data: Dict[str, Any], expires_delta_seconds: int = 86400) -> str:
    """
    Create a secure signed session token containing payload dictionary.
    Format: base64_payload.hex_signature
    """
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(seconds=expires_delta_seconds)
    payload["exp"] = expire.timestamp()
    
    # Serialize and encode payload
    payload_json = json.dumps(payload).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("utf-8")
    
    # Calculate signature
    signature = hmac.new(
        SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    return f"{payload_b64}.{signature}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify the signature and expiration of a session token."""
    try:
        if "." not in token:
            return None
            
        payload_b64, signature = token.split(".", 1)
        
        # Verify signature
        expected_signature = hmac.new(
            SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return None
            
        # Decode and load payload
        payload_json = base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8")
        payload = json.loads(payload_json)
        
        # Check expiration
        exp = payload.get("exp")
        if not exp or datetime.utcnow().timestamp() > exp:
            return None
            
        return payload
    except Exception:
        return None
