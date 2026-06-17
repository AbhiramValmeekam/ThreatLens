"""Verification script for testing the backend authentication logic."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.auth_utils import hash_password, verify_password, create_access_token, verify_access_token
from src.database import init_db, create_user, get_user_by_email

print("=" * 60)
print("TESTING BACKEND AUTHENTICATION")
print("=" * 60)

# Test 1: Hashing & Verification
print("\n[1] Testing Hashing & Verification...")
password = "super-secret-password-123"
hashed = hash_password(password)
print(f"  Password: {password}")
print(f"  Hashed format: {hashed}")

verify_success = verify_password(password, hashed)
print(f"  Verification with correct pwd: {verify_success} (Expected: True)")
assert verify_success is True

verify_fail = verify_password("wrong-password", hashed)
print(f"  Verification with wrong pwd: {verify_fail} (Expected: False)")
assert verify_fail is False

# Test 2: Token Creation & Verification
print("\n[2] Testing Session Tokens...")
payload = {"sub": "user@example.com", "id": 42}
token = create_access_token(payload, expires_delta_seconds=5)
print(f"  Token generated: {token}")

decoded = verify_access_token(token)
print(f"  Decoded token: {decoded}")
assert decoded is not None
assert decoded["sub"] == "user@example.com"
assert decoded["id"] == 42

# Test 3: Database User creation and query
print("\n[3] Testing Database User integration...")
init_db()
email = "test_auth_user@threatlens.com"

# Clear user if exists
import sqlite3
from src.database import DB_PATH
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("DELETE FROM users WHERE email=?", (email,))
conn.commit()
conn.close()

user = create_user(email, hashed)
print(f"  Created user in DB: ID={user.id}, Email={user.email}")
assert user.id is not None
assert user.email == email

retrieved = get_user_by_email(email)
print(f"  Retrieved user from DB: ID={retrieved.id}, Email={retrieved.email}")
assert retrieved is not None
assert retrieved.id == user.id
assert verify_password(password, retrieved.password_hash) is True

print("\n" + "=" * 60)
print("ALL AUTHENTICATION TESTS PASSED!")
print("=" * 60)
