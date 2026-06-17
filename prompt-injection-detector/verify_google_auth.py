"""Verification script for testing the backend Google OAuth2 authentication route."""
import sys
import os
import json
import urllib.request
import urllib.parse
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api import verify_google_token
from src.database import init_db, get_user_by_email

print("=" * 60)
print("TESTING BACKEND GOOGLE AUTHENTICATION")
print("=" * 60)

# Initialize database
init_db()

# Test 1: verify_google_token mock verification
print("\n[1] Testing token verification with mock...")

mock_payload = {
    "email": "google_test_user@threatlens.com",
    "aud": "1036329437199-dummyclientid.apps.googleusercontent.com",
    "name": "Google Test User"
}

# Mock urllib.request to return mock payload
class MockResponse:
    def __init__(self, data):
        self.data = json.dumps(data).encode("utf-8")
    def read(self):
        return self.data
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def mock_urlopen(req, timeout=None):
    return MockResponse(mock_payload)

with patch("urllib.request.urlopen", mock_urlopen):
    verified_data = verify_google_token("mock-google-id-token-12345")
    print(f"  Verified Token Data: {verified_data}")
    assert verified_data is not None
    assert verified_data["email"] == "google_test_user@threatlens.com"
    print("  OK - Token verification passes")

# Test 2: Database registration/query of Google Users
print("\n[2] Testing Database operations for Google User...")
email = "google_test_user@threatlens.com"

# Clear user if exists
import sqlite3
from src.database import DB_PATH
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute("DELETE FROM users WHERE email=?", (email,))
conn.commit()
conn.close()

# Test FastAPI /api/auth/google logic
from api import app
from fastapi.testclient import TestClient

client = TestClient(app)

with patch("api.verify_google_token", return_value=mock_payload):
    response = client.post("/api/auth/google", json={"id_token": "mock-google-id-token-12345"})
    print(f"  FastAPI Response Status: {response.status_code}")
    print(f"  FastAPI Response Body: {response.json()}")
    
    assert response.status_code == 200
    assert "token" in response.json()
    assert response.json()["user"]["email"] == email

    # Verify user was saved in DB
    user = get_user_by_email(email)
    print(f"  Retrieved from DB: Email={user.email}, PwdHash={user.password_hash[:30]}...")
    assert user is not None
    assert user.email == email
    print("  OK - Database insertion & Session token creation works")

print("\n" + "=" * 60)
print("ALL GOOGLE AUTHENTICATION TESTS PASSED!")
print("=" * 60)
