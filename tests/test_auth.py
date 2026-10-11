"""
tests/test_auth.py - Comprehensive Automated Verification Suite
SecureAuth Lab - Cyber Security Task-2 Project

Tests all mandatory requirements:
  1. Successful user registration.
  2. Password hashing with Argon2id parameters (RFC 9106, 64MB RAM).
  3. Rejection of missing, weak, or invalid inputs.
  4. Duplicate email prevention & normalization.
  5. Successful login with valid credentials.
  6. Rejection of incorrect password.
  7. Generic authentication errors & timing attack mitigation.
  8. Login rate limiting (HTTP 429).
  9. Protected dashboard access control (unauthenticated rejection).
 10. Secure logout & session invalidation.
 11. Anti-caching HTTP headers (back-button mitigation).
 12. Session inactivity expiry enforcement.
 13. Secure cookie attributes (HttpOnly, SameSite).
 14. CSRF protection verification.
"""

import os
import re
import tempfile
import time
import pytest

from app import app, limiter
from auth_service import (
    hash_password,
    verify_password,
    verify_dummy_password,
    validate_registration_payload,
)
import database


def reset_rate_limiter():
    """Helper to thoroughly reset the rate limiter state in memory."""
    try:
        limiter.reset()
    except Exception:
        pass
    if hasattr(limiter, "_storage"):
        storage = getattr(limiter, "_storage")
        if hasattr(storage, "storage") and hasattr(storage.storage, "clear"):
            storage.storage.clear()
        if hasattr(storage, "events") and hasattr(storage.events, "clear"):
            storage.events.clear()
        if hasattr(storage, "reset"):
            storage.reset()


@pytest.fixture
def test_env():
    """
    Creates an isolated temporary SQLite database and configures the test client.
    Cleans up after testing to guarantee zero test interference.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    # Set up test app configuration
    app.config["TESTING"] = True
    app.config["DATABASE_PATH"] = db_path
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["SECRET_KEY"] = "test_super_secure_secret_key_1234567890"
    app.config["LOGIN_RATE_LIMIT"] = "5 per minute"
    app.config["REGISTER_RATE_LIMIT"] = "20 per minute"

    # Reset limiter storage and initialize DB
    reset_rate_limiter()
    database.init_db(db_path)

    with app.test_client() as client:
        yield client, db_path

    # Teardown: Remove temporary database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


def get_csrf_token(client, url):
    """Helper to fetch a GET page and extract the rendered CSRF token from the form."""
    res = client.get(url)
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', res.get_data(as_text=True))
    if not match:
        match = re.search(r'name="csrf-token"\s+content="([^"]+)"', res.get_data(as_text=True))
    return match.group(1) if match else ""


# -----------------------------------------------------------------------------
# 1. Password Hashing & Cryptographic Primitives
# -----------------------------------------------------------------------------

def test_argon2id_hashing_parameters():
    """Verify that Argon2id is properly configured and hashes passwords securely."""
    password = "CorrectHorseBatteryStaple!9"
    hashed = hash_password(password)

    # Must start with $argon2id$ identifier
    assert hashed.startswith("$argon2id$")
    # Verify memory cost of 64MB (m=65536) and time cost 2 (t=2)
    assert "m=65536" in hashed
    assert "t=2" in hashed

    # Plaintext password must never appear in the hash
    assert password not in hashed

    # Verification function must succeed for matching password
    assert verify_password(hashed, password) is True
    # Verification function must fail for wrong password
    assert verify_password(hashed, "WrongPassword!9") is False


def test_dummy_password_verification():
    """Verify constant-time dummy verification behavior."""
    assert verify_dummy_password("AnyPassword123!") is False


# -----------------------------------------------------------------------------
# 2. Registration Flow & Validation
# -----------------------------------------------------------------------------

def test_registration_success(test_env):
    """Test successful user registration creates Argon2id hash in DB."""
    client, db_path = test_env
    reset_rate_limiter()
    csrf_token = get_csrf_token(client, "/register")

    response = client.post("/register", data={
        "csrf_token": csrf_token,
        "name": "SecOps Engineer",
        "email": "engineer@security-lab.local",
        "password": "ValidMasterKey@2026",
        "confirm_password": "ValidMasterKey@2026"
    }, follow_redirects=True)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Registration successful" in html

    # Verify user saved in DB
    user = database.get_user_by_email("engineer@security-lab.local", db_path)
    assert user is not None
    assert user["name"] == "SecOps Engineer"
    assert user["email"] == "engineer@security-lab.local"
    assert user["password_hash"].startswith("$argon2id$")
    assert "ValidMasterKey@2026" not in user["password_hash"]


def test_duplicate_email_registration_rejected(test_env):
    """Test that registering an existing email (even with different casing) is rejected."""
    client, db_path = test_env
    reset_rate_limiter()

    # First registration
    token1 = get_csrf_token(client, "/register")
    res1 = client.post("/register", data={
        "csrf_token": token1,
        "name": "First User",
        "email": "analyst@test.local",
        "password": "Password123!@",
        "confirm_password": "Password123!@"
    })
    assert res1.status_code in [200, 302]

    # Second registration with uppercase variance
    token2 = get_csrf_token(client, "/register")
    response = client.post("/register", data={
        "csrf_token": token2,
        "name": "Second User",
        "email": "ANALYST@TEST.LOCAL",
        "password": "Password123!@",
        "confirm_password": "Password123!@"
    }, follow_redirects=True)

    assert response.status_code == 400
    html = response.get_data(as_text=True)
    assert "already exists" in html


def test_registration_input_validation():
    """Verify server-side validation catches invalid inputs."""
    # Missing uppercase
    valid, errors = validate_registration_payload("Alice", "alice@test.local", "password123!", "password123!")
    assert not valid
    assert "uppercase" in errors.get("password", "")

    # Too short (< 8 chars)
    valid, errors = validate_registration_payload("Alice", "alice@test.local", "Short1!", "Short1!")
    assert not valid
    assert "at least 8" in errors.get("password", "")

    # Mismatched passwords
    valid, errors = validate_registration_payload("Alice", "alice@test.local", "StrongPass123!", "DifferentPass123!")
    assert not valid
    assert "Passwords do not match" in errors.get("confirm_password", "")

    # Malformed email
    valid, errors = validate_registration_payload("Alice", "not-an-email", "StrongPass123!", "StrongPass123!")
    assert not valid
    assert "valid email" in errors.get("email", "")


# -----------------------------------------------------------------------------
# 3. Authentication & Login
# -----------------------------------------------------------------------------

def test_login_success(test_env):
    """Test successful login redirects to dashboard and populates session."""
    client, db_path = test_env
    reset_rate_limiter()

    # Register user first
    token1 = get_csrf_token(client, "/register")
    client.post("/register", data={
        "csrf_token": token1,
        "name": "Bob Analyst",
        "email": "bob@soc.local",
        "password": "SecurePassword#99",
        "confirm_password": "SecurePassword#99"
    })

    # Attempt login
    token2 = get_csrf_token(client, "/login")
    response = client.post("/login", data={
        "csrf_token": token2,
        "email": "bob@soc.local",
        "password": "SecurePassword#99",
        "remember_me": "on"
    }, follow_redirects=True)

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Welcome" in html
    assert "Bob Analyst" in html
    assert "Session Inactivity Expiry" in html


def test_login_incorrect_password(test_env):
    """Test login rejection when password is wrong."""
    client, db_path = test_env
    reset_rate_limiter()

    # Register user
    token1 = get_csrf_token(client, "/register")
    client.post("/register", data={
        "csrf_token": token1,
        "name": "Charlie",
        "email": "charlie@soc.local",
        "password": "CorrectPassword!1",
        "confirm_password": "CorrectPassword!1"
    })

    # Login with wrong password
    token2 = get_csrf_token(client, "/login")
    response = client.post("/login", data={
        "csrf_token": token2,
        "email": "charlie@soc.local",
        "password": "WrongPassword!99"
    })

    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Invalid email or password." in html


def test_generic_auth_error_nonexistent_email(test_env):
    """Test that non-existent emails return the exact same generic error message."""
    client, db_path = test_env
    reset_rate_limiter()
    token = get_csrf_token(client, "/login")

    response = client.post("/login", data={
        "csrf_token": token,
        "email": "ghost.user@nonexistent.local",
        "password": "ArbitraryPassword!2026"
    })

    assert response.status_code == 401
    html = response.get_data(as_text=True)
    # Generic error: Never reveal if the email exists
    assert "Invalid email or password." in html
    assert "User not found" not in html
    assert "Email does not exist" not in html


# -----------------------------------------------------------------------------
# 4. Protected Routes, Session Control & Logout
# -----------------------------------------------------------------------------

def test_unauthenticated_dashboard_redirect(test_env):
    """Verify that unauthenticated users cannot access the dashboard."""
    client, db_path = test_env
    response = client.get("/dashboard", follow_redirects=False)

    # Must redirect to login
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_logout_invalidates_session(test_env):
    """Verify that logging out clears session and prevents access to dashboard."""
    client, db_path = test_env
    reset_rate_limiter()

    # Register and log in
    token1 = get_csrf_token(client, "/register")
    client.post("/register", data={
        "csrf_token": token1,
        "name": "Diana Prince",
        "email": "diana@test.local",
        "password": "AmazonianKey!2026",
        "confirm_password": "AmazonianKey!2026"
    })

    token2 = get_csrf_token(client, "/login")
    client.post("/login", data={
        "csrf_token": token2,
        "email": "diana@test.local",
        "password": "AmazonianKey!2026"
    })

    # Verify dashboard accessible
    dash_res = client.get("/dashboard")
    assert dash_res.status_code == 200

    # Extract CSRF token from dashboard logout form
    dash_csrf = get_csrf_token(client, "/dashboard")

    # Execute logout via POST with CSRF token
    logout_res = client.post("/logout", data={"csrf_token": dash_csrf}, follow_redirects=True)
    assert logout_res.status_code == 200
    assert "logged out" in logout_res.get_data(as_text=True).lower()

    # Verify dashboard is no longer accessible
    after_logout_dash = client.get("/dashboard", follow_redirects=False)
    assert after_logout_dash.status_code == 302
    assert "/login" in after_logout_dash.headers.get("Location", "")


def test_anti_caching_headers(test_env):
    """Verify anti-caching headers on all responses."""
    client, _ = test_env
    response = client.get("/login")

    cache_control = response.headers.get("Cache-Control", "")
    assert "no-store" in cache_control
    assert "no-cache" in cache_control
    assert "must-revalidate" in cache_control
    assert response.headers.get("Pragma") == "no-cache"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"


def test_secure_cookie_attributes():
    """Verify cookie security configuration settings."""
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_session_inactivity_expiry(test_env):
    """Simulate server-side session inactivity timeout."""
    client, db_path = test_env
    reset_rate_limiter()

    # Register and log in
    token1 = get_csrf_token(client, "/register")
    client.post("/register", data={
        "csrf_token": token1,
        "name": "Eve Operator",
        "email": "eve@operator.local",
        "password": "OperatorSecureKey!1",
        "confirm_password": "OperatorSecureKey!1"
    })

    token2 = get_csrf_token(client, "/login")
    client.post("/login", data={
        "csrf_token": token2,
        "email": "eve@operator.local",
        "password": "OperatorSecureKey!1"
    })

    # Manually simulate expired last_active timestamp in session
    with client.session_transaction() as sess:
        sess["last_active"] = time.time() - 3600  # 1 hour ago
        sess["timeout_seconds"] = 1200            # 20 min timeout

    # Next request must detect inactivity and redirect to login
    response = client.get("/dashboard", follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "session has expired due to inactivity" in html.lower()


# -----------------------------------------------------------------------------
# 5. Rate Limiting & CSRF Protection
# -----------------------------------------------------------------------------

def test_login_rate_limiting(test_env):
    """Verify that exceeding login attempt limits triggers HTTP 429 Too Many Requests."""
    client, _ = test_env
    reset_rate_limiter()
    app.config["LOGIN_RATE_LIMIT"] = "3 per minute"

    # Make 3 invalid login attempts (which return 401)
    for i in range(3):
        token = get_csrf_token(client, "/login")
        res = client.post("/login", data={
            "csrf_token": token,
            "email": "victim@test.local",
            "password": f"WrongAttempt{i}!1"
        })
        assert res.status_code == 401

    # 4th attempt should be blocked by rate limiter with 429
    token = get_csrf_token(client, "/login")
    res_4 = client.post("/login", data={
        "csrf_token": token,
        "email": "victim@test.local",
        "password": "WrongAttempt4!1"
    })

    assert res_4.status_code == 429
    assert "Rate Limit Exceeded" in res_4.get_data(as_text=True)


def test_csrf_protection_blocks_forged_requests(test_env):
    """Verify that POST requests without a valid CSRF token are blocked with HTTP 400."""
    client, _ = test_env
    reset_rate_limiter()

    # Attempt POST without CSRF token
    response = client.post("/login", data={
        "email": "attacker@evil.local",
        "password": "SomePassword123!"
    }, follow_redirects=False)

    # Must be rejected (either 400 Bad Request or redirect with alert)
    assert response.status_code in [400, 302]
