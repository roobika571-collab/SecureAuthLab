"""
app.py - SecureAuth Lab Main Application
Cyber Security Task-2: Secure Authentication System

Features:
  1. Argon2id Password Hashing (resistant to GPU, ASIC, & timing side-channel attacks).
  2. Strict Server-Side Input Validation & Email Normalization.
  3. Login & Registration Rate Limiting (Flask-Limiter) to mitigate brute-force.
  4. Secure Session Management (HttpOnly, SameSite, Secure flags, server-side inactivity expiry).
  5. Session Fixation Mitigation (session regeneration / clear on auth).
  6. CSRF Protection (Flask-WTF).
  7. Anti-Caching Headers (prevents sensitive page exposure via browser history/back button).
  8. Generic Authentication Error Responses (prevents user enumeration).
"""

import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError

from auth_service import (
    hash_password,
    normalize_email,
    validate_registration_payload,
    verify_dummy_password,
    verify_password,
)
from database import (
    create_user,
    get_recent_audit_logs,
    get_user_by_email,
    get_user_by_id,
    init_db,
    record_audit_log,
    update_last_login,
)

# Load environment variables from .env if present
load_dotenv()

app = Flask(__name__)

# --- Cryptographic & Session Configuration ---
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", secrets.token_hex(32)
)

# Cookie Security attributes
# HttpOnly: Blocks JavaScript access to document.cookie (mitigates XSS cookie theft)
app.config["SESSION_COOKIE_HTTPONLY"] = True

# SameSite='Lax': Restricts cookie sharing across third-party contexts (mitigates CSRF)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Secure: Requires HTTPS when enabled; False during local HTTP development
# Controlled via environment variable SESSION_COOKIE_SECURE
is_secure_cookie = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
app.config["SESSION_COOKIE_SECURE"] = is_secure_cookie

# Session Lifetime & Inactivity Policy
SESSION_TIMEOUT_MINUTES = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "20"))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)
app.config["SESSION_REFRESH_EACH_REQUEST"] = True

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiter setup (Flask-Limiter)
# Default rate limits apply globally; sensitive endpoints have stricter policies
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["120 per hour", "30 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "5 per minute")
REGISTER_RATE_LIMIT = os.environ.get("REGISTER_RATE_LIMIT", "3 per minute")

def get_login_rate_limit():
    return app.config.get("LOGIN_RATE_LIMIT", LOGIN_RATE_LIMIT)

def get_register_rate_limit():
    return app.config.get("REGISTER_RATE_LIMIT", REGISTER_RATE_LIMIT)

# Initialize database tables on startup
init_db()


# --- Security Decorators & Context Processors ---

def login_required(f):
    """Decorator ensuring that only authenticated users can access the endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Authentication required. Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_security_meta():
    """Inject security configuration status into Jinja templates for user transparency."""
    return {
        "security_info": {
            "hashing_algo": "Argon2id (RFC 9106)",
            "memory_cost": "64 MiB",
            "time_cost": "2 iterations",
            "cookie_httponly": app.config["SESSION_COOKIE_HTTPONLY"],
            "cookie_samesite": app.config["SESSION_COOKIE_SAMESITE"],
            "cookie_secure": app.config["SESSION_COOKIE_SECURE"],
            "session_timeout_min": SESSION_TIMEOUT_MINUTES,
            "csrf_enabled": True,
            "rate_limits": {
                "login": LOGIN_RATE_LIMIT,
                "register": REGISTER_RATE_LIMIT,
            },
        }
    }


# --- Inactivity Session Expiry Enforcement ---

@app.before_request
def enforce_inactivity_timeout():
    """
    Enforces server-side session inactivity expiration on every request.
    If the user has been inactive longer than the configured timeout,
    the session is destroyed and the user is redirected to the login page.
    """
    if "user_id" in session:
        now = time.time()
        last_active = session.get("last_active", now)
        timeout_seconds = session.get(
            "timeout_seconds", SESSION_TIMEOUT_MINUTES * 60
        )

        if now - last_active > timeout_seconds:
            user_id = session.get("user_id")
            record_audit_log(
                "SESSION_EXPIRED",
                request.remote_addr,
                user_id=user_id,
                user_agent=request.headers.get("User-Agent"),
                details=f"Inactivity timeout ({timeout_seconds // 60}m) reached."
            )
            session.clear()
            flash("Your session has expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for("login"))

        # Update last active timestamp
        session["last_active"] = now


# --- Anti-Caching & Defensive HTTP Headers ---

@app.after_request
def apply_security_headers(response):
    """
    Applies defensive HTTP headers to prevent page caching, frame embedding (clickjacking),
    and MIME-type sniffing.
    """
    # Prevent browser caching of sensitive authenticated content (back-button vulnerability)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"

    # MIME sniffing protection
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Referrer policy to prevent sensitive URL leakage
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Restrict permissions
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    return response


# --- Error Handlers ---

@app.errorhandler(429)
def ratelimit_exceeded(e):
    """Handles rate-limiting threshold breaches (HTTP 429)."""
    ip = request.remote_addr
    record_audit_log(
        "RATE_LIMIT_EXCEEDED",
        ip,
        user_agent=request.headers.get("User-Agent"),
        details=f"Endpoint: {request.path} | Reason: {e.description}"
    )

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "status": "error",
            "code": 429,
            "message": "Too many requests. Rate limit exceeded. Please wait a moment before trying again."
        }), 429

    return render_template(
        "error_429.html",
        description=e.description,
        limit_policy="5 attempts/minute for login, 3 attempts/minute for registration"
    ), 429


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handles Cross-Site Request Forgery token errors."""
    ip = request.remote_addr
    record_audit_log(
        "CSRF_VIOLATION",
        ip,
        user_agent=request.headers.get("User-Agent"),
        details=f"Description: {e.description}"
    )

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "status": "error",
            "code": 400,
            "message": "CSRF token validation failed. Refresh the page and try again."
        }), 400

    flash("Security Alert: Invalid or missing CSRF token. Please refresh the page and try again.", "error")
    return redirect(request.referrer or url_for("login"))


# --- Application Routes ---

@app.route("/")
def index():
    """Root route: Redirect to dashboard if logged in, otherwise login page."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(get_login_rate_limit, methods=["POST"])
def login():
    """
    Login endpoint:
      - Validates user credentials.
      - Uses constant-time dummy verification when email is absent (timing attack prevention).
      - Returns generic error messages (user enumeration mitigation).
      - Regenerates session upon authentication (session fixation mitigation).
      - Configures session lifetime based on 'remember_me' option.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email_raw = request.form.get("email", "")
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "on"

        clean_email = normalize_email(email_raw)
        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        # Basic input sanity check
        if not clean_email or not password:
            flash("Invalid email or password.", "error")
            return render_template("login.html", email_val=clean_email), 401

        # Look up user in database via safe parameterized query
        user = get_user_by_email(clean_email)

        # Authenticate with timing attack defense
        authenticated = False
        if user:
            authenticated = verify_password(user["password_hash"], password)
        else:
            # Perform dummy verification so timing matches real password verification
            verify_dummy_password(password)

        if not authenticated:
            record_audit_log(
                "LOGIN_FAILURE",
                ip,
                user_id=user["id"] if user else None,
                user_agent=user_agent,
                details=f"Failed attempt for email identifier: {clean_email[:3]}***@{clean_email.split('@')[-1] if '@' in clean_email else 'invalid'}"
            )
            # GENERIC ERROR: Never indicate whether email or password was wrong
            flash("Invalid email or password.", "error")
            return render_template("login.html", email_val=clean_email), 401

        # --- Authentication Succeeded ---
        # Session Fixation Defense: Completely purge existing session before setting new auth data
        session.clear()

        # Populate fresh session
        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        session["last_active"] = time.time()

        if remember_me:
            # Extended session (7 days)
            session.permanent = True
            session["timeout_seconds"] = 7 * 24 * 60 * 60
        else:
            session.permanent = False
            session["timeout_seconds"] = SESSION_TIMEOUT_MINUTES * 60

        # Update last login timestamp in DB
        update_last_login(user["id"])

        record_audit_log(
            "LOGIN_SUCCESS",
            ip,
            user_id=user["id"],
            user_agent=user_agent,
            details=f"Authenticated via Argon2id. RememberMe={remember_me}"
        )

        flash(f"Welcome back, {user['name']}! Authenticated securely.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", email_val="")


@app.route("/register", methods=["GET", "POST"])
@limiter.limit(get_register_rate_limit, methods=["POST"])
def register():
    """
    Registration endpoint:
      - Validates all input data server-side (length, format, regex).
      - Checks password complexity.
      - Enforces email uniqueness (avoids duplicates).
      - Hashes password using Argon2id.
      - Never logs or stores plaintext passwords.
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "")
        email_raw = request.form.get("email", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        clean_email = normalize_email(email_raw)
        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent")

        # 1. Server-side validation
        is_valid, errors = validate_registration_payload(name, clean_email, password, confirm_password)

        if not is_valid:
            for field, err_msg in errors.items():
                flash(err_msg, "error")
            return render_template(
                "register.html",
                name_val=name,
                email_val=clean_email,
                field_errors=errors
            ), 400

        # 2. Check for duplicate account
        existing_user = get_user_by_email(clean_email)
        if existing_user:
            flash("An account with this email address already exists. Please log in or use another email.", "error")
            return render_template(
                "register.html",
                name_val=name,
                email_val=clean_email,
                field_errors={"email": "Email is already registered."}
            ), 400

        # 3. Hash password using Argon2id
        pw_hash = hash_password(password)

        # 4. Insert into database using parameterized query
        try:
            new_user_id = create_user(name, clean_email, pw_hash)
            record_audit_log(
                "REGISTER_SUCCESS",
                ip,
                user_id=new_user_id,
                user_agent=user_agent,
                details="New user registered with Argon2id hash."
            )
            flash("Registration successful! Your account is created with Argon2id protection. Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash("An error occurred during account creation. Please try again.", "error")
            return render_template("register.html", name_val=name, email_val=clean_email), 500

    return render_template("register.html", name_val="", email_val="", field_errors={})


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Protected user dashboard:
      - Requires active, non-expired session.
      - Displays user profile and security health status.
      - Displays live session countdown and recent audit trail.
    """
    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        flash("User session invalid. Please log in again.", "warning")
        return redirect(url_for("login"))

    recent_logs = get_recent_audit_logs(user_id=user["id"], limit=6)

    # Compute remaining session time in seconds
    now = time.time()
    last_active = session.get("last_active", now)
    timeout_seconds = session.get("timeout_seconds", SESSION_TIMEOUT_MINUTES * 60)
    time_remaining_sec = max(0, int(timeout_seconds - (now - last_active)))

    return render_template(
        "dashboard.html",
        user=user,
        logs=recent_logs,
        time_remaining_sec=time_remaining_sec,
        session_timeout_min=timeout_seconds // 60
    )


@app.route("/security")
def security_info():
    """
    Security Architecture & Verification Page:
      - Details all implemented defensive security controls.
      - Explains Argon2id parameters, rate-limiting policies, and session flags.
      - Includes self-test verification checklists and instructions for reviewers.
    """
    is_authenticated = "user_id" in session
    return render_template("security.html", is_authenticated=is_authenticated)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Logout endpoint:
      - Completely purges server-side session.
      - Clears session cookies.
      - Records audit log.
      - Redirects to login with confirmation.
    """
    user_id = session.get("user_id")
    if user_id:
        record_audit_log(
            "LOGOUT",
            request.remote_addr,
            user_id=user_id,
            user_agent=request.headers.get("User-Agent"),
            details="User logged out cleanly."
        )

    # Completely clear session data
    session.clear()

    flash("You have been securely logged out. Session terminated.", "info")
    response = redirect(url_for("login"))

    # Explicitly instruct client to clear cookies
    response.delete_cookie(app.config.get("SESSION_COOKIE_NAME", "session"))
    return response


@app.route("/api/session-status")
@login_required
def session_status():
    """
    API endpoint returning session status and remaining inactivity seconds
    for the live JavaScript countdown and auto-logout prompt.
    """
    now = time.time()
    last_active = session.get("last_active", now)
    timeout_seconds = session.get("timeout_seconds", SESSION_TIMEOUT_MINUTES * 60)
    remaining = max(0, int(timeout_seconds - (now - last_active)))

    return jsonify({
        "authenticated": True,
        "seconds_remaining": remaining,
        "timeout_seconds": timeout_seconds,
        "user_name": session.get("user_name"),
        "user_email": session.get("user_email")
    })


if __name__ == "__main__":
    # In development mode; for production, use a WSGI server such as gunicorn or waitress
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
