# 🛡️ SecureAuth Lab – Secure Authentication System

> **Cyber Security Task-2 Project** | Python · Flask · SQLite · Argon2id · Flask-Limiter

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1+-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Argon2id](https://img.shields.io/badge/Hashing-Argon2id-blueviolet?style=flat-square)](https://argon2-cffi.readthedocs.io)
[![Tests](https://img.shields.io/badge/Tests-15%20Passed-22c55e?style=flat-square)](#testing)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)

---

## 📋 Problem Statement

Most beginner authentication systems store passwords in plaintext, use no rate limiting, or leave sessions unprotected. **SecureAuth Lab** is a production-standard reference implementation that demonstrates every layer of modern authentication security, built as a complete full-stack web application for Cyber Security Task-2.

---

## ✨ Implemented Security Features

| # | Feature | Implementation |
|---|---------|----------------|
| 1 | **Argon2id Password Hashing** | RFC 9106 – 64 MiB memory, 2 iterations, resistant to GPU/ASIC attacks |
| 2 | **Server-Side Input Validation** | Regex, length limits, email normalization across all endpoints |
| 3 | **Parameterized SQL Queries** | 100% of DB operations use `?` placeholders – no SQL injection risk |
| 4 | **Login Rate Limiting** | Flask-Limiter: 5 attempts/minute per IP with HTTP 429 response |
| 5 | **Generic Auth Errors** | "Invalid email or password" – never reveals if account exists |
| 6 | **Timing Attack Defense** | Dummy Argon2id computation for non-existent users |
| 7 | **Secure Session Cookies** | HttpOnly=True, SameSite=Lax, Secure (configurable for HTTPS) |
| 8 | **Server-Side Inactivity Expiry** | Configurable timeout (default 20 min), enforced on every request |
| 9 | **Session Fixation Mitigation** | `session.clear()` before new session after successful login |
| 10 | **CSRF Protection** | Flask-WTF tokens on all state-changing POST requests |
| 11 | **Secure Logout** | Full session invalidation + cookie deletion + audit log |
| 12 | **Anti-Caching Headers** | `Cache-Control: no-store` prevents back-button dashboard access |
| 13 | **Security Audit Logging** | All auth events logged to SQLite with IP, user-agent, timestamp |
| 14 | **Clickjacking Defense** | `X-Frame-Options: DENY` header on all responses |

---

## 🖥️ Screenshots

### Login Page
> Dark navy glassmorphism design · Show/hide password · CSRF protected

### Registration Page
> Real-time password strength meter · Interactive criteria checklist · Server-validated

### Dashboard
> Live session countdown timer · Audit trail table · Security health status cards

### Security Specifications Page
> Full architecture breakdown · Evaluator testing guide · Code samples

---

## 🗂️ Project Structure

```
SecureAuthLab/
│
├── app.py                  ← Flask application (routes, config, session logic)
├── auth_service.py         ← Argon2id hashing, validation, timing defense
├── database.py             ← SQLite schema, parameterized queries, audit logs
│
├── requirements.txt        ← Python dependencies
├── .env.example            ← Environment variable template (safe to commit)
├── .gitignore              ← Excludes venv, .env, *.db, __pycache__
│
├── templates/
│   ├── base.html           ← Navigation, flash alerts, footer, security badges
│   ├── login.html          ← Login form with CSRF token and show/hide password
│   ├── register.html       ← Registration with live strength meter + checklist
│   ├── dashboard.html      ← Protected: session timer, profile, audit log
│   ├── security.html       ← Security specifications & evaluator testing guide
│   └── error_429.html      ← Rate limit exceeded page
│
├── static/
│   ├── css/style.css       ← Glassmorphism cybersecurity dark theme
│   └── js/main.js          ← Vanilla JS: toggles, strength meter, countdown
│
└── tests/
    └── test_auth.py        ← 15 automated security verification tests
```

---

## ⚙️ Setup Instructions (Windows / VS Code)

### Prerequisites
- Python 3.10+ installed ([download](https://python.org))
- Git installed ([download](https://git-scm.com))
- VS Code ([download](https://code.visualstudio.com))

### Step-by-Step Setup

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/SecureAuthLab.git
cd SecureAuthLab
```

**2. Create a Python virtual environment**
```bash
python -m venv venv
```

**3. Activate the virtual environment**
```bash
# Windows PowerShell
.\venv\Scripts\Activate.ps1

# Windows Command Prompt
venv\Scripts\activate.bat
```

**4. Install all dependencies**
```bash
pip install -r requirements.txt
```

**5. Configure environment variables**
```bash
# Copy the example file
copy .env.example .env

# Open .env in VS Code and update SECRET_KEY with a strong random value:
# python -c "import secrets; print(secrets.token_hex(32))"
```

**6. Start the Flask development server**
```bash
python app.py
```

**7. Open the application in your browser**
```
http://127.0.0.1:5000
```

> ✅ The SQLite database is created automatically on first run — no manual setup needed.

---

## 🔐 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto-generated | Flask session signing key — **change in production** |
| `SESSION_COOKIE_SECURE` | `False` | Set `True` when deploying over HTTPS |
| `SESSION_TIMEOUT_MINUTES` | `20` | Inactivity timeout before auto-logout |
| `LOGIN_RATE_LIMIT` | `5 per minute` | Max login attempts per IP per minute |
| `REGISTER_RATE_LIMIT` | `3 per minute` | Max registration attempts per IP per minute |
| `RATELIMIT_STORAGE_URI` | `memory://` | Use `redis://` in production multi-worker deployments |
| `DATABASE_PATH` | `secureauth.db` | Path to the SQLite database file |

> ⚠️ **Production Note:** The in-memory rate limit storage (`memory://`) only works correctly with a single worker process. For production deployments using Gunicorn with multiple workers, set `RATELIMIT_STORAGE_URI=redis://localhost:6379/0` so rate limits are shared across all workers.

---

## 🧪 Testing

Run the full automated test suite (15 tests):

```bash
# Activate venv first, then:
.\venv\Scripts\pytest.exe -v
```

### Test Results (All Passing ✅)

```
tests/test_auth.py::test_argon2id_hashing_parameters          PASSED
tests/test_auth.py::test_dummy_password_verification           PASSED
tests/test_auth.py::test_registration_success                  PASSED
tests/test_auth.py::test_duplicate_email_registration_rejected PASSED
tests/test_auth.py::test_registration_input_validation         PASSED
tests/test_auth.py::test_login_success                         PASSED
tests/test_auth.py::test_login_incorrect_password              PASSED
tests/test_auth.py::test_generic_auth_error_nonexistent_email  PASSED
tests/test_auth.py::test_unauthenticated_dashboard_redirect    PASSED
tests/test_auth.py::test_logout_invalidates_session            PASSED
tests/test_auth.py::test_anti_caching_headers                  PASSED
tests/test_auth.py::test_secure_cookie_attributes              PASSED
tests/test_auth.py::test_session_inactivity_expiry             PASSED
tests/test_auth.py::test_login_rate_limiting                   PASSED
tests/test_auth.py::test_csrf_protection_blocks_forged_requests PASSED

15 passed in 3.88s
```

> Tests use isolated temporary SQLite databases — they never touch production data or real credentials.

---

## 📋 Cyber Security Task-2 Requirement Checklist

| Requirement | Implementation | Test |
|-------------|---------------|------|
| ✅ Hash passwords (Argon2id) | `auth_service.py` – `hash_password()` | `test_argon2id_hashing_parameters` |
| ✅ Verify passwords securely | `auth_service.py` – `verify_password()` | `test_login_success` |
| ✅ Never store plaintext passwords | Checked in `create_user()`, hash only stored | `test_registration_success` |
| ✅ Never return hash to frontend | `get_user_by_id()` excludes hash field | Dashboard inspection |
| ✅ Email normalization | `normalize_email()` lowercases + strips | `test_duplicate_email_registration_rejected` |
| ✅ Server-side input validation | `validate_registration_payload()` | `test_registration_input_validation` |
| ✅ Parameterized SQL queries | All `database.py` queries use `?` placeholders | Code review |
| ✅ Generic auth error | "Invalid email or password" always returned | `test_generic_auth_error_nonexistent_email` |
| ✅ Timing attack mitigation | `verify_dummy_password()` for nonexistent users | `test_dummy_password_verification` |
| ✅ Login rate limiting | `@limiter.limit(get_login_rate_limit, methods=["POST"])` | `test_login_rate_limiting` |
| ✅ HTTP 429 on limit breach | Custom `error_429.html` handler | `test_login_rate_limiting` |
| ✅ HttpOnly cookies | `SESSION_COOKIE_HTTPONLY = True` | `test_secure_cookie_attributes` |
| ✅ SameSite cookies | `SESSION_COOKIE_SAMESITE = "Lax"` | `test_secure_cookie_attributes` |
| ✅ Secure flag (HTTPS-ready) | Configurable via `SESSION_COOKIE_SECURE` env | `.env.example` |
| ✅ Session inactivity expiry | `enforce_inactivity_timeout()` before_request hook | `test_session_inactivity_expiry` |
| ✅ Session fixation mitigation | `session.clear()` before login assignment | `test_logout_invalidates_session` |
| ✅ CSRF protection | Flask-WTF tokens on all POST forms | `test_csrf_protection_blocks_forged_requests` |
| ✅ Secure logout | `/logout` clears session + deletes cookie + audit log | `test_logout_invalidates_session` |
| ✅ Anti-caching headers | `Cache-Control: no-store` after_request hook | `test_anti_caching_headers` |
| ✅ No localStorage credentials | JS only reads `/api/session-status` endpoint | `main.js` code review |
| ✅ Secret key in env variable | Loaded via `python-dotenv` from `.env` | `.env.example` |
| ✅ Audit logging | `audit_logs` SQLite table, all auth events | Dashboard UI |
| ✅ Protected dashboard | `@login_required` decorator | `test_unauthenticated_dashboard_redirect` |
| ✅ Auto database creation | `init_db()` called at startup | App startup |

---

## 🔧 Manual Security Verification Guide

### 1. Test Rate Limiting
Submit 6+ failed login attempts within 60 seconds → HTTP 429 page appears.

### 2. Inspect Cookie Security
Open **Browser DevTools** (F12) → **Application** → **Cookies** → Look for `session` cookie with ✅ HttpOnly and SameSite=Lax.

### 3. Test Logout Invalidation  
Login → visit Dashboard → Logout → press Browser Back → Dashboard will NOT load (no-store cache headers prevent it).

### 4. Verify No Plaintext Passwords
Register → open `secureauth.db` with SQLite Browser → `users` table → `password_hash` column starts with `$argon2id$`.

### 5. Run Full Test Suite
```bash
.\venv\Scripts\pytest.exe -v
```

---

## ⚠️ Known Limitations

| Limitation | Details |
|-----------|---------|
| **Single-worker rate limiting** | In-memory limiter is per-process; use Redis in production with multiple workers |
| **Development HTTPS** | `SESSION_COOKIE_SECURE=False` for local HTTP — must be `True` in production HTTPS |
| **SQLite for demo** | SQLite is single-file; production deployments should migrate to PostgreSQL or MySQL |
| **No account lockout** | Rate limiting is per-IP; a distributed attack from multiple IPs requires WAF/CDN protection |
| **No 2FA/MFA** | Multi-factor authentication is not implemented in this Task-2 scope |

---

## 🛠️ Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend | Python + Flask | 3.11 / 3.1+ |
| Database | SQLite | Built-in |
| Password Hashing | argon2-cffi (Argon2id) | 25.1.0 |
| Rate Limiting | Flask-Limiter | 4.1.1 |
| CSRF Protection | Flask-WTF | 1.3.0 |
| Env Config | python-dotenv | 1.2.0 |
| Testing | pytest | 9.1.1 |
| Frontend | HTML5 + CSS3 + Vanilla JS | — |

---

## 📸 How to Take Screenshots for Submission

1. Run the app: `python app.py`
2. Open `http://127.0.0.1:5000` in your browser
3. Take screenshots of:
   - Login page (`/login`)
   - Register page (`/register`)
   - Dashboard after login (`/dashboard`)
   - Security specs page (`/security`)
   - Rate limit page (submit 6 bad logins quickly)
   - Browser DevTools → Application → Cookies (showing HttpOnly)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

Built for **Cyber Security Task-2** using Python Flask, demonstrating production-grade authentication security engineering.

> *"Security is not a product, but a process."* — Bruce Schneier
