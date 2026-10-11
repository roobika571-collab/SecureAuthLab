"""
database.py - Database Layer for SecureAuth Lab
Demonstrates:
  - SQLite database auto-initialization.
  - Parameterized queries to protect against SQL Injection (CWE-89).
  - Schema constraints (PRIMARY KEY, UNIQUE, NOT NULL, DEFAULT timestamps).
  - Security event audit logging for security monitoring & observability.
"""

import sqlite3
import os
from datetime import datetime

try:
    from flask import current_app, has_app_context
except ImportError:
    has_app_context = lambda: False
    current_app = None

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secureauth.db")


def get_db_path(custom_path=None):
    """Retrieve database path from parameter, Flask config, environment, or default."""
    if custom_path:
        return custom_path
    if has_app_context() and current_app and current_app.config.get("DATABASE_PATH"):
        return current_app.config["DATABASE_PATH"]
    return os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)


def get_db_connection(db_path=None):
    """
    Establish and return a SQLite database connection with row access by column name.
    """
    path = get_db_path(db_path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path=None):
    """
    Initialize database schema if tables do not exist.
    Tables:
      - users: stores user credentials (passwords hashed with Argon2id, NEVER plaintext).
      - audit_logs: stores chronological security events for cyber security auditing.
    """
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    with conn:
        # 1. Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0
            )
        """)

        # 2. Audit logs table (for SOC tracking & security review)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
    conn.close()


def create_user(name, email, password_hash, db_path=None):
    """
    Insert a newly registered user using parameterized queries.
    Returns the new user ID on success, or raises sqlite3.IntegrityError if email exists.
    """
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        with conn:
            cursor = conn.cursor()
            # SAFE: Parameterized query eliminates SQL Injection risks
            cursor.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (name.strip(), email.strip().lower(), password_hash)
            )
            return cursor.lastrowid
    finally:
        conn.close()


def get_user_by_email(email, db_path=None):
    """
    Retrieve user record by email (normalized).
    Safe parameterized query.
    """
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email, password_hash, created_at, last_login, failed_login_attempts FROM users WHERE email = ?",
            (email.strip().lower(),)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id, db_path=None):
    """
    Retrieve user record by ID.
    Does not return the password hash to caller functions unless specifically needed.
    """
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email, created_at, last_login FROM users WHERE id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def update_last_login(user_id, db_path=None):
    """Update last_login timestamp and reset failed attempts counter upon successful login."""
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        with conn:
            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            conn.execute(
                """
                UPDATE users
                SET last_login = ?, failed_login_attempts = 0
                WHERE id = ?
                """,
                (now_str, user_id)
            )
    finally:
        conn.close()


def record_audit_log(event_type, ip_address, user_id=None, user_agent=None, details=None, db_path=None):
    """
    Record an authentication/security event in the audit log.
    Captures: REGISTER_SUCCESS, LOGIN_SUCCESS, LOGIN_FAILURE, LOGOUT, RATE_LIMITED, SESSION_TIMEOUT.
    """
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, event_type, ip_address, user_agent, details)
            )
    except Exception:
        # In a security app, audit log failure should not crash user auth, but be logged
        pass
    finally:
        conn.close()


def get_recent_audit_logs(user_id=None, limit=8, db_path=None):
    """Fetch recent security audit logs for display on the dashboard or security page."""
    path = get_db_path(db_path)
    conn = get_db_connection(path)
    try:
        cursor = conn.cursor()
        if user_id:
            cursor.execute(
                """
                SELECT event_type, ip_address, details, created_at
                FROM audit_logs
                WHERE user_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (user_id, limit)
            )
        else:
            cursor.execute(
                """
                SELECT event_type, ip_address, details, created_at
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
