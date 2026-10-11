"""
auth_service.py - Authentication and Cryptographic Service Layer
Implements:
  - Argon2id password hashing & verification (resistant to GPU, ASIC, and side-channel attacks).
  - Timing attack mitigation using dummy hash computation for non-existent users.
  - Strict server-side input validation and email normalization.
  - Password complexity verification against cyber security standards.
"""

import re
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Configure Argon2id hasher following OWASP & RFC 9106 guidelines
# Type.ID combines Argon2d (data-dependent) and Argon2i (data-independent) to resist side-channels & GPU crackers
hasher = PasswordHasher(
    time_cost=2,            # 2 iterations
    memory_cost=65536,      # 64 MiB RAM requirement
    parallelism=1,          # 1 lane
    hash_len=32,            # 32-byte output
    type=Type.ID
)

# Dummy hash for constant-time authentication (mitigates email enumeration via timing side-channels)
# When an email does not exist in the DB, the backend verifies against this dummy hash
# so response times are indistinguishable between existent and non-existent accounts.
DUMMY_HASH = hasher.hash("SecureAuthLabDummyPasswordForTimingMitigation2026!")

# RFC-compliant email regex pattern
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*(?:\.[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*)+$"
)

# Allowed name characters: letters, spaces, hyphens, and single quotes
NAME_REGEX = re.compile(r"^[A-Za-z\s'-]{2,60}$")


def hash_password(plaintext_password: str) -> str:
    """
    Hash a plaintext password using Argon2id.
    Never stores or logs the plaintext password.
    """
    if not isinstance(plaintext_password, str) or not plaintext_password:
        raise ValueError("Password must be a non-empty string.")
    return hasher.hash(plaintext_password)


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """
    Verify candidate password against stored Argon2id hash.
    Returns True if valid, False otherwise.
    Never exposes internal hash or exceptions.
    """
    if not stored_hash or not candidate_password:
        return False
    try:
        return hasher.verify(stored_hash, candidate_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy_password(candidate_password: str) -> bool:
    """
    Runs Argon2id verification against dummy hash to maintain constant response timing
    even when an email does not exist in the database.
    Always returns False.
    """
    try:
        hasher.verify(DUMMY_HASH, candidate_password or "dummy")
    except Exception:
        pass
    return False


def normalize_email(email: str) -> str:
    """
    Normalize email address to avoid duplicate accounts via case or whitespace variance.
    e.g., '  User@Example.COM  ' -> 'user@example.com'
    """
    if not email:
        return ""
    return email.strip().lower()


def validate_name(name: str) -> tuple[bool, str]:
    """Validate user full name."""
    if not name or not name.strip():
        return False, "Full name is required."
    clean_name = name.strip()
    if len(clean_name) < 2:
        return False, "Full name must be at least 2 characters long."
    if len(clean_name) > 60:
        return False, "Full name cannot exceed 60 characters."
    if not NAME_REGEX.match(clean_name):
        return False, "Full name can only contain letters, spaces, hyphens, and apostrophes."
    return True, ""


def validate_email(email: str) -> tuple[bool, str]:
    """Validate email format and length."""
    if not email or not email.strip():
        return False, "Email address is required."
    clean_email = normalize_email(email)
    if len(clean_email) > 120:
        return False, "Email address is too long (maximum 120 characters)."
    if not EMAIL_REGEX.match(clean_email):
        return False, "Please enter a valid email address (e.g., user@example.com)."
    return True, ""


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password against modern cybersecurity complexity rules:
      - Minimum 8 characters, maximum 128 characters
      - At least one uppercase letter (A-Z)
      - At least one lowercase letter (a-z)
      - At least one numerical digit (0-9)
      - At least one special symbol (!@#$%^&* etc.)
    """
    errors = []
    if not password:
        return False, ["Password is required."]

    if len(password) < 8:
        errors.append("Must be at least 8 characters long.")
    if len(password) > 128:
        errors.append("Cannot exceed 128 characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must include at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        errors.append("Must include at least one lowercase letter (a-z).")
    if not re.search(r"[0-9]", password):
        errors.append("Must include at least one number (0-9).")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\\\/\[\]~`]', password):
        errors.append("Must include at least one special character (!@#$%^&* etc.).")

    return (len(errors) == 0), errors


def validate_registration_payload(name: str, email: str, password: str, confirm_password: str) -> tuple[bool, dict]:
    """
    Comprehensive server-side validation for user registration.
    Returns (is_valid, field_errors_dict).
    """
    field_errors = {}

    # 1. Validate name
    valid_name, name_err = validate_name(name)
    if not valid_name:
        field_errors["name"] = name_err

    # 2. Validate email
    valid_email, email_err = validate_email(email)
    if not valid_email:
        field_errors["email"] = email_err

    # 3. Validate password strength
    valid_pw, pw_errors = validate_password_strength(password)
    if not valid_pw:
        field_errors["password"] = " ".join(pw_errors)

    # 4. Check confirm password match
    if not confirm_password:
        field_errors["confirm_password"] = "Please confirm your password."
    elif password != confirm_password:
        field_errors["confirm_password"] = "Passwords do not match."

    return (len(field_errors) == 0), field_errors
