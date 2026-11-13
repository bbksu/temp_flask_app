
import os
import json

# Set the environment variable before importing app.py.
os.environ.setdefault("SECRET_KEY", "pytest-development-secret")

import pytest

from app import app, initialise_storage
from werkzeug.security import check_password_hash


# --------------------------------------------------
# 1. TEST CONFIGURATION
# --------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Configure an isolated Flask test environment.

    tmp_path provides a temporary directory.
    monkeypatch redirects JSON storage to that directory.

    Each test receives a clean JSON file.
    """

    test_data_file = tmp_path / "users.json"

    # Redirect the application away from its real JSON file.
    monkeypatch.setattr("app.DATA_FILE", test_data_file)

    # Configure Flask for testing.
    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SECRET_KEY="pytest-development-secret"
    )

    # Create an empty JSON database.
    initialise_storage()

    # Return Flask's built-in test client.
    with app.test_client() as test_client:
        yield test_client


# --------------------------------------------------
# 2. TEST DATA
# --------------------------------------------------

VALID_USER = {
    "full_name": "John Smith",
    "email": "john@example.com",
    "phone": "+27123456789",
    "date_of_birth": "2000-05-15",
    "password": "StrongPassword123"
}


def register_user(client, user_data=None):
    """
    Reusable registration helper.

    Allows individual tests to override specific fields
    without duplicating the entire registration process.
    """

    data = VALID_USER.copy()

    if user_data:
        data.update(user_data)

    return client.post(
        "/register",
        data=data,
        follow_redirects=True
    )


def login_user(client, email=None, password=None):
    """
    Reusable login helper.
    """

    return client.post(
        "/",
        data={
            "email": email or VALID_USER["email"],
            "password": password or VALID_USER["password"]
        },
        follow_redirects=True
    )


def read_test_users():
    """
    Read the isolated test JSON file.

    The application module's DATA_FILE has been redirected
    by the client fixture.
    """

    from app import DATA_FILE

    with DATA_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)["users"]


# --------------------------------------------------
# 3. REGISTRATION PAGE TESTS
# --------------------------------------------------

def test_registration_page_loads(client):
    """TC-001: Registration page should load successfully."""

    response = client.get("/register")

    assert response.status_code == 200
    assert b"Create an Account" in response.data


def test_valid_registration(client):
    """TC-002: Valid registration should create a JSON record."""

    response = register_user(client)

    users = read_test_users()

    assert response.status_code == 200
    assert len(users) == 1
    assert users[0]["email"] == "john@example.com"
    assert users[0]["full_name"] == "John Smith"


def test_empty_name_rejected(client):
    """TC-003: Empty full name should be rejected."""

    response = register_user(
        client,
        {"full_name": ""}
    )

    assert b"Full name is required." in response.data
    assert len(read_test_users()) == 0


def test_invalid_email_rejected(client):
    """TC-004: Invalid email should be rejected."""

    response = register_user(
        client,
        {"email": "invalid-email"}
    )

    assert b"Enter a valid email address." in response.data
    assert len(read_test_users()) == 0


def test_duplicate_email_rejected(client):
    """TC-005: Duplicate email should be rejected."""

    register_user(client)

    response = register_user(
        client,
        {"full_name": "Jane Smith"}
    )

    assert b"already registered" in response.data
    assert len(read_test_users()) == 1


def test_invalid_phone_rejected(client):
    """TC-006: Invalid phone number should be rejected."""

    response = register_user(
        client,
        {"phone": "abc123"}
    )

    assert b"Enter a valid phone number." in response.data
    assert len(read_test_users()) == 0


def test_short_password_rejected(client):
    """TC-007: Password shorter than 12 characters rejected."""

    response = register_user(
        client,
        {"password": "short"}
    )

    assert b"at least 12 characters" in response.data
    assert len(read_test_users()) == 0


def test_password_is_hashed(client):
    """TC-008: Plain-text password must not be stored."""

    register_user(client)

    users = read_test_users()

    stored_password = users[0]["password_hash"]

    assert stored_password != VALID_USER["password"]

    assert check_password_hash(
        stored_password,
        VALID_USER["password"]
    )


# --------------------------------------------------
# 4. LOGIN TESTS
# --------------------------------------------------

def test_login_page_loads(client):
    """TC-009: Login page should load successfully."""

    response = client.get("/")

    assert response.status_code == 200
    assert b"Login" in response.data


def test_invalid_login_rejected(client):
    """TC-010: Incorrect password should be rejected."""

    register_user(client)

    response = login_user(
        client,
        password="IncorrectPassword123"
    )

    assert b"Invalid email or password." in response.data


def test_valid_login(client):
    """TC-011: Valid credentials should create a session."""

    register_user(client)

    response = login_user(client)

    assert response.status_code == 200
    assert b"My Profile" in response.data


# --------------------------------------------------
# 5. PROFILE ACCESS TESTS
# --------------------------------------------------

def test_profile_requires_authentication(client):
    """TC-012: Anonymous users cannot access profiles."""

    response = client.get("/profile")

    assert response.status_code == 302
    assert "/" in response.location


def test_profile_displays_correct_user(client):
    """TC-013: Authenticated user sees their own information."""

    register_user(client)
    login_user(client)

    response = client.get("/profile")

    assert response.status_code == 200
    assert b"John Smith" in response.data
    assert b"john@example.com" in response.data


# --------------------------------------------------
# 6. PROFILE UPDATE TESTS
# --------------------------------------------------

def test_profile_update(client):
    """TC-014: Valid profile changes should persist in JSON."""

    register_user(client)
    login_user(client)

    response = client.post(
        "/profile/edit",
        data={
            "full_name": "John Updated",
            "email": "john.updated@example.com",
            "phone": "+27111222333",
            "date_of_birth": "2000-05-15"
        },
        follow_redirects=True
    )

    users = read_test_users()

    assert response.status_code == 200
    assert users[0]["full_name"] == "John Updated"
    assert users[0]["email"] == "john.updated@example.com"
    assert users[0]["phone"] == "+27111222333"


def test_invalid_profile_email_rejected(client):
    """TC-015: Invalid email should not update the profile."""

    register_user(client)
    login_user(client)

    client.post(
        "/profile/edit",
        data={
            "full_name": "John Smith",
            "email": "invalid-email",
            "phone": "+27123456789",
            "date_of_birth": "2000-05-15"
        }
    )

    users = read_test_users()

    assert users[0]["email"] == "john@example.com"


def test_duplicate_profile_email_rejected(client):
    """TC-016: Another user's email cannot be reused."""

    register_user(client)

    register_user(
        client,
        {
            "full_name": "Jane Smith",
            "email": "jane@example.com"
        }
    )

    login_user(client)

    client.post(
        "/profile/edit",
        data={
            "full_name": "John Smith",
            "email": "jane@example.com",
            "phone": "+27123456789",
            "date_of_birth": "2000-05-15"
        }
    )

    users = read_test_users()

    assert users[0]["email"] == "john@example.com"
    assert users[1]["email"] == "jane@example.com"


# --------------------------------------------------
# 7. USER DIRECTORY TESTS
# --------------------------------------------------

def test_users_page_displays_registered_users(client):
    """TC-017: User directory should display stored names."""

    register_user(client)
    login_user(client)

    response = client.get("/users")

    assert response.status_code == 200
    assert b"John Smith" in response.data


def test_users_page_requires_authentication(client):
    """TC-018: Anonymous users cannot access user directory."""

    response = client.get("/users")

    assert response.status_code == 302
    assert "/" in response.location


# --------------------------------------------------
# 8. LOGOUT TESTS
# --------------------------------------------------

def test_logout_terminates_session(client):
    """TC-019: Logout should remove authentication."""

    register_user(client)
    login_user(client)

    response = client.post("/logout")

    assert response.status_code == 302

    profile_response = client.get("/profile")

    assert profile_response.status_code == 302
    assert "/" in profile_response.location


# --------------------------------------------------
# 9. ERROR HANDLING TESTS
# --------------------------------------------------

def test_unknown_route_returns_404(client):
    """TC-020: Unknown routes should return HTTP 404."""

    response = client.get("/unknown-page")

    assert response.status_code == 404
