
import os
import re
import json
import uuid

from pathlib import Path
from datetime import date
from tempfile import NamedTemporaryFile

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# --------------------------------------------------
# 1. app config
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set the SECRET_KEY environment variable.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS") == "1"
)

# Enable Cross-Site Request Forgery protection.
csrf = CSRFProtect(app)


# --------------------------------------------------
# 2. json storage
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_FILE = BASE_DIR / "users.json"

# Create the JSON file if it does not already exist.
def initialise_storage():          
    #prevent file not found error    

    if not DATA_FILE.exists():
        DATA_FILE.write_text(
            json.dumps({"users": []}, indent=4),
            encoding="utf-8"
        )

# read all user records from the JSON file.
def load_users():
    initialise_storage()

    with DATA_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return data.get("users", [])

# store user records to JSON.
def save_users(users):  

    data = {"users": users}
    # Create the temporary file in the same directory    
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=BASE_DIR,
        delete=False
    ) as temp_file:

        json.dump(data, temp_file, indent=4)
        temp_path = temp_file.name

    try:
        os.replace(temp_path, DATA_FILE)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# --------------------------------------------------
# 3. input validations
# --------------------------------------------------

def validate_registration(form):
    #Validate registration form data.
    errors = {}

    user_data = {
        "full_name": form.get("full_name", "").strip(),
        "email": form.get("email", "").strip().lower(),
        "phone": form.get("phone", "").strip(),
        "date_of_birth": form.get("date_of_birth", "").strip(),
        "password": form.get("password", "")
    }

    # Full name validation.
    if not user_data["full_name"]:
        errors["full_name"] = "Full name is required."

    elif len(user_data["full_name"]) > 100:
        errors["full_name"] = "Name cannot exceed 100 characters."

    # Email validation.
    email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    if not user_data["email"]:
        errors["email"] = "Email address is required."

    elif not re.fullmatch(email_pattern, user_data["email"]):
        errors["email"] = "Enter a valid email address."

    # Phone number validation.
    if not user_data["phone"]:
        errors["phone"] = "Phone number is required."

    elif not re.fullmatch(r"\+?[0-9]{7,15}", user_data["phone"]):
        errors["phone"] = "Enter a valid phone number."

    # Date of birth validation.
    if user_data["date_of_birth"]:
        try:
            dob = date.fromisoformat(user_data["date_of_birth"])

            if dob > date.today():
                errors["date_of_birth"] = "Date cannot be in the future."

        except ValueError:
            errors["date_of_birth"] = "Enter a valid date."

    # Password validation.
    if len(user_data["password"]) < 12:
        errors["password"] = "Password must contain at least 12 characters."

    return errors, user_data


# --------------------------------------------------
# 4. user look up functions
# --------------------------------------------------

# find by their email address.
def find_user_by_email(email):
    

    users = load_users()

    return next(
        (user for user in users if user["email"] == email.lower()),
        None
    )


def find_user_by_id(user_id):
    #Locate a user using their unique UUID.    

    users = load_users()

    return next(
        (user for user in users if user["id"] == user_id),
        None
    )


# get the currently authenticated user.
def get_current_user():
    

        

    user_id = session.get("user_id")

    if not user_id:
        return None

    return find_user_by_id(user_id)


# --------------------------------------------------
# 5. registration route
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        errors, user_data = validate_registration(request.form)

        # check whether the email address is already registered.
        if find_user_by_email(user_data["email"]):
            errors["email"] = "This email address is already registered."

        if errors:
            return render_template(
                "register.html",
                errors=errors,
                form_data=request.form
            )

        # generate a unique user identifier.
        new_user = {
            "id": str(uuid.uuid4()),
            "full_name": user_data["full_name"],
            "email": user_data["email"],
            "phone": user_data["phone"],
            "date_of_birth": user_data["date_of_birth"],

            # hash the password
            "password_hash": generate_password_hash(
                user_data["password"]
            )
        }

        # add the new user to the existing records.
        users = load_users()
        users.append(new_user)

        save_users(users)

        flash("Registration successful. Please log in.", "success")

        return redirect(url_for("login"))

    return render_template("register.html", errors={})


# --------------------------------------------------
# 6. login route
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = find_user_by_email(email)

        # Verify both the user and the password hash.
        if user and check_password_hash(
            user["password_hash"], password
        ):

            session.clear()
            session["user_id"] = user["id"]

            return redirect(url_for("profile"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# --------------------------------------------------
# 7. logout route
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
def logout():

    # Clear the authenticated session.
    session.clear()

    flash("You have logged out.", "success")

    return redirect(url_for("login"))


# --------------------------------------------------
# 8. show all users
# --------------------------------------------------

@app.route("/users")
def users():

    current_user = get_current_user()

    if not current_user:
        return redirect(url_for("login"))

    # Expose only names in the user directory.    
    public_users = [
        {
            "id": user["id"],
            "full_name": user["full_name"]
        }
        for user in load_users()
    ]

    return render_template(
        "users.html",
        users=public_users
    )


# --------------------------------------------------
# 9. show indivudal profile
# --------------------------------------------------

@app.route("/profile")
def profile():

    user = get_current_user()

    if not user:
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        user=user
    )


# --------------------------------------------------
# 10. update profile route
# --------------------------------------------------

@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():

    user = get_current_user()

    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":

        # Collect updated profile information.
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        dob = request.form.get("date_of_birth", "").strip()

        errors = {}

        # Validate full name.
        if not full_name:
            errors["full_name"] = "Full name is required."

        elif len(full_name) > 100:
            errors["full_name"] = "Name cannot exceed 100 characters."

        # Validate email format.
        email_pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

        if not email or not re.fullmatch(email_pattern, email):
            errors["email"] = "Enter a valid email address."

        # Prevent duplicate email addresses.
        existing_user = find_user_by_email(email)

        if existing_user and existing_user["id"] != user["id"]:
            errors["email"] = "Email address is already in use."

        # Validate phone number.
        if not re.fullmatch(r"\+?[0-9]{7,15}", phone):
            errors["phone"] = "Enter a valid phone number."

        # Validate date of birth.
        if dob:
            try:
                if date.fromisoformat(dob) > date.today():
                    errors["date_of_birth"] = "Date cannot be in the future."
            except ValueError:
                errors["date_of_birth"] = "Enter a valid date."

        if errors:
            return render_template(
                "edit_profile.html",
                user=user,
                errors=errors
            )

        # Update the matching record without changing        
        users = load_users()

        for record in users:

            if record["id"] == user["id"]:

                record["full_name"] = full_name
                record["email"] = email
                record["phone"] = phone
                record["date_of_birth"] = dob

                break

        save_users(users)

        flash("Profile updated successfully.", "success")

        return redirect(url_for("profile"))

    return render_template(
        "edit_profile.html",
        user=user,
        errors={}
    )


# --------------------------------------------------
# 11. application start
# --------------------------------------------------

if __name__ == "__main__":

    initialise_storage()
    
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
