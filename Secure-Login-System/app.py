
import os
import re
import sqlite3
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Read the secret key from the environment.
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Set it in your terminal before running the app."
    )

# Protect POST forms against cross-site request forgery.
csrf = CSRFProtect(app)

# Create a folder for the SQLite database.
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)
DATABASE = INSTANCE_DIR / "users.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate the username.
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash(
                "Username must be 3–30 characters and use only letters, numbers, or underscores.",
                "error"
            )
            return render_template("register.html")

        # Perform basic email-format validation.
        if (
            len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")

        # Enforce a minimum password length.
        if len(password) < 12:
            flash("Password must contain at least 12 characters.", "error")
            return render_template("register.html")

        if len(password) > 128:
            flash("Password must not exceed 128 characters.", "error")
            return render_template("register.html")

        # Ensure both password entries match.
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # Hash the password before storing it.
        password_hash = generate_password_hash(password)

        try:
            with get_db_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO users (username, email, password_hash)
                    VALUES (?, ?, ?)
                    """,
                    (username, email, password_hash)
                )

            flash("Registration successful. You can now log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("That username or email is already registered.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db_connection() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        # Use a generic error message for invalid credentials.
        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # Start a fresh authenticated session.
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)
