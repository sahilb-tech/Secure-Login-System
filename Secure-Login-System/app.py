
import os
import sqlite3
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use an environment variable for the secret key.
app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Set the SECRET_KEY environment variable before running the app.")

# Enable CSRF protection for submitted forms.
csrf = CSRFProtect(app)

# Store the database in the instance directory.
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
    # Registration will be implemented in the next step.
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Login will be implemented in the next step.
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        flash("Please log in to access the dashboard.", "warning")
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
