
import re
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db


def register_user(name, email, password):
    name = (name or "").strip()
    email = (email or "").strip().lower()

    if not name or not email or not password:
        return {
            "success": False,
            "message": "All fields are required."
        }

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return {
            "success": False,
            "message": "Enter a valid email address."
        }

    if len(password) < 8:
        return {
            "success": False,
            "message": "Password must contain at least 8 characters."
        }

    password_hash = generate_password_hash(password)

    try:
        with get_db() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (full_name, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (name, email, password_hash)
            )

            user_id = cursor.lastrowid

        return {
            "success": True,
            "message": "Account created successfully.",
            "user": {
                "id": user_id,
                "name": name,
                "email": email
            }
        }

    except sqlite3.IntegrityError as error:
        if "UNIQUE constraint failed" in str(error):
            return {
                "success": False,
                "message": "An account with this email already exists."
            }

        raise


def login_user(email, password):
    email = (email or "").strip().lower()

    with get_db() as connection:
        user = connection.execute(
            """
            SELECT id, full_name, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], password or ""
    ):
        return {
            "success": False,
            "message": "Invalid email or password."
        }

    return {
        "success": True,
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "name": user["full_name"],
            "email": user["email"]
        }
    }
