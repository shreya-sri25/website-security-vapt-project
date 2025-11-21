from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
import random
import string
import base64
import hmac
import hashlib
import time
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change this for production

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # set True when using HTTPS
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30)
)

@app.before_request
def make_session_permanent():
    session.permanent = True

fernet_key = "r-zOXKfidLACi6YxMdxsuAHs9TTsqpqGxWGwW_hIgsU="
try:
    HMAC_KEY = base64.urlsafe_b64decode(fernet_key)
except Exception:
    HMAC_KEY = fernet_key.encode()

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root123",
            database="vuln_login",
            connection_timeout=10
        )
        return conn
    except mysql.connector.Error as err:
        # Print to console so you can see what's wrong in PowerShell
        print(f"[DB ERROR] {err}")
        return None

def urlsafe_b64decode_padded(data: str) -> bytes:
    if not isinstance(data, str):
        raise TypeError("data must be str")
    b = data.replace('-', '+').replace('_', '/')
    padding = (4 - len(b) % 4) % 4
    b += "=" * padding
    return base64.b64decode(b)

def verify_hmac(task_text: str, ts_str: str, sig_b64: str, max_age_seconds=300):
    if not sig_b64 or not ts_str:
        return False, "missing signature or timestamp"
    try:
        ts = int(ts_str)
    except Exception:
        return False, "invalid timestamp"

    now = int(time.time())
    if abs(now - ts) > max_age_seconds:
        return False, "timestamp too old"

    msg = (task_text + "|" + ts_str).encode()
    computed = hmac.new(HMAC_KEY, msg, hashlib.sha256).digest()
    try:
        provided = urlsafe_b64decode_padded(sig_b64)
    except Exception:
        return False, "invalid signature encoding"
    if hmac.compare_digest(computed, provided):
        return True, "ok"
    return False, "signature mismatch"


@app.route("/")
def home():
    return redirect(url_for("login_page"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Please provide username and password.", "warning")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        if conn is None:
            flash("Database connection error. Try again later.", "danger")
            return render_template("register.html")

        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            conn.commit()
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login_page"))
        except mysql.connector.IntegrityError:
            conn.rollback()
            flash("Username already taken. Choose another.", "danger")
            return render_template("register.html")
        except Exception as e:
            conn.rollback()
            print(f"[DB ERROR - register] {e}")
            flash("Database error during registration.", "danger")
            return render_template("register.html")
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        session["captcha"] = captcha
        return render_template("login.html", captcha=captcha)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    user_captcha = request.form.get("captcha")
    real_captcha = session.get("captcha")

    if user_captcha != real_captcha:
        flash("Captcha does not match!", "danger")
        # regenerate captcha for retry
        captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        session["captcha"] = captcha
        return render_template("login.html", captcha=captcha)

    conn = get_db_connection()
    if conn is None:
        flash("Database connection error. Try again later.", "danger")
        captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        session["captcha"] = captcha
        return render_template("login.html", captcha=captcha)

    try:
        cur = conn.cursor(dictionary=True, buffered=True)
        cur.execute("SELECT id, username, password FROM users WHERE username=%s", (username,))
        user = cur.fetchone()
    except Exception as e:
        print(f"[DB ERROR - login] {e}")
        flash("Database error. Try again.", "danger")
        user = None
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    if user and user.get("password") and check_password_hash(user["password"], password):
        session["user"] = {"id": user["id"], "username": user["username"]}
        flash("Login successful! Redirecting...", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid username or password", "danger")
        captcha = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        session["captcha"] = captcha
        return render_template("login.html", captcha=captcha)

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login_page"))

    user = session["user"]

    conn = get_db_connection()
    if conn is None:
        flash("Database connection error. Try again later.", "danger")
        return redirect(url_for("login_page"))

    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT id, task, completed, created_at FROM todos WHERE user_id=%s ORDER BY created_at DESC",
            (user["id"],)
        )
        todos = cur.fetchall()
    except Exception as e:
        print(f"[DB ERROR - dashboard] {e}")
        flash("Database error. Try again.", "danger")
        todos = []
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return render_template("dashboard.html", user=user, todos=todos, client_key=fernet_key)

@app.route("/add_todo", methods=["POST"])
def add_todo():
    user = session.get("user")
    if not user:
        return redirect(url_for("login_page"))

    task = request.form.get("task", "")
    sig = request.form.get("sig", "")
    ts = request.form.get("ts", "")

    ok, reason = verify_hmac(task, ts, sig, max_age_seconds=300)
    if not ok:
        flash(f"Rejected: {reason}", "danger")
        return redirect(url_for("dashboard"))

    if task:
        conn = get_db_connection()
        if conn is None:
            flash("Database connection error. Try again later.", "danger")
            return redirect(url_for("dashboard"))
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO todos (user_id, task) VALUES (%s, %s)", (user["id"], task))
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB ERROR - add_todo] {e}")
            flash("Could not add todo.", "danger")
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    return redirect(url_for("dashboard"))

@app.route("/edit_todo/<int:todo_id>", methods=["POST"])
def edit_todo(todo_id):
    user = session.get("user")
    if not user:
        return redirect(url_for("login_page"))

    new_task = request.form.get("task", "")
    sig = request.form.get("sig", "")
    ts = request.form.get("ts", "")

    ok, reason = verify_hmac(new_task, ts, sig, max_age_seconds=300)
    if not ok:
        flash(f"Rejected: {reason}", "danger")
        return redirect(url_for("dashboard"))

    if new_task:
        conn = get_db_connection()
        if conn is None:
            flash("Database connection error. Try again later.", "danger")
            return redirect(url_for("dashboard"))
        try:
            cur = conn.cursor()
            cur.execute(
                "UPDATE todos SET task = %s WHERE id = %s AND user_id = %s",
                (new_task, todo_id, user["id"])
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB ERROR - edit_todo] {e}")
            flash("Could not update todo.", "danger")
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    return redirect(url_for("dashboard"))

@app.route("/mark_done/<int:todo_id>", methods=["POST"])
def mark_done(todo_id):
    user = session.get("user")
    if not user:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection error. Try again later.", "danger")
        return redirect(url_for("dashboard"))

    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE todos SET completed = 1 WHERE id = %s AND user_id = %s",
            (todo_id, user["id"])
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[DB ERROR - mark_done] {e}")
        flash("Could not mark as done.", "danger")
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return redirect(url_for("dashboard"))

@app.route("/delete_todo/<int:todo_id>", methods=["POST"])
def delete_todo(todo_id):
    user = session.get("user")
    if not user:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection error. Try again later.", "danger")
        return redirect(url_for("dashboard"))

    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM todos WHERE id = %s AND user_id = %s",
            (todo_id, user["id"])
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"[DB ERROR - delete_todo] {e}")
        flash("Could not delete todo.", "danger")
    finally:
        try:
            cur.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login_page"))

if __name__ == "__main__":
    app.run(debug=True)
