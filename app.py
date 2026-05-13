
import os
import secrets
import sqlite3
import uuid
import hmac
import hashlib
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import requests
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

DB_PATH = os.path.join("database", "pharmacy.db")
UPLOAD_MEDICINES = os.path.join("static", "uploads", "medicines")
UPLOAD_PRESCRIPTIONS = os.path.join("static", "uploads", "prescriptions")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg"}
ALLOWED_PRESCRIPTION_EXT = {"png", "jpg", "jpeg", "pdf"}
JWT_ALGO = "HS256"
JWT_EXP_HOURS = int(os.environ.get("JWT_EXP_HOURS", "48"))
OTP_EXP_MINUTES = 5
load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
ADMIN_ENTRY_PATH = "/" + os.environ.get("ADMIN_ENTRY_PATH", "secure-admin-portal-9x7").strip("/")
ADMIN_REGISTER_PATH = f"{ADMIN_ENTRY_PATH}/register"
ADMIN_FORGOT_PATH = f"{ADMIN_ENTRY_PATH}/forgot-password"

def send_email_otp(receiver_email, otp):
    sender_email = os.environ.get("EMAIL_USER")
    sender_password = os.environ.get("EMAIL_PASS")

    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Healthcare Pharmacy OTP"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
def ensure_dirs() -> None:
    os.makedirs("database", exist_ok=True)
    os.makedirs(UPLOAD_MEDICINES, exist_ok=True)
    os.makedirs(UPLOAD_PRESCRIPTIONS, exist_ok=True)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def ensure_db_migrations() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS user_cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            medicine_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, medicine_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (medicine_id) REFERENCES medicines(id)
        )
        """
    )
    order_cols = {row["name"] for row in db.execute("PRAGMA table_info(orders)").fetchall()}
    if "payment_provider" not in order_cols:
        db.execute("ALTER TABLE orders ADD COLUMN payment_provider TEXT")
    if "payment_reference" not in order_cols:
        db.execute("ALTER TABLE orders ADD COLUMN payment_reference TEXT")
    if "payment_status" not in order_cols:
        db.execute("ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT 'Pending'")
    user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "last_login_at" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
    if "last_login_ip" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN last_login_ip TEXT")
    if "login_count" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0")
    if "wallet_balance" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN wallet_balance REAL DEFAULT 0")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            txn_type TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    db.commit()


def allowed_file(filename: str, allowed_extensions: set[str]) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def record_user_login(user_id: int) -> None:
    db = get_db()
    db.execute(
        """
        UPDATE users
        SET last_login_at = ?, last_login_ip = ?, login_count = COALESCE(login_count, 0) + 1
        WHERE id = ?
        """,
        (datetime.now(timezone.utc).isoformat(), request.remote_addr, user_id),
    )
    db.commit()


def adjust_wallet_balance(user_id: int, amount: float, txn_type: str, note: str) -> bool:
    db = get_db()
    user = db.execute("SELECT wallet_balance FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return False
    current = float(user["wallet_balance"] or 0.0)
    new_balance = current + amount
    if new_balance < 0:
        return False
    db.execute("UPDATE users SET wallet_balance = ? WHERE id = ?", (new_balance, user_id))
    db.execute(
        """
        INSERT INTO wallet_transactions (user_id, amount, txn_type, note, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, amount, txn_type, note, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return True


def send_otp_to_session(purpose: str, email: str) -> str:
    otp = f"{secrets.randbelow(1000000):06d}"
    session["otp_data"] = {
        "purpose": purpose,
        "email": email.lower(),
        "otp": otp,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=OTP_EXP_MINUTES)).isoformat(),
    }
    session.modified = True
    return otp


def verify_otp_from_session(purpose: str, email: str, otp: str) -> tuple[bool, str]:
    otp_data = session.get("otp_data")
    if not otp_data:
        return False, "OTP not requested. Please click Send OTP first."
    if otp_data.get("purpose") != purpose or otp_data.get("email") != email.lower():
        return False, "OTP does not match this email/purpose."
    if datetime.now(timezone.utc) > datetime.fromisoformat(otp_data.get("expires_at", "")):
        return False, "OTP expired. Please request a new OTP."
    if otp_data.get("otp") != otp:
        return False, "Invalid OTP."
    session.pop("otp_data", None)
    session.modified = True
    return True, ""


def jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", app.config["SECRET_KEY"])


def generate_access_token(user: sqlite3.Row) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "is_admin": bool(user["is_admin"]),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXP_HOURS)).timestamp()),
    }
    return jwt.encode(payload, jwt_secret(), algorithm=JWT_ALGO)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, jwt_secret(), algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None


def bearer_token_from_request() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def api_current_user():
    token = bearer_token_from_request()
    if token:
        payload = decode_access_token(token)
        if not payload:
            return None
        try:
            user_id = int(payload.get("sub", "0"))
        except ValueError:
            return None
        return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return current_user()


def serialize_user(user: sqlite3.Row) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "address": user["address"],
        "is_admin": bool(user["is_admin"]),
        "wallet_balance": float(user["wallet_balance"] or 0.0),
    }


def serialize_medicine(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "category": row["category"],
        "description": row["description"],
        "price": row["price"],
        "stock": row["stock"],
        "prescription_required": bool(row["prescription_required"]),
        "image_url": (
            url_for("static", filename=f"uploads/medicines/{row['image_filename']}")
            if row["image_filename"]
            else None
        ),
    }


def serialize_cart_item(item: dict) -> dict:
    return {
        "medicine": serialize_medicine(item["medicine"]),
        "quantity": item["quantity"],
        "subtotal": item["subtotal"],
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def api_login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = api_current_user()
        if not user:
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        g.api_user = user
        return view(*args, **kwargs)

    return wrapped


def get_cart() -> dict:
    if "cart" not in session:
        session["cart"] = {}
    return session["cart"]


def cart_details():
    cart = get_cart()
    if not cart:
        return [], 0.0, False
    ids = [int(mid) for mid in cart.keys()]
    rows = get_db().execute(
        f"SELECT * FROM medicines WHERE id IN ({','.join(['?'] * len(ids))})",
        ids,
    ).fetchall()
    items, total, requires_prescription = [], 0.0, False
    for row in rows:
        quantity = int(cart.get(str(row["id"]), 0))
        if quantity <= 0:
            continue
        subtotal = quantity * row["price"]
        total += subtotal
        if row["prescription_required"]:
            requires_prescription = True
        items.append({"medicine": row, "quantity": quantity, "subtotal": subtotal})
    return items, total, requires_prescription


def api_cart_details(user_id: int):
    rows = get_db().execute(
        """
        SELECT uci.medicine_id, uci.quantity, m.*
        FROM user_cart_items uci
        JOIN medicines m ON m.id = uci.medicine_id
        WHERE uci.user_id = ?
        ORDER BY uci.updated_at DESC
        """,
        (user_id,),
    ).fetchall()
    items, total, requires_prescription = [], 0.0, False
    for row in rows:
        quantity = int(row["quantity"])
        subtotal = quantity * row["price"]
        total += subtotal
        if row["prescription_required"]:
            requires_prescription = True
        items.append({"medicine": row, "quantity": quantity, "subtotal": subtotal})
    return items, total, requires_prescription


def set_api_cart_item(user_id: int, medicine_id: int, quantity: int) -> None:
    db = get_db()
    if quantity <= 0:
        db.execute("DELETE FROM user_cart_items WHERE user_id = ? AND medicine_id = ?", (user_id, medicine_id))
    else:
        db.execute(
            """
            INSERT INTO user_cart_items (user_id, medicine_id, quantity, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, medicine_id)
            DO UPDATE SET quantity = excluded.quantity, updated_at = excluded.updated_at
            """,
            (user_id, medicine_id, quantity, datetime.now(timezone.utc).isoformat()),
        )
    db.commit()


def clear_api_cart(user_id: int) -> None:
    db = get_db()
    db.execute("DELETE FROM user_cart_items WHERE user_id = ?", (user_id,))
    db.commit()

def create_order_for_user(
    user: sqlite3.Row,
    shipping_address: str,
    items: list[dict],
    total: float,
    uploaded_filename: str | None = None,
    uploaded_original_name: str | None = None,
    payment_provider: str | None = None,
    payment_reference: str | None = None,
    payment_status: str = "Pending",
) -> int:
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        INSERT INTO orders (
            user_id, total_amount, status, payment_provider, payment_reference,
            payment_status, shipping_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user["id"],
            total,
            "Pending",
            payment_provider,
            payment_reference,
            payment_status,
            shipping_address,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    order_id = cursor.lastrowid
    for item in items:
        cursor.execute(
            "INSERT INTO order_items (order_id, medicine_id, quantity, unit_price) VALUES (?, ?, ?, ?)",
            (order_id, item["medicine"]["id"], item["quantity"], item["medicine"]["price"]),
        )
        cursor.execute("UPDATE medicines SET stock = stock - ? WHERE id = ?", (item["quantity"], item["medicine"]["id"]))
    if uploaded_filename and uploaded_original_name:
        cursor.execute(
            "INSERT INTO prescriptions (order_id, user_id, file_name, original_name, uploaded_at) VALUES (?, ?, ?, ?, ?)",
            (order_id, user["id"], uploaded_filename, uploaded_original_name, datetime.now(timezone.utc).isoformat()),
        )
    db.commit()
    return order_id


def create_payment_intent(provider: str, amount_inr: float) -> dict:
    amount_paise = max(1, int(round(amount_inr * 100)))
    if provider == "stripe":
        secret = os.environ.get("STRIPE_SECRET_KEY")
        if not secret:
            return {"ok": False, "error": "Missing STRIPE_SECRET_KEY"}
        try:
            resp = requests.post(
                "https://api.stripe.com/v1/payment_intents",
                headers={"Authorization": f"Bearer {secret}"},
                data={"amount": str(amount_paise), "currency": "inr", "automatic_payment_methods[enabled]": "true"},
                timeout=20,
            )
            data = resp.json()
            if resp.status_code >= 400:
                return {"ok": False, "error": data.get("error", {}).get("message", "Stripe error")}
            return {"ok": True, "provider": "stripe", "payment_reference": data.get("id"), "client_secret": data.get("client_secret"), "status": data.get("status"), "amount": amount_inr}
        except requests.RequestException:
            return {"ok": False, "error": "Stripe network error"}
    if provider == "razorpay":
        key_id = os.environ.get("RAZORPAY_KEY_ID")
        key_secret = os.environ.get("RAZORPAY_KEY_SECRET")
        if not key_id or not key_secret:
            return {"ok": False, "error": "Missing RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET"}
        try:
            resp = requests.post(
                "https://api.razorpay.com/v1/orders",
                auth=(key_id, key_secret),
                json={"amount": amount_paise, "currency": "INR", "receipt": f"rx_{secrets.token_hex(6)}", "payment_capture": 1},
                timeout=20,
            )
            data = resp.json()
            if resp.status_code >= 400:
                return {"ok": False, "error": data.get("error", {}).get("description", "Razorpay error")}
            return {"ok": True, "provider": "razorpay", "payment_reference": data.get("id"), "status": data.get("status"), "amount": amount_inr, "key_id": key_id}
        except requests.RequestException:
            return {"ok": False, "error": "Razorpay network error"}
    return {"ok": False, "error": "Unsupported provider"}


def create_stripe_checkout_session(amount_inr: float, success_url: str, cancel_url: str) -> dict:
    secret = os.environ.get("STRIPE_SECRET_KEY")
    if not secret:
        return {"ok": False, "error": "Missing STRIPE_SECRET_KEY"}
    amount_paise = max(1, int(round(amount_inr * 100)))
    try:
        resp = requests.post(
            "https://api.stripe.com/v1/checkout/sessions",
            headers={"Authorization": f"Bearer {secret}"},
            data={
                "mode": "payment",
                "success_url": success_url,
                "cancel_url": cancel_url,
                "line_items[0][price_data][currency]": "inr",
                "line_items[0][price_data][product_data][name]": "Healthcare Pharmacy Order",
                "line_items[0][price_data][unit_amount]": str(amount_paise),
                "line_items[0][quantity]": "1",
            },
            timeout=20,
        )
        data = resp.json()
        if resp.status_code >= 400:
            return {"ok": False, "error": data.get("error", {}).get("message", "Stripe Checkout error")}
        return {
            "ok": True,
            "provider": "stripe",
            "session_id": data.get("id"),
            "checkout_url": data.get("url"),
            "payment_reference": data.get("payment_intent"),
        }
    except requests.RequestException:
        return {"ok": False, "error": "Stripe network error"}


def verify_stripe_checkout_session(session_id: str) -> dict:
    secret = os.environ.get("STRIPE_SECRET_KEY")
    if not secret:
        return {"ok": False, "error": "Missing STRIPE_SECRET_KEY"}
    try:
        resp = requests.get(
            f"https://api.stripe.com/v1/checkout/sessions/{session_id}",
            headers={"Authorization": f"Bearer {secret}"},
            timeout=20,
        )
        data = resp.json()
        if resp.status_code >= 400:
            return {"ok": False, "error": data.get("error", {}).get("message", "Stripe verify error")}
        return {
            "ok": True,
            "payment_status": data.get("payment_status", "unpaid"),
            "payment_reference": data.get("payment_intent") or session_id,
            "session_id": data.get("id", session_id),
        }
    except requests.RequestException:
        return {"ok": False, "error": "Stripe network error"}


def update_order_payment_status(payment_reference: str, provider: str, payment_status: str) -> int:
    db = get_db()
    cursor = db.execute(
        """
        UPDATE orders
        SET payment_provider = ?, payment_status = ?
        WHERE payment_reference = ?
        """,
        (provider, payment_status, payment_reference),
    )
    db.commit()
    return cursor.rowcount


def verify_stripe_signature(payload: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header:
        return False
    parts = {}
    for item in signature_header.split(","):
        if "=" in item:
            key, value = item.split("=", 1)
            parts[key.strip()] = value.strip()
    timestamp = parts.get("t")
    signature = parts.get("v1")
    if not timestamp or not signature:
        return False
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - ts_int) > 300:
        return False
    signed_payload = f"{timestamp}.{payload.decode('utf-8')}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_razorpay_signature(payload: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header:
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@app.context_processor
def inject_global_context():
    cart = session.get("cart", {})
    cart_count = sum(int(qty) for qty in cart.values())
    return {"current_user": current_user(), "cart_count": cart_count, "admin_logged_in": bool(session.get("admin_id"))}


@app.route("/")
def index():
    db = get_db()
    featured = db.execute("SELECT * FROM medicines ORDER BY created_at DESC LIMIT 8").fetchall()
    categories = db.execute("SELECT DISTINCT category FROM medicines ORDER BY category").fetchall()
    return render_template("index.html", featured=featured, categories=categories)


@app.route("/register", methods=["GET", "POST"])
@app.route("/customer/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()

        if not name or not email or not password:
            flash("Name, email, and password are required.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("Email is already registered.", "warning")
            return redirect(url_for("register"))
        db.execute("INSERT INTO users (name, email, password_hash, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?)", (name, email, generate_password_hash(password), phone, address, datetime.now(timezone.utc).isoformat()))
        db.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@app.route("/customer/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            record_user_login(user["id"])
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
@app.route("/customer/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        action = request.form.get("action", "send_otp")
        email = request.form.get("email", "").strip().lower()
        otp = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", "")

        if action == "send_otp":
            user = get_db().execute(
                "SELECT * FROM users WHERE email = ? AND is_admin = 0", (email,)
            ).fetchone()
            if not user:
                flash("Customer account not found.", "warning")
                return redirect(url_for("forgot_password"))
            generated = send_otp_to_session("customer_reset_password", email)
            print(f"[CUSTOMER RESET OTP] {email}: {generated}")
            flash("OTP sent (demo mode: check terminal output).", "info")
            return redirect(url_for("forgot_password"))

        if not email or not otp or not new_password:
            flash("Email, OTP, and new password are required.", "danger")
            return redirect(url_for("forgot_password"))
        ok, message = verify_otp_from_session("customer_reset_password", email, otp)
        if not ok:
            flash(message, "danger")
            return redirect(url_for("forgot_password"))
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ? AND is_admin = 0", (email,)
        ).fetchone()
        if not user:
            flash("Customer account not found.", "warning")
            return redirect(url_for("forgot_password"))
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
        db.commit()
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("cart", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/medicines")
def medicines():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    query = "SELECT * FROM medicines WHERE 1=1"
    params = []
    if q:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY name"
    db = get_db()
    rows = db.execute(query, tuple(params)).fetchall()
    categories = db.execute("SELECT DISTINCT category FROM medicines ORDER BY category").fetchall()
    return render_template("medicines.html", medicines=rows, categories=categories, q=q, selected_category=category)


@app.route("/medicine/<int:medicine_id>")
def medicine_detail(medicine_id: int):
    db = get_db()
    medicine = db.execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not medicine:
        flash("Medicine not found.", "warning")
        return redirect(url_for("medicines"))
    related = db.execute("SELECT * FROM medicines WHERE category = ? AND id != ? LIMIT 4", (medicine["category"], medicine_id)).fetchall()
    return render_template("medicine_detail.html", medicine=medicine, related=related)


@app.route("/cart")
def cart():
    items, total, requires_prescription = cart_details()
    return render_template("cart.html", items=items, total=total, requires_prescription=requires_prescription)


@app.route("/cart/add/<int:medicine_id>", methods=["POST"])
def add_to_cart(medicine_id: int):
    medicine = get_db().execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not medicine:
        flash("Medicine not found.", "warning")
        return redirect(url_for("medicines"))
    try:
        quantity = int(request.form.get("quantity", 1))
    except ValueError:
        quantity = 1
    quantity = max(1, quantity)
    cart_data = get_cart()
    current_qty = int(cart_data.get(str(medicine_id), 0))
    cart_data[str(medicine_id)] = min(current_qty + quantity, medicine["stock"])
    session["cart"] = cart_data
    session.modified = True
    flash(f"{medicine['name']} added to cart.", "success")
    return redirect(request.referrer or url_for("medicines"))

@app.route("/cart/update", methods=["POST"])
def update_cart():
    cart_data = get_cart()
    db = get_db()
    for key, value in request.form.items():
        if key.startswith("qty_"):
            med_id = key.split("_", 1)[1]
            try:
                qty = int(value)
            except ValueError:
                qty = 1
            medicine = db.execute("SELECT stock FROM medicines WHERE id = ?", (med_id,)).fetchone()
            if not medicine:
                cart_data.pop(med_id, None)
                continue
            if qty <= 0:
                cart_data.pop(med_id, None)
            else:
                cart_data[med_id] = min(qty, medicine["stock"])
    session["cart"] = cart_data
    session.modified = True
    flash("Cart updated.", "info")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:medicine_id>", methods=["POST"])
def remove_from_cart(medicine_id: int):
    cart_data = get_cart()
    cart_data.pop(str(medicine_id), None)
    session["cart"] = cart_data
    session.modified = True
    flash("Item removed from cart.", "info")
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    items, total, requires_prescription = cart_details()
    if not items:
        flash("Your cart is empty.", "warning")
        return redirect(url_for("medicines"))
    user = current_user()
    stripe_payment_reference = None
    stripe_paid = False
    if request.args.get("stripe_cancelled", "").strip():
        flash("Stripe payment was cancelled.", "warning")
    stripe_session_id = request.args.get("stripe_session_id", "").strip()
    if stripe_session_id:
        verification = verify_stripe_checkout_session(stripe_session_id)
        if verification.get("ok") and verification.get("payment_status") == "paid":
            stripe_paid = True
            stripe_payment_reference = verification.get("payment_reference")
            session["stripe_paid_session_id"] = verification.get("session_id")
            session["stripe_payment_reference"] = stripe_payment_reference
            session.modified = True
            flash("Stripe payment verified. You can place order now.", "success")
        else:
            flash(verification.get("error", "Stripe payment not verified."), "warning")
    if request.method == "POST":
        shipping_address = request.form.get("shipping_address", "").strip() or user["address"]
        payment_method = request.form.get("payment_method", "pay_on_delivery").strip().lower()
        posted_payment_reference = request.form.get("payment_reference", "").strip()
        posted_payment_status = request.form.get("payment_status", "").strip()
        if not shipping_address:
            flash("Shipping address is required.", "danger")
            return redirect(url_for("checkout"))
        if payment_method not in {"pay_on_delivery", "upi", "wallet", "stripe", "razorpay"}:
            payment_method = "pay_on_delivery"
        uploaded_filename = None
        uploaded_original_name = None
        prescription_file = request.files.get("prescription")
        if requires_prescription:
            if not prescription_file or not prescription_file.filename:
                flash("Prescription upload is required for selected medicines.", "danger")
                return redirect(url_for("checkout"))
            if not allowed_file(prescription_file.filename, ALLOWED_PRESCRIPTION_EXT):
                flash("Invalid prescription format. Allowed: JPG, PNG, PDF.", "danger")
                return redirect(url_for("checkout"))
            uploaded_original_name = secure_filename(prescription_file.filename)
            extension = uploaded_original_name.rsplit(".", 1)[1].lower()
            uploaded_filename = f"rx_{uuid.uuid4().hex}.{extension}"
            prescription_file.save(os.path.join(UPLOAD_PRESCRIPTIONS, uploaded_filename))
        for item in items:
            if item["quantity"] > item["medicine"]["stock"]:
                flash(f"Insufficient stock for {item['medicine']['name']}.", "danger")
                return redirect(url_for("cart"))
        payment_reference = "PAY_ON_DELIVERY"
        payment_status = "Pending"
        if payment_method == "upi":
            payment_reference = "UPI_PENDING"
        elif payment_method == "wallet":
            latest_user = get_db().execute(
                "SELECT wallet_balance FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            wallet_balance = float(latest_user["wallet_balance"] or 0.0)
            if wallet_balance < total:
                flash("Insufficient wallet balance. Please top up wallet.", "danger")
                return redirect(url_for("wallet"))
            payment_reference = f"WALLET_{uuid.uuid4().hex[:12].upper()}"
            payment_status = "Paid"
        elif payment_method in {"stripe", "razorpay"}:
            if payment_method == "stripe":
                if session.get("stripe_paid_session_id") and session.get("stripe_payment_reference"):
                    payment_reference = str(session.get("stripe_payment_reference"))
                    payment_status = "Paid"
                else:
                    flash("Please complete Stripe checkout first.", "warning")
                    return redirect(url_for("checkout"))
            else:
                if posted_payment_reference:
                    payment_reference = posted_payment_reference
                if posted_payment_status.lower() == "paid":
                    payment_status = "Paid"
                else:
                    flash("Please complete Razorpay payment first.", "warning")
                    return redirect(url_for("checkout"))

        order_id = create_order_for_user(
            user,
            shipping_address,
            items,
            total,
            uploaded_filename,
            uploaded_original_name,
            payment_method,
            payment_reference,
            payment_status,
        )
        if payment_method == "wallet":
            adjust_wallet_balance(user["id"], -total, "DEBIT", f"Order #{order_id} payment")
        if payment_method == "stripe":
            session.pop("stripe_paid_session_id", None)
            session.pop("stripe_payment_reference", None)
            session.modified = True
        session.pop("cart", None)
        flash("Order placed successfully.", "success")
        return redirect(url_for("order_success", order_id=order_id))
    upi_id = os.environ.get("UPI_ID", "").strip()
    upi_name = os.environ.get("UPI_NAME", "Healthcare Pharmacy").strip()
    upi_link = ""
    if upi_id:
        upi_link = f"upi://pay?pa={upi_id}&pn={upi_name}&am={total:.2f}&cu=INR"
    return render_template(
        "checkout.html",
        items=items,
        total=total,
        requires_prescription=requires_prescription,
        user=user,
        upi_id=upi_id,
        upi_name=upi_name,
        upi_link=upi_link,
        stripe_publishable_key=os.environ.get("STRIPE_PUBLISHABLE_KEY", "").strip(),
        razorpay_key_id=os.environ.get("RAZORPAY_KEY_ID", "").strip(),
        stripe_paid=stripe_paid or bool(session.get("stripe_paid_session_id")),
        stripe_payment_reference=stripe_payment_reference or session.get("stripe_payment_reference", ""),
    )


@app.route("/order-success/<int:order_id>")
@login_required
def order_success(order_id: int):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?", (order_id, session["user_id"])).fetchone()
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("index"))
    items = db.execute("SELECT oi.quantity, oi.unit_price, m.name FROM order_items oi JOIN medicines m ON m.id = oi.medicine_id WHERE oi.order_id = ?", (order_id,)).fetchall()
    return render_template("order_success.html", order=order, items=items)


@app.route("/orders")
@login_required
def customer_orders():
    rows = get_db().execute(
        """
        SELECT id, total_amount, status, payment_provider, payment_status, created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (session["user_id"],),
    ).fetchall()
    return render_template("orders.html", orders=rows)


@app.route("/orders/<int:order_id>")
@login_required
def customer_order_detail(order_id: int):
    db = get_db()
    order = db.execute(
        """
        SELECT id, total_amount, status, payment_provider, payment_status, shipping_address, created_at
        FROM orders
        WHERE id = ? AND user_id = ?
        """,
        (order_id, session["user_id"]),
    ).fetchone()
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("customer_orders"))
    items = db.execute(
        """
        SELECT oi.quantity, oi.unit_price, m.name
        FROM order_items oi
        JOIN medicines m ON m.id = oi.medicine_id
        WHERE oi.order_id = ?
        """,
        (order_id,),
    ).fetchall()
    return render_template("order_detail.html", order=order, items=items)


@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    user = current_user()
    db = get_db()
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            amount = 0.0
        if amount <= 0:
            flash("Enter a valid wallet top-up amount.", "danger")
            return redirect(url_for("wallet"))
        if adjust_wallet_balance(user["id"], amount, "CREDIT", "Wallet top-up"):
            flash("Wallet topped up successfully.", "success")
        else:
            flash("Unable to top up wallet.", "danger")
        return redirect(url_for("wallet"))

    balance_row = db.execute("SELECT wallet_balance FROM users WHERE id = ?", (user["id"],)).fetchone()
    balance = float(balance_row["wallet_balance"] or 0.0)
    txns = db.execute(
        """
        SELECT amount, txn_type, note, created_at
        FROM wallet_transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 20
        """,
        (user["id"],),
    ).fetchall()
    return render_template("wallet.html", balance=balance, txns=txns)


@app.route(ADMIN_ENTRY_PATH, methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute("SELECT * FROM users WHERE email = ? AND is_admin = 1", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["admin_id"] = user["id"]
            record_user_login(user["id"])
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "danger")
        return redirect(url_for("admin_login"))
    return render_template("admin/login.html")


@app.route(ADMIN_REGISTER_PATH, methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        reg_code = request.form.get("registration_code", "").strip()

        required_code = os.environ.get("ADMIN_REGISTRATION_CODE", "").strip()
        if required_code and reg_code != required_code:
            flash("Invalid admin registration code.", "danger")
            return redirect(url_for("admin_register"))

        if not name or not email or not password:
            flash("Name, email, and password are required.", "danger")
            return redirect(url_for("admin_register"))

        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("Email is already registered.", "warning")
            return redirect(url_for("admin_register"))
        db.execute(
            """
            INSERT INTO users (name, email, password_hash, is_admin, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (name, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
        flash("Admin registration successful. Please login.", "success")
        return redirect(url_for("admin_login"))
    return render_template("admin/register.html")

#Forgot Password
@app.route(ADMIN_FORGOT_PATH, methods=["GET", "POST"])
def admin_forgot_password():
    if request.method == "POST":
        action = request.form.get("action", "send_otp")
        email = request.form.get("email", "").strip().lower()
        otp = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", "")

        # Send OTP
        if action == "send_otp":
            admin_user = get_db().execute(
                "SELECT * FROM users WHERE email = ? AND is_admin = 1",
                (email,)
            ).fetchone()

            if not admin_user:
                flash("Admin account not found.", "warning")
                return redirect(url_for("admin_forgot_password"))

            generated = send_otp_to_session(
                "admin_reset_password",
                email
            )

            # OTP terminal me show hoga
            send_email_otp(email, generated)

            flash("OTP sent. Check terminal output.", "info")
            return redirect(url_for("admin_forgot_password"))

        # Verify OTP + Reset Password
        if not email or not otp or not new_password:
            flash("Email, OTP, and new password are required.", "danger")
            return redirect(url_for("admin_forgot_password"))

        ok, message = verify_otp_from_session(
            "admin_reset_password",
            email,
            otp
        )

        if not ok:
            flash(message, "danger")
            return redirect(url_for("admin_forgot_password"))

        db = get_db()

        admin_user = db.execute(
            "SELECT * FROM users WHERE email = ? AND is_admin = 1",
            (email,)
        ).fetchone()

        if not admin_user:
            flash("Admin account not found.", "warning")
            return redirect(url_for("admin_forgot_password"))

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (
                generate_password_hash(new_password),
                admin_user["id"]
            )
        )

        db.commit()

        flash("Password reset successful. Please login.", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin/forgot_password.html")

# Admin Logout
@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_id", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    totals = {
        "users": db.execute("SELECT COUNT(*) FROM users WHERE is_admin = 0").fetchone()[0],
        "medicines": db.execute("SELECT COUNT(*) FROM medicines").fetchone()[0],
        "orders": db.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        "sales": db.execute("SELECT COALESCE(SUM(total_amount), 0) FROM orders").fetchone()[0],
    }
    recent_orders = db.execute("SELECT o.*, u.name AS user_name FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.created_at DESC LIMIT 8").fetchall()
    return render_template("admin/dashboard.html", totals=totals, recent_orders=recent_orders)


@app.route("/admin/medicines")
@admin_required
def admin_medicines():
    rows = get_db().execute("SELECT * FROM medicines ORDER BY created_at DESC").fetchall()
    return render_template("admin/medicines.html", medicines=rows)


@app.route("/admin/medicines/add", methods=["GET", "POST"])
@admin_required
def admin_add_medicine():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        try:
            price = float(request.form.get("price", "0"))
            stock = int(request.form.get("stock", "0"))
        except ValueError:
            flash("Invalid price or stock value.", "danger")
            return redirect(url_for("admin_add_medicine"))
        prescription_required = 1 if request.form.get("prescription_required") else 0
        if not name or not category:
            flash("Name and category are required.", "danger")
            return redirect(url_for("admin_add_medicine"))
        image_filename = ""
        image = request.files.get("image")
        if image and image.filename:
            if not allowed_file(image.filename, ALLOWED_IMAGE_EXT):
                flash("Invalid image format. Allowed: JPG, PNG.", "danger")
                return redirect(url_for("admin_add_medicine"))
            original = secure_filename(image.filename)
            extension = original.rsplit(".", 1)[1].lower()
            image_filename = f"med_{uuid.uuid4().hex}.{extension}"
            image.save(os.path.join(UPLOAD_MEDICINES, image_filename))
        db = get_db()
        db.execute("INSERT INTO medicines (name, category, description, price, stock, prescription_required, image_filename, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (name, category, description, price, stock, prescription_required, image_filename, datetime.now(timezone.utc).isoformat()))
        db.commit()
        flash("Medicine added successfully.", "success")
        return redirect(url_for("admin_medicines"))
    return render_template("admin/add_medicine.html")


@app.route("/admin/medicines/edit/<int:medicine_id>", methods=["GET", "POST"])
@admin_required
def admin_edit_medicine(medicine_id: int):
    db = get_db()
    medicine = db.execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not medicine:
        flash("Medicine not found.", "warning")
        return redirect(url_for("admin_medicines"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        try:
            price = float(request.form.get("price", "0"))
            stock = int(request.form.get("stock", "0"))
        except ValueError:
            flash("Invalid price or stock value.", "danger")
            return redirect(url_for("admin_edit_medicine", medicine_id=medicine_id))
        prescription_required = 1 if request.form.get("prescription_required") else 0
        image_filename = medicine["image_filename"] or ""
        image = request.files.get("image")
        if image and image.filename:
            if not allowed_file(image.filename, ALLOWED_IMAGE_EXT):
                flash("Invalid image format. Allowed: JPG, PNG.", "danger")
                return redirect(url_for("admin_edit_medicine", medicine_id=medicine_id))
            original = secure_filename(image.filename)
            extension = original.rsplit(".", 1)[1].lower()
            image_filename = f"med_{uuid.uuid4().hex}.{extension}"
            image.save(os.path.join(UPLOAD_MEDICINES, image_filename))
        db.execute("UPDATE medicines SET name = ?, category = ?, description = ?, price = ?, stock = ?, prescription_required = ?, image_filename = ? WHERE id = ?", (name, category, description, price, stock, prescription_required, image_filename, medicine_id))
        db.commit()
        flash("Medicine updated successfully.", "success")
        return redirect(url_for("admin_medicines"))
    return render_template("admin/edit_medicine.html", medicine=medicine)


@app.route("/admin/medicines/delete/<int:medicine_id>", methods=["POST"])
@admin_required
def admin_delete_medicine(medicine_id: int):
    db = get_db()
    db.execute("DELETE FROM medicines WHERE id = ?", (medicine_id,))
    db.commit()
    flash("Medicine deleted.", "info")
    return redirect(url_for("admin_medicines"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    rows = get_db().execute("SELECT o.*, u.name AS user_name, u.email AS user_email FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.created_at DESC").fetchall()
    return render_template("admin/orders.html", orders=rows)


@app.route("/admin/orders/<int:order_id>", methods=["GET", "POST"])
@admin_required
def admin_order_detail(order_id: int):
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action", "update_status")
        if action == "mark_payment_received":
            db.execute(
                "UPDATE orders SET payment_status = 'Paid' WHERE id = ?",
                (order_id,),
            )
            db.commit()
            flash("Payment marked as received.", "success")
        else:
            status = request.form.get("status", "Pending")
            db.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
            db.commit()
            flash("Order status updated.", "success")
        return redirect(url_for("admin_order_detail", order_id=order_id))
    order = db.execute("SELECT o.*, u.name AS user_name, u.email AS user_email, u.phone AS user_phone FROM orders o JOIN users u ON u.id = o.user_id WHERE o.id = ?", (order_id,)).fetchone()
    if not order:
        flash("Order not found.", "warning")
        return redirect(url_for("admin_orders"))
    items = db.execute("SELECT oi.quantity, oi.unit_price, m.name FROM order_items oi JOIN medicines m ON m.id = oi.medicine_id WHERE oi.order_id = ?", (order_id,)).fetchall()
    prescription = db.execute("SELECT * FROM prescriptions WHERE order_id = ?", (order_id,)).fetchone()
    statuses = ["Pending", "Confirmed", "Packed", "Shipped", "Delivered", "Cancelled"]
    return render_template("admin/order_detail.html", order=order, items=items, prescription=prescription, statuses=statuses)


@app.route("/admin/users")
@admin_required
def admin_users():
    rows = get_db().execute(
        """
        SELECT id, name, email, phone, address, created_at, last_login_at, last_login_ip, login_count
        FROM users
        WHERE is_admin = 0
        ORDER BY created_at DESC
        """
    ).fetchall()
    return render_template("admin/users.html", users=rows)

@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "service": "Healthcare Pharmacy API"})


@app.route("/api/auth/register", methods=["POST"])
def api_auth_register():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    phone = str(data.get("phone", "")).strip()
    address = str(data.get("address", "")).strip()
    if not name or not email or not password:
        return jsonify({"ok": False, "error": "name, email, password are required"}), 400
    db = get_db()
    if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"ok": False, "error": "Email already registered"}), 409
    db.execute("INSERT INTO users (name, email, password_hash, phone, address, created_at) VALUES (?, ?, ?, ?, ?, ?)", (name, email, generate_password_hash(password), phone, address, datetime.now(timezone.utc).isoformat()))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return jsonify({"ok": True, "token": generate_access_token(user), "user": serialize_user(user)})


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    return jsonify({"ok": True, "token": generate_access_token(user), "user": serialize_user(user)})


@app.route("/api/auth/me")
def api_auth_me():
    user = api_current_user()
    if not user:
        return jsonify({"ok": True, "authenticated": False, "user": None})
    return jsonify({"ok": True, "authenticated": True, "user": serialize_user(user)})


@app.route("/api/medicines")
def api_medicines():
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    query = "SELECT * FROM medicines WHERE 1=1"
    params = []
    if q:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY name"
    rows = get_db().execute(query, tuple(params)).fetchall()
    return jsonify({"ok": True, "items": [serialize_medicine(r) for r in rows]})


@app.route("/api/medicines/<int:medicine_id>")
def api_medicine_detail(medicine_id: int):
    row = get_db().execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Medicine not found"}), 404
    return jsonify({"ok": True, "item": serialize_medicine(row)})


@app.route("/api/cart")
@api_login_required
def api_cart():
    user = g.api_user
    items, total, requires_prescription = api_cart_details(user["id"])
    return jsonify({"ok": True, "items": [serialize_cart_item(i) for i in items], "total": total, "requires_prescription": requires_prescription, "count": sum(i["quantity"] for i in items)})


@app.route("/api/cart/add", methods=["POST"])
@api_login_required
def api_cart_add():
    user = g.api_user
    data = request.get_json(silent=True) or {}
    medicine_id = data.get("medicine_id")
    try:
        quantity = int(data.get("quantity", 1))
    except ValueError:
        return jsonify({"ok": False, "error": "quantity must be an integer"}), 400
    if not medicine_id:
        return jsonify({"ok": False, "error": "medicine_id is required"}), 400
    if quantity < 1:
        return jsonify({"ok": False, "error": "quantity must be >= 1"}), 400
    medicine = get_db().execute("SELECT * FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not medicine:
        return jsonify({"ok": False, "error": "Medicine not found"}), 404
    existing = get_db().execute("SELECT quantity FROM user_cart_items WHERE user_id = ? AND medicine_id = ?", (user["id"], medicine_id)).fetchone()
    current_qty = int(existing["quantity"]) if existing else 0
    set_api_cart_item(user["id"], int(medicine_id), min(current_qty + quantity, int(medicine["stock"])))
    return api_cart()


@app.route("/api/cart/update", methods=["POST"])
@api_login_required
def api_cart_update():
    user = g.api_user
    data = request.get_json(silent=True) or {}
    medicine_id = data.get("medicine_id")
    if not medicine_id:
        return jsonify({"ok": False, "error": "medicine_id is required"}), 400
    try:
        quantity = int(data.get("quantity", 0))
    except ValueError:
        return jsonify({"ok": False, "error": "quantity must be an integer"}), 400
    medicine = get_db().execute("SELECT stock FROM medicines WHERE id = ?", (medicine_id,)).fetchone()
    if not medicine:
        return jsonify({"ok": False, "error": "Medicine not found"}), 404
    quantity = min(quantity, int(medicine["stock"]))
    set_api_cart_item(user["id"], int(medicine_id), quantity)
    return api_cart()


@app.route("/api/cart/remove", methods=["POST"])
@api_login_required
def api_cart_remove():
    user = g.api_user
    data = request.get_json(silent=True) or {}
    medicine_id = data.get("medicine_id")
    if not medicine_id:
        return jsonify({"ok": False, "error": "medicine_id is required"}), 400
    set_api_cart_item(user["id"], int(medicine_id), 0)
    return api_cart()


@app.route("/api/payments/create-intent", methods=["POST"])
@api_login_required
def api_create_payment_intent():
    user = g.api_user
    data = request.get_json(silent=True) or {}
    provider = str(data.get("provider", "")).strip().lower()
    if provider not in {"stripe", "razorpay"}:
        return jsonify({"ok": False, "error": "provider must be stripe or razorpay"}), 400
    items, total, _ = api_cart_details(user["id"])
    if not items:
        return jsonify({"ok": False, "error": "Cart is empty"}), 400
    result = create_payment_intent(provider, total)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/payments/create-stripe-checkout-session", methods=["POST"])
@api_login_required
def api_create_stripe_checkout_session():
    user = g.api_user
    items, total, _ = api_cart_details(user["id"])
    if not items:
        return jsonify({"ok": False, "error": "Cart is empty"}), 400

    base = request.host_url.rstrip("/")
    success_url = f"{base}{url_for('checkout')}?stripe_session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base}{url_for('checkout')}?stripe_cancelled=1"
    result = create_stripe_checkout_session(total, success_url, cancel_url)
    if not result.get("ok"):
        return jsonify(result), 400
    return jsonify(result)


@app.route("/api/webhooks/stripe", methods=["POST"])
def api_webhook_stripe():
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")
    if not secret:
        return jsonify({"ok": False, "error": "STRIPE_WEBHOOK_SECRET not configured"}), 500
    if not verify_stripe_signature(payload, sig_header, secret):
        return jsonify({"ok": False, "error": "Invalid signature"}), 400

    data = request.get_json(silent=True) or {}
    event_type = data.get("type", "")
    obj = (data.get("data") or {}).get("object") or {}
    payment_reference = obj.get("id", "")
    if not payment_reference:
        return jsonify({"ok": True, "updated": 0})

    status_map = {
        "payment_intent.succeeded": "Paid",
        "payment_intent.payment_failed": "Failed",
        "payment_intent.canceled": "Cancelled",
        "payment_intent.processing": "Processing",
    }
    mapped = status_map.get(event_type)
    if not mapped:
        return jsonify({"ok": True, "updated": 0, "ignored_event": event_type})
    updated = update_order_payment_status(payment_reference, "stripe", mapped)
    return jsonify({"ok": True, "updated": updated, "event": event_type})


@app.route("/api/webhooks/razorpay", methods=["POST"])
def api_webhook_razorpay():
    secret = os.environ.get("RAZORPAY_WEBHOOK_SECRET", "")
    payload = request.get_data()
    sig_header = request.headers.get("X-Razorpay-Signature", "")
    if not secret:
        return jsonify({"ok": False, "error": "RAZORPAY_WEBHOOK_SECRET not configured"}), 500
    if not verify_razorpay_signature(payload, sig_header, secret):
        return jsonify({"ok": False, "error": "Invalid signature"}), 400

    data = request.get_json(silent=True) or {}
    event_type = data.get("event", "")
    entity = ((data.get("payload") or {}).get("order") or {}).get("entity") or {}
    payment_reference = entity.get("id", "")
    if not payment_reference:
        return jsonify({"ok": True, "updated": 0})

    status_map = {
        "payment.captured": "Paid",
        "payment.failed": "Failed",
        "order.paid": "Paid",
    }
    mapped = status_map.get(event_type)
    if not mapped:
        return jsonify({"ok": True, "updated": 0, "ignored_event": event_type})
    updated = update_order_payment_status(payment_reference, "razorpay", mapped)
    return jsonify({"ok": True, "updated": updated, "event": event_type})


@app.route("/api/checkout", methods=["POST"])
@api_login_required
def api_checkout():
    user = g.api_user
    items, total, requires_prescription = api_cart_details(user["id"])
    if not items:
        return jsonify({"ok": False, "error": "Cart is empty"}), 400
    if requires_prescription:
        return jsonify({"ok": False, "error": "Prescription items require web checkout with upload."}), 400
    data = request.get_json(silent=True) or {}
    shipping_address = (str(data.get("shipping_address", "")).strip() or (user["address"] or "").strip())
    payment_provider = str(data.get("payment_provider", "pay_on_delivery")).strip().lower()
    payment_reference = str(data.get("payment_reference", "")).strip() or None
    payment_status = str(data.get("payment_status", "Pending")).strip() or "Pending"
    if not shipping_address:
        return jsonify({"ok": False, "error": "shipping_address is required"}), 400
    allowed_providers = {"pay_on_delivery", "wallet", "stripe", "razorpay"}
    if payment_provider not in allowed_providers:
        return jsonify({"ok": False, "error": "payment_provider must be pay_on_delivery, wallet, stripe, or razorpay"}), 400
    if payment_provider in {"stripe", "razorpay"} and not payment_reference:
        return jsonify({"ok": False, "error": "payment_reference is required for online payments"}), 400
    if payment_provider == "wallet":
        wallet_row = get_db().execute("SELECT wallet_balance FROM users WHERE id = ?", (user["id"],)).fetchone()
        wallet_balance = float(wallet_row["wallet_balance"] or 0.0)
        if wallet_balance < total:
            return jsonify({"ok": False, "error": "Insufficient wallet balance"}), 400
        payment_reference = f"WALLET_{uuid.uuid4().hex[:12].upper()}"
        payment_status = "Paid"
    for item in items:
        if item["quantity"] > item["medicine"]["stock"]:
            return jsonify({"ok": False, "error": f"Insufficient stock for {item['medicine']['name']}"}), 400
    order_id = create_order_for_user(user, shipping_address, items, total, payment_provider=payment_provider, payment_reference=payment_reference, payment_status=payment_status)
    if payment_provider == "wallet":
        adjust_wallet_balance(user["id"], -total, "DEBIT", f"Order #{order_id} payment")
    clear_api_cart(user["id"])
    return jsonify({"ok": True, "order_id": order_id, "total_amount": total})


@app.route("/api/orders")
@api_login_required
def api_orders():
    user = g.api_user
    rows = get_db().execute("SELECT id, total_amount, status, payment_provider, payment_reference, payment_status, shipping_address, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC", (user["id"],)).fetchall()
    return jsonify({"ok": True, "items": [dict(r) for r in rows]})


@app.route("/api/orders/<int:order_id>")
@api_login_required
def api_order_detail(order_id: int):
    user = g.api_user
    db = get_db()
    order = db.execute("SELECT id, total_amount, status, payment_provider, payment_reference, payment_status, shipping_address, created_at FROM orders WHERE id = ? AND user_id = ?", (order_id, user["id"])).fetchone()
    if not order:
        return jsonify({"ok": False, "error": "Order not found"}), 404
    items = db.execute("SELECT oi.quantity, oi.unit_price, m.name FROM order_items oi JOIN medicines m ON m.id = oi.medicine_id WHERE oi.order_id = ?", (order_id,)).fetchall()
    return jsonify({"ok": True, "order": dict(order), "items": [dict(i) for i in items]})


def bootstrap_app() -> None:
    ensure_dirs()
    if not os.path.exists(DB_PATH):
        from init_db import init_db

        init_db()
    with app.app_context():
        ensure_db_migrations()


bootstrap_app()


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
