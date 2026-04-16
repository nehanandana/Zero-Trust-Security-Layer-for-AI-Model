from flask import Flask, request, jsonify
import bcrypt
import re
import sqlite3
from contextlib import contextmanager
import jwt
import datetime
from functools import wraps
import os

app = Flask(__name__)

# ================= CONFIG =================
DATABASE_PATH = 'users.db'
SECRET_KEY = "super_secret_key"
TOKEN_EXPIRY_SECONDS = 5

# ================= DATABASE =================
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_database():
    # Ensure fresh DB for testing consistency
    if not os.path.exists(DATABASE_PATH):
        with get_db_connection() as conn:
            with open('schema.sql', 'r') as f:
                conn.executescript(f.read())
        print("Database initialized")

# ================= HELPERS =================
def hash_password(password):
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def validate_password_strength(password):
    if len(password) < 8:
        return False, "Min 8 characters required"
    if not re.search(r'[A-Z]', password):
        return False, "Need uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Need lowercase letter"
    if not re.search(r'\d', password):
        return False, "Need number"
    return True, "Strong"

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def user_exists(username=None, email=None):
    with get_db_connection() as conn:
        if username:
            if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return True
        if email:
            if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                return True
    return False

def create_user(username, email, password_hash):
    with get_db_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        return cur.lastrowid

def get_user_by_username(username):
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

# ================= JWT MIDDLEWARE =================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token missing or invalid format"}), 401

        token = auth_header.split(" ")[1]

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'role' not in request.user:
                return jsonify({"error": "Access denied"}), 403
            if request.user['role'] != role:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return wrapper

# ================= ROUTES =================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "message": "Server is working!"})

# -------- REGISTER --------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username:
            return jsonify({"success": False, "error": "Username required"}), 400
        if not email:
            return jsonify({"success": False, "error": "Email required"}), 400
        if not password:
            return jsonify({"success": False, "error": "Password required"}), 400

        if not validate_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400

        valid, msg = validate_password_strength(password)
        if not valid:
            return jsonify({"success": False, "error": msg}), 400

        if user_exists(username=username):
            return jsonify({"success": False, "error": "Username already exists"}), 409
        if user_exists(email=email):
            return jsonify({"success": False, "error": "Email already registered"}), 409

        password_hash = hash_password(password)
        user_id = create_user(username, email, password_hash)

        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "user_id": user_id
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# -------- LOGIN --------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = get_user_by_username(username)

        if not user or not check_password(password, user['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401

        token = jwt.encode({
            "user_id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRY_SECONDS)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------- PROTECTED --------
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    return jsonify({"message": f"Welcome {request.user['username']}"})

@app.route('/admin', methods=['GET'])
@token_required
@role_required('admin')
def admin():
    return jsonify({"message": "Admin access granted"})

# ================= MAIN =================
if __name__ == '__main__':
    init_database()
    app.run(debug=True)
