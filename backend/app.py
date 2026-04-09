from flask import Flask, request, jsonify
import bcrypt
import re
import sqlite3
from contextlib import contextmanager

app = Flask(__name__)

# ============ DATABASE SETUP ============
DATABASE_PATH = 'users.db'

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
    """Create database using schema.sql file"""
    with get_db_connection() as conn:
        # Read and execute schema.sql
        with open('schema.sql', 'r') as f:
            schema_sql = f.read()
            conn.executescript(schema_sql)
        print("Database initialized from schema.sql")
# ============ PASSWORD HASHING ============
def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def validate_password_strength(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must have an uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must have a lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must have a number"
    return True, "Password is strong"

def validate_email(email):
    """Check email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def user_exists(username=None, email=None):
    """Check if user exists"""
    with get_db_connection() as conn:
        if username:
            result = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if result:
                return True
        if email:
            result = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if result:
                return True
    return False

def create_user(username, email, password_hash):
    """Save user to database"""
    with get_db_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
        return cursor.lastrowid

# ============ REGISTRATION API ============
@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Check required fields
        if not username:
            return jsonify({"success": False, "error": "Username required"}), 400
        if not email:
            return jsonify({"success": False, "error": "Email required"}), 400
        if not password:
            return jsonify({"success": False, "error": "Password required"}), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
        
        # Validate password
        is_valid, msg = validate_password_strength(password)
        if not is_valid:
            return jsonify({"success": False, "error": msg}), 400
        
        # Check duplicates
        if user_exists(username=username):
            return jsonify({"success": False, "error": "Username already exists"}), 409
        if user_exists(email=email):
            return jsonify({"success": False, "error": "Email already registered"}), 409
        
        # Hash password and create user
        password_hash = hash_password(password)
        user_id = create_user(username, email, password_hash)
        
        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "user_id": user_id,
            "username": username
        }), 201
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "message": "Server is working!"})

# ============ RUN THE SERVER ============
if __name__ == '__main__':
    init_database()
    print("Server is starting...")
    print("Registration API: http://127.0.0.1:5000/register")
    print("Health check: http://127.0.0.1:5000/health")
    print("Press CTRL+C to stop the server")
    app.run(debug=True, host='127.0.0.1', port=5000)