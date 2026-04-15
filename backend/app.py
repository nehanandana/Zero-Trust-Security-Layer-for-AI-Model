from flask import Flask, request, jsonify, g
import bcrypt
import re
import sqlite3
from contextlib import contextmanager
import jwt
import datetime
from functools import wraps
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'  # Change this!

# ============ CONFIGURATION ============
DATABASE_PATH = 'users.db'
JWT_EXPIRATION_HOURS = 24
JWT_REFRESH_EXPIRATION_DAYS = 7
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ============ DATABASE SETUP ============
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
        
        # Add login tracking columns if not exists
        try:
            conn.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0")
            conn.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP")
            conn.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
        except sqlite3.OperationalError:
            pass  # Columns already exist
        
        print("Database initialized from schema.sql")

# ============ PASSWORD HASHING ============
def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

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

# ============ JWT FUNCTIONS ============
def generate_token(user_id, username, role='user'):
    """Generate JWT token for authenticated user"""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.datetime.utcnow(),
        'jti': str(int(time.time()))  # Unique token ID
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def generate_refresh_token(user_id, username):
    """Generate refresh token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'type': 'refresh',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

# ============ AUTHENTICATION MIDDLEWARE ============
def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is missing'}), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload, error = decode_token(token)
        if error:
            return jsonify({'success': False, 'error': error}), 401
        
        # Check if token is refresh token (not for API access)
        if payload.get('type') == 'refresh':
            return jsonify({'success': False, 'error': 'Invalid token type'}), 401
        
        g.user_id = payload['user_id']
        g.username = payload['username']
        g.user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated

def role_required(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if g.user_role != required_role and g.user_role != 'admin':
                return jsonify({'success': False, 'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============ USER MANAGEMENT FUNCTIONS ============
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

def get_user_by_username(username):
    """Get user by username"""
    with get_db_connection() as conn:
        return conn.execute(
            "SELECT id, username, email, password_hash, role, login_attempts, locked_until FROM users WHERE username = ?",
            (username,)
        ).fetchone()

def update_login_attempts(username, success=False):
    """Update login attempts tracking"""
    with get_db_connection() as conn:
        if success:
            conn.execute(
                "UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?",
                (username,)
            )
        else:
            conn.execute(
                "UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?",
                (username,)
            )

def is_account_locked(user):
    """Check if account is locked"""
    if user and user['locked_until']:
        lock_time = datetime.datetime.fromisoformat(user['locked_until'].replace('Z', '+00:00'))
        if datetime.datetime.now() < lock_time:
            return True, lock_time
    return False, None

def lock_account(username):
    """Lock account for specified duration"""
    lock_until = datetime.datetime.now() + datetime.timedelta(minutes=LOCKOUT_MINUTES)
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET locked_until = ? WHERE username = ?",
            (lock_until.isoformat(), username)
        )

def revoke_all_tokens(user_id):
    """Revoke all tokens for a user (for session tampering protection)"""
    # In production, maintain a blacklist table
    # For now, we'll just update a token_version field
    with get_db_connection() as conn:
        try:
            conn.execute("ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        conn.execute(
            "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
            (user_id,)
        )

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

# ============ LOGIN API ============
@app.route('/login', methods=['POST'])
def login():
    """User login endpoint - returns JWT token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password required"}), 400
        
        # Get user from database
        user = get_user_by_username(username)
        
        if not user:
            # Don't reveal that user doesn't exist
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
        
        # Check if account is locked
        is_locked, lock_time = is_account_locked(user)
        if is_locked:
            return jsonify({
                "success": False, 
                "error": f"Account locked. Try again after {lock_time.strftime('%Y-%m-%d %H:%M:%S')}"
            }), 401
        
        # Verify password
        if not verify_password(password, user['password_hash']):
            # Increment login attempts
            update_login_attempts(username, success=False)
            
            # Lock account if max attempts reached
            new_attempts = user['login_attempts'] + 1 if user['login_attempts'] else 1
            if new_attempts >= MAX_LOGIN_ATTEMPTS:
                lock_account(username)
                return jsonify({
                    "success": False,
                    "error": f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes"
                }), 401
            
            remaining = MAX_LOGIN_ATTEMPTS - new_attempts
            return jsonify({
                "success": False,
                "error": f"Invalid credentials. {remaining} attempts remaining"
            }), 401
        
        # Successful login - reset attempts and update last login
        update_login_attempts(username, success=True)
        
        # Generate tokens
        access_token = generate_token(user['id'], user['username'], user['role'])
        refresh_token = generate_refresh_token(user['id'], user['username'])
        
        return jsonify({
            "success": True,
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "role": user['role']
            },
            "expires_in_hours": JWT_EXPIRATION_HOURS
        }), 200
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============ TOKEN REFRESH API ============
@app.route('/refresh', methods=['POST'])
def refresh_token():
    """Refresh expired access token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({"success": False, "error": "Refresh token required"}), 400
        
        payload, error = decode_token(refresh_token)
        if error or payload.get('type') != 'refresh':
            return jsonify({"success": False, "error": "Invalid refresh token"}), 401
        
        # Generate new access token
        new_access_token = generate_token(payload['user_id'], payload['username'])
        
        return jsonify({
            "success": True,
            "access_token": new_access_token
        }), 200
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ============ LOGOUT API ============
@app.route('/logout', methods=['POST'])
@token_required
def logout():
    """Logout user"""
    # In production, add token to blacklist
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    }), 200

# ============ PROTECTED ROUTES (For Testing) ============
@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """Get current user profile (requires authentication)"""
    return jsonify({
        "success": True,
        "user": {
            "id": g.user_id,
            "username": g.username,
            "role": g.user_role
        }
    }), 200

@app.route('/admin/dashboard', methods=['GET'])
@role_required('admin')
def admin_dashboard():
    """Admin only route"""
    return jsonify({
        "success": True,
        "message": "Welcome to Admin Dashboard",
        "admin": g.username
    }), 200

@app.route('/user/dashboard', methods=['GET'])
@token_required
def user_dashboard():
    """User dashboard (any authenticated user)"""
    return jsonify({
        "success": True,
        "message": f"Welcome {g.username} to your dashboard",
        "role": g.user_role
    }), 200

# ============ HEALTH CHECK ============
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "message": "Server is working!"})

# ============ RUN THE SERVER ============
if __name__ == '__main__':
    init_database()
    print("=" * 50)
    print("Server is starting...")
    print("Registration API: http://127.0.0.1:5000/register")
    print("Login API: http://127.0.0.1:5000/login")
    print("Health check: http://127.0.0.1:5000/health")
    print("=" * 50)
    print("Press CTRL+C to stop the server")
    app.run(debug=True, host='127.0.0.1', port=5000)
