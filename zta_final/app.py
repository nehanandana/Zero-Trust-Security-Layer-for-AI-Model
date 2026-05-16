from trust_engine import update_trust_score, check_rate_limit, make_decision
from flask import Flask, request, jsonify # type: ignore
from flask_cors import CORS  # type: ignore # Add this for frontend connectivity
from mfa_helper import MFAHelper # type: ignore
import bcrypt # type: ignore
import re
import sqlite3
from contextlib import contextmanager
import jwt # type: ignore
import datetime
from functools import wraps
import os
import time
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response
# ================= CONFIG =================
DATABASE_PATH = 'users.db'

# --- ADVANCED KEY MANAGEMENT ---
KEY_FILE = '.secret.key'
def get_or_create_secret_key():
    
    if not os.path.exists(KEY_FILE):
        new_key = secrets.token_hex(64)
        with open(KEY_FILE, 'w') as f:
            f.write(new_key)
    with open(KEY_FILE, 'r') as f:
        return f.read().strip()
SECRET_KEY = get_or_create_secret_key()
ACCESS_TOKEN_EXPIRY_SECONDS = 300  
REFRESH_TOKEN_EXPIRY_SECONDS = 86400  

# ================= DATABASE =================
@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_PATH, timeout=20)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Database error: {e}")
        raise e
    finally:
        if conn:
            conn.close()

def init_database():
    # Ensure fresh DB for testing consistency
    if not os.path.exists(DATABASE_PATH):
        with get_db_connection() as conn:
            with open('schema.sql', 'r') as f:
                conn.executescript(f.read())
        print("Database initialized")
       
        # Create default admin user
        create_default_admin()
       



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
def sync_trust_score_to_db(user_id):
    """Sync in-memory trust score to database"""
    from trust_engine import user_data
    user_id_str = str(user_id)
    if user_id_str in user_data:
        score = user_data[user_id_str]['score']
        with get_db_connection() as conn:
            conn.execute("UPDATE users SET trust_score = ? WHERE id = ?", (score, user_id))
        return score
    return None

def create_user(username, email, password_hash, mfa_secret=None, mfa_enabled=0):
    with get_db_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, is_blocked, mfa_secret, mfa_enabled) VALUES (?, ?, ?, ?, ?, ?)",
            (username, email, password_hash, 0, mfa_secret, mfa_enabled)
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
            # Verify it's an access token
            if data.get('type') != 'access':
                return jsonify({"error": "Invalid token type"}), 401
            request.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Token expired",
                "code": "TOKEN_EXPIRED"
            }), 401
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401

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
        
        # Generate MFA secret and QR code for the new user
        mfa_secret = MFAHelper.generate_secret()
        mfa_uri = MFAHelper.get_totp_uri(mfa_secret, username)
        mfa_qr_code = MFAHelper.generate_qr_code(mfa_uri)

        user_id = create_user(username, email, password_hash, mfa_secret=mfa_secret, mfa_enabled=0)

        return jsonify({
            "success": True,
            "message": "User registered successfully. Please complete MFA setup.",
            "user_id": user_id,
            "mfa_setup": {
                "secret": mfa_secret,
                "qr_code": mfa_qr_code,
                "uri": mfa_uri
            }
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# -------- LOGIN (with Access & Refresh Tokens) --------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        mfa_code = data.get('mfa_code')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = get_user_by_username(username)

        if not user or not check_password(password, user['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401

        # Check if user is blocked
        if user['is_blocked'] == 1:
            return jsonify({
                "error": "Account blocked",
                "reason": user['blocked_reason'] or "Security violation",
                "contact": "Contact admin for support"
            }), 403
        
        # Check MFA - NOW COMPULSORY!
        mfa_enabled = user['mfa_enabled'] == 1 if 'mfa_enabled' in user.keys() else False
        
        # If MFA is NOT enabled, force user to setup MFA first
        if not mfa_enabled:
            return jsonify({
                "error": "MFA setup required",
                "mfa_required": True,
                "mfa_setup_needed": True,
                "message": "You must setup Multi-Factor Authentication before accessing the system"
            }), 401
        
        # MFA is enabled, verify the code
        if not mfa_code:
            return jsonify({
                "error": "MFA code required",
                "mfa_required": True
            }), 401
        
        # Verify MFA code
        secret = user['mfa_secret']
        if not MFAHelper.verify_totp(secret, mfa_code):
            return jsonify({"error": "Invalid MFA code"}), 401

        # Load user's trust score from database into memory
        from trust_engine import initialize_user, user_data
        initialize_user(str(user['id']))
        user_data[str(user['id'])]['score'] = user['trust_score']

        # Create ACCESS token (short lived)
        access_token = jwt.encode({
            "user_id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "mfa_verified": True,
            "type": "access",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ACCESS_TOKEN_EXPIRY_SECONDS)
        }, SECRET_KEY, algorithm="HS256")

        # Create REFRESH token (long lived)
        refresh_token = jwt.encode({
            "user_id": user['id'],
            "type": "refresh",
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=REFRESH_TOKEN_EXPIRY_SECONDS)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": ACCESS_TOKEN_EXPIRY_SECONDS,
            "token_type": "Bearer",
            "mfa_enabled": True
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------- REFRESH TOKEN --------
@app.route('/refresh', methods=['POST'])
def refresh():
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')

        if not refresh_token:
            return jsonify({"error": "Refresh token required"}), 400

        try:
            # Decode the refresh token
            token_data = jwt.decode(refresh_token, SECRET_KEY, algorithms=["HS256"])
            
            if token_data.get('type') != 'refresh':
                return jsonify({"error": "Invalid token type"}), 401
                
            user_id = token_data.get('user_id')
            
            # Fetch user to ensure they still exist and get latest info
            with get_db_connection() as conn:
                user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
                
            if not user:
                return jsonify({"error": "User not found"}), 404
                
            if user['is_blocked'] == 1:
                return jsonify({"error": "Account blocked"}), 403

            # Create new ACCESS token
            access_token = jwt.encode({
                "user_id": user['id'],
                "username": user['username'],
                "role": user['role'],
                "mfa_verified": True,
                "type": "access",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ACCESS_TOKEN_EXPIRY_SECONDS)
            }, SECRET_KEY, algorithm="HS256")

            return jsonify({
                "access_token": access_token,
                "expires_in": ACCESS_TOKEN_EXPIRY_SECONDS,
                "token_type": "Bearer"
            })

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Refresh token expired"}), 401
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ================= NEW ENDPOINTS FOR FRONTEND (MEMBER 4) =================

@app.route('/user/<username>', methods=['GET'])
@token_required
def get_user_info(username):
    """Get user info including trust score for frontend display"""
    requesting_username = request.user.get('username')
    requesting_role = request.user.get('role')
   
    if requesting_username != username and requesting_role != 'admin':
        return jsonify({"error": "Access denied"}), 403
   
    user = get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
   
    from trust_engine import user_data
    user_id = user['id']
    trust_score = user_data.get(user_id, {}).get('score', user['trust_score'])
   
    return jsonify({
        "username": user['username'],
        "role": user['role'],
        "trust_score": trust_score,
        "user_id": user['id'],
        "email": user['email']
    })



# -------- CHAT (YOUR MODULE INTEGRATION) --------
@app.route('/chat', methods=['POST'])
@token_required
def chat():
    from prompt_filter import classify_prompt, log_prompt
    from trust_engine import user_data, initialize_user
   
    user_id = request.user.get("user_id")
    user_role = request.user.get("role")

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT is_blocked, blocked_reason, trust_score FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
       
        if user and user['is_blocked'] and user_role != 'admin':
            return jsonify({
                "status": "blocked",
                "reason": f"Your account has been blocked. Reason: {user['blocked_reason']}",
                "contact": "Contact admin for support"
            }), 403
            
        user_id_str = str(user_id)
        if user_id_str not in user_data and user:
            initialize_user(user_id_str)
            user_data[user_id_str]['score'] = user['trust_score']
    data = request.get_json()
    prompt = data.get("prompt")

    if not prompt:
        return jsonify({"error": "Prompt required"}), 400


    # Step 1: Prompt analysis
    risk = classify_prompt(prompt)
    log_prompt(user_id, prompt, risk)

    # Step 2: Normalize risk (Safe → safe)
    risk_lower = risk.lower()

    # Step 3: Rate limiting
    if not check_rate_limit(user_id):
        return jsonify({
            "status": "blocked",
            "reason": "Too many requests"
        }), 429

     # Step 4: Update trust score - SKIP for admin!
    if user_role == 'admin':
        # Admin immune - score stays the same
        score = user_data.get(str(user_id), {}).get("score", 100)
        decision = "ALLOW"  # Always allow admin
    else:
        score = update_trust_score(user_id, risk_lower)
        decision = make_decision(user_id)

        sync_trust_score_to_db(user_id)
   
        # Auto-block user if trust score is too low (only for non-admin)
        if score <= 40:
            with get_db_connection() as conn:
                conn.execute("""
                    UPDATE users
                    SET is_blocked = 1, blocked_reason = 'Trust score too low - automatic block', trust_score = ?
                    WHERE id = ? AND is_blocked = 0
                """, (score, user_id))

    # Step 5: Apply decision for non-admin users
    if user_role != 'admin':
        if decision == "BLOCK":
            return jsonify({
                "status": "blocked",
                "reason": "Low trust score",
                "trust_score": score
            }), 403

        elif decision == "RESTRICT":
            return jsonify({
                "status": "restricted",
                "response": "Limited response due to suspicious activity",
                "trust_score": score
            }), 200
   

    # Step 6: If allowed → normal response
    return jsonify({
        "status": "success",
        "response": f"AI Response to: {prompt}",
        "risk": risk,
        "trust_score": score,
        "decision": decision
    })

   


# ================= ADMIN ROUTES =================

# 1. View all users
@app.route('/admin/users', methods=['GET'])
@token_required
@role_required('admin')
def admin_get_users():
    with get_db_connection() as conn:
        users = conn.execute("""
            SELECT id, username, email, role, trust_score, is_blocked, created_at
            FROM users
            ORDER BY id
        """).fetchall()
   
    return jsonify({
        "users": [dict(user) for user in users]
    })


# 5. Unblock a user
@app.route('/admin/unblock-user/<int:user_id>', methods=['POST'])
@token_required
@role_required('admin')
def admin_unblock_user(user_id):
    try:
        print(f"Unblocking user: {user_id}")
        RESET_TRUST_SCORE = 60
        for attempt in range(3):
            try:
                with get_db_connection() as conn:
                    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                    if not user:
                        return jsonify({"error": "User not found"}), 404
                   
                    print(f"Found user: {user['username']}, is_blocked: {user['is_blocked']}")
                   
                    conn.execute("""
                        UPDATE users
                        SET is_blocked = 0, blocked_at = NULL, blocked_reason = NULL, trust_score = ?
                        WHERE id = ?
                    """, (RESET_TRUST_SCORE,user_id,))
                   
                    break
            except sqlite3.OperationalError as e:
                if "database is locked" in str(e) and attempt < 2:
                    print(f"Database locked, retrying...")
                    time.sleep(0.5)
                    continue
                raise e
       
        # Reset trust score in memory
        from trust_engine import initialize_user, user_data
        initialize_user(str(user_id))
        if str(user_id) in user_data:
            user_data[str(user_id)]['score'] = RESET_TRUST_SCORE
            user_data[str(user_id)]['request_count'] = 0
            user_data[str(user_id)]['last_request'] = time.time()
       
        # Sync to ensure consistency
        sync_trust_score_to_db(user_id)
       
        return jsonify({
            "success": True,
            "message": f"User has been unblocked with trust score reset to {RESET_TRUST_SCORE}"
        })
       
    except Exception as e:
        print(f"Error in unblock: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# 6. Get user details with their COMPLETE history (for blocked users)
@app.route('/admin/user-details/<int:user_id>', methods=['GET'])
@token_required
@role_required('admin')
def admin_user_details(user_id):
    with get_db_connection() as conn:
        # Get user info
        user = conn.execute("""
            SELECT id, username, email, role, trust_score, is_blocked, blocked_reason, created_at
            FROM users WHERE id = ?
        """, (user_id,)).fetchone()
       
        if not user:
            return jsonify({"error": "User not found"}), 404
       
        # Get their malicious prompts from database
        malicious_prompts = conn.execute("""
            SELECT prompt, risk, action, created_at
            FROM malicious_logs
            WHERE user_id = ?
            ORDER BY created_at DESC
        """, (user_id,)).fetchall()
       
        # ENHANCED: Get ALL prompts from text file (Safe, Suspicious, Malicious)
        all_user_logs = []
        prompt_summary = {"safe": 0, "suspicious": 0, "malicious": 0}
       
        try:
            with open('prompt_logs.txt', 'r') as f:
                for line in f:
                    if f"| {user_id} |" in line:
                        all_user_logs.append(line.strip())
                        # Count by risk type
                        if "| Safe |" in line:
                            prompt_summary["safe"] += 1
                        elif "| Suspicious |" in line:
                            prompt_summary["suspicious"] += 1
                        elif "| Malicious |" in line:
                            prompt_summary["malicious"] += 1
        except FileNotFoundError:
            pass  # No logs file yet
       
        # Parse logs into structured format
        structured_logs = []
        for log in all_user_logs[-50:]:  # Last 50 logs
            parts = log.split(' | ')
            if len(parts) >= 5:
                structured_logs.append({
                    "timestamp": parts[0],
                    "risk": parts[2],
                    "action": parts[3],
                    "prompt": parts[4]
                })
   
    return jsonify({
        "user": dict(user),
        "summary": {
            "total_prompts": len(all_user_logs),
            "safe_count": prompt_summary["safe"],
            "suspicious_count": prompt_summary["suspicious"],
            "malicious_count": prompt_summary["malicious"],
            "malicious_in_database": len(malicious_prompts)
        },
        "malicious_prompts": [dict(p) for p in malicious_prompts],
        "all_recent_prompts": structured_logs,  # Last 50 prompts of ALL types
        "blocked_info": {
            "is_blocked": user['is_blocked'],
            "blocked_reason": user['blocked_reason'] if user['is_blocked'] else None
        }
    })

# ================= admin creation =================
def create_default_admin():
    """Create default admin user if none exists"""
    with get_db_connection() as conn:
        admin_exists = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin'"
        ).fetchone()
       
        if not admin_exists:
            admin_password_hash = hash_password("Admin123!")
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role, trust_score, is_blocked)  VALUES (?, ?, ?, ?,?,?)",
                ("admin", "admin@system.com", admin_password_hash, "admin",100,0)
            )
            print("ADMIN CREATED!")
            #Username: admin
            #Password: Admin123!
        else:
            print("Admin user already exists")


# ================= MFA ENDPOINTS =================

# ================= COMPULSORY MFA SETUP (NO TOKEN REQUIRED) =================

@app.route('/mfa/setup-compulsory', methods=['POST'])
def mfa_setup_compulsory():
    """Setup MFA for user who hasn't set it up yet (no token required)"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        
        user = get_user_by_username(username)
        
        if not user or not check_password(password, user['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Check if MFA is already enabled
        mfa_enabled = user['mfa_enabled'] == 1 if 'mfa_enabled' in user.keys() else False
        
        if mfa_enabled:
            return jsonify({"error": "MFA already enabled"}), 400
        
        # Generate new secret
        secret = MFAHelper.generate_secret()
        
        # Generate QR code
        uri = MFAHelper.get_totp_uri(secret, username)
        qr_code = MFAHelper.generate_qr_code(uri)
        
        return jsonify({
            "secret": secret,
            "qr_code": qr_code,
            "uri": uri,
            "user_id": user['id']
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/mfa/verify-compulsory', methods=['POST'])
def mfa_verify_compulsory():
    """Verify and enable MFA for compulsory setup"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        secret = data.get('secret')
        code = data.get('code')
        
        if not username or not password or not secret or not code:
            return jsonify({"error": "All fields required"}), 400
        
        user = get_user_by_username(username)
        
        if not user or not check_password(password, user['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Verify the code
        if MFAHelper.verify_totp(secret, code):
            # Enable MFA for user
            if MFAHelper.enable_mfa(user['id'], secret):
                # Now login the user and return tokens
                from trust_engine import initialize_user, user_data
                initialize_user(str(user['id']))
                user_data[str(user['id'])]['score'] = user['trust_score']
                
                # Create tokens
                access_token = jwt.encode({
                    "user_id": user['id'],
                    "username": user['username'],
                    "role": user['role'],
                    "mfa_verified": True,
                    "type": "access",
                    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ACCESS_TOKEN_EXPIRY_SECONDS)
                }, SECRET_KEY, algorithm="HS256")
                
                refresh_token = jwt.encode({
                    "user_id": user['id'],
                    "type": "refresh",
                    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=REFRESH_TOKEN_EXPIRY_SECONDS)
                }, SECRET_KEY, algorithm="HS256")
                
                return jsonify({
                    "success": True,
                    "message": "MFA enabled successfully",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": ACCESS_TOKEN_EXPIRY_SECONDS,
                    "token_type": "Bearer"
                })
            else:
                return jsonify({"error": "Failed to enable MFA"}), 500
        else:
            return jsonify({"error": "Invalid verification code"}), 400
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# ================= MAIN =================
if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)   