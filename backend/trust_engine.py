import time

# Store everything in ONE place
user_data = {}

MAX_SCORE = 100
MIN_SCORE = 0
REQUEST_LIMIT = 10  # per minute


def initialize_user(user_id):
    if user_id not in user_data:
        user_data[user_id] = {
            "score": 100,
            "last_request": time.time(),
            "request_count": 0
        }


# ================= TRUST SCORE =================
def update_trust_score(user_id, risk):
    initialize_user(user_id)

    if risk == "safe":
        user_data[user_id]["score"] += 2
    elif risk == "suspicious":
        user_data[user_id]["score"] -= 10
    elif risk == "malicious":
        user_data[user_id]["score"] = 0   # 🔥 immediate drop

    # Clamp score between 0 and 100
    user_data[user_id]["score"] = max(MIN_SCORE, min(MAX_SCORE, user_data[user_id]["score"]))

    return user_data[user_id]["score"]


# ================= RATE LIMIT =================
def check_rate_limit(user_id):
    initialize_user(user_id)

    current_time = time.time()
    last_time = user_data[user_id]["last_request"]

    if current_time - last_time < 60:
        user_data[user_id]["request_count"] += 1
    else:
        user_data[user_id]["request_count"] = 1

    user_data[user_id]["last_request"] = current_time

    if user_data[user_id]["request_count"] > REQUEST_LIMIT:
        user_data[user_id]["score"] -= 10
        return False

    return True


# ================= DECISION ENGINE =================
def make_decision(user_id):
    initialize_user(user_id)

    score = user_data[user_id]["score"]

    if score <= 40:
        return "BLOCK"
    elif score <= 70:
        return "RESTRICT"
    else:
        return "ALLOW"