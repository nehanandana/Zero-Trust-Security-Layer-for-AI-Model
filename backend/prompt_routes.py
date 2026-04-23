from flask import Blueprint, request, jsonify
from prompt_filter import classify_prompt, log_prompt

prompt_bp = Blueprint('prompt', __name__)

from app import token_required

@prompt_bp.route('/analyze_prompt', methods=['POST'])
@token_required
def analyze_prompt():
    data = request.get_json()

    if not data or "prompt" not in data:
        return jsonify({"error": "Prompt required"}), 400

    prompt = data["prompt"]

    # Get user from Member 1 system
    user_id = request.user.get("user_id")

    # Run your logic
    risk = classify_prompt(prompt)

    # Log
    log_prompt(user_id, prompt, risk)

    # Decision
    if risk == "Malicious":
        return jsonify({
            "risk": risk,
            "action": "BLOCK",
            "message": "Malicious prompt detected"
        }), 403

    elif risk == "Suspicious":
        return jsonify({
            "risk": risk,
            "action": "WARN",
            "message": "Suspicious prompt detected",
            "note": "Request allowed but flagged"
        })

    else:
        return jsonify({
            "risk": risk,
            "action": "ALLOW"
        })