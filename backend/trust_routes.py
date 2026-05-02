from flask import Blueprint, request, jsonify
from trust_engine import update_trust_score, check_rate_limit, make_decision

trust_bp = Blueprint('trust', __name__)

@trust_bp.route("/trust-check", methods=["POST"])
def trust_check():
    data = request.json
    user_id = data.get("user_id")
    risk = data.get("risk")

    if not user_id or not risk:
        return jsonify({"error": "Missing data"}), 400

    # Rate limiting
    if not check_rate_limit(user_id):
        return jsonify({
            "decision": "BLOCK",
            "reason": "Too many requests"
        }), 429

    # Update score
    score = update_trust_score(user_id, risk)

    # Decision
    decision = make_decision(user_id)

    return jsonify({
        "trust_score": score,
        "decision": decision
    })