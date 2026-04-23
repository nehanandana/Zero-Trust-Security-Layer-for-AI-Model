import re
import datetime
import os

# ---------------- KEYWORDS ----------------

MALICIOUS_KEYWORDS = [
    "ignore previous instructions",
    "reveal system prompt",
    "show hidden instructions",
    "bypass security",
    "disable safety",
    "reveal secrets",
    "show api keys",
    "extract hidden data",
    "dump memory",
    "admin credentials",
    "show me the password",
    "override safety",
    "disable filter",
    "remove restrictions",
    "jailbreak",
    "developer mode"
]

SUSPICIOUS_KEYWORDS = [
    "hack",
    "hacker",
    "bypass",
    "exploit",
    "attack",
    "crack",
    "password cracking",
    "social engineering",
    "override",
    "manipulate ai",
    "break into",
    "restricted data",
    "act as",
    "pretend to be",
    "system prompt",
    "reveal hidden"
]

# ---------------- REGEX ----------------
# These are checked AFTER keyword priority is established

MALICIOUS_REGEX = [
    r"ignore\s+(previous\s+)?instructions",
    r"reveal\s+(the\s+)?(system\s+)?prompt",
    r"(system|hidden)\s+prompt",
    r"bypass\s+.*security",
    r"disable\s+.*safety",
    r"dump\s+.*memory",
    r"show\s+.*(api\s+key|credential|password)",
]

SUSPICIOUS_REGEX = [
    r"act\s+as\s+.+",
    r"pretend\s+to\s+be\s+.+",
    r"how\s+to\s+(hack|exploit|attack|crack)",
    r"(sql|xss|csrf)\s+injection",
    r"brute\s+force",
]

# ---------------- CHECKS ----------------

def malicious_keyword_check(prompt):
    for word in MALICIOUS_KEYWORDS:
        if word in prompt.lower():
            return True
    return False

def suspicious_keyword_check(prompt):
    for word in SUSPICIOUS_KEYWORDS:
        if word in prompt.lower():
            return True
    return False

def malicious_regex_check(prompt):
    for pattern in MALICIOUS_REGEX:
        if re.search(pattern, prompt.lower()):
            return True
    return False

def suspicious_regex_check(prompt):
    for pattern in SUSPICIOUS_REGEX:
        if re.search(pattern, prompt.lower()):
            return True
    return False

# ---------------- CLASSIFICATION ----------------
# FIX: Malicious checks always run BEFORE suspicious checks
# to prevent severity downgrade bugs.

def classify_prompt(prompt):
    prompt_lower = prompt.lower()

    # ── STEP 1: Malicious keyword check (highest priority) ──
    if malicious_keyword_check(prompt):
        return "Malicious"

    # ── STEP 2: Malicious regex check ──
    if malicious_regex_check(prompt):
        return "Malicious"

    # ── STEP 3: Suspicious keyword check ──
    if suspicious_keyword_check(prompt):
        return "Suspicious"

    # ── STEP 4: Suspicious regex check ──
    if suspicious_regex_check(prompt):
        return "Suspicious"

    # ── STEP 5: Intent-based detection ──
    if "how" in prompt_lower and ("hack" in prompt_lower or "attack" in prompt_lower):
        return "Suspicious"

    return "Safe"

# ---------------- LOGGING ----------------
def log_prompt(user_id, prompt, risk):
    # Decide action based on risk level
    action = "BLOCK" if risk == "Malicious" else "WARN" if risk == "Suspicious" else "ALLOW"

    # Get log path from environment (fallback to default)
    log_path = os.environ.get("PROMPT_LOG_PATH", "prompt_logs.txt")

    # Write log entry
    with open(log_path, "a") as f:
        f.write(f"{datetime.datetime.now()} | {user_id} | {risk} | {action} | {prompt}\n")