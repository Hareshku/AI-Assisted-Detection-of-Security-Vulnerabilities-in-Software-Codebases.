# ─────────────────────────────────────────
# RISK SCORING ENGINE
# Converts extracted features into a risk score
# ─────────────────────────────────────────

# Point weights for each type of finding
RISK_WEIGHTS = {
    # Python code risks
    "dangerous_function":   15,   # e.g. eval, exec, os.system
    "dangerous_import":     10,   # e.g. subprocess, pickle
    "hardcoded_secret":     20,   # e.g. password = "abc123"
    "network_call":          8,   # e.g. requests.get()
    "file_operation":        5,   # e.g. open(), os.remove()

    # Pipeline risks
    "dangerous_command":    15,   # e.g. curl, wget, bash
    "credential_leak":      25,   # e.g. echo $SECRET_KEY
    "external_script_exec": 30,   # e.g. curl url | bash
}

# Risk thresholds
RISK_LEVELS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 65),
    "HIGH":     (66, 999),
}


def calculate_risk_score(features):
    """
    Takes extracted features and returns a risk score + level.
    """
    score = 0
    reasons = []

    if features.get("file_type") == "python":

        # Score dangerous functions
        count = len(features.get("dangerous_functions", []))
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_function"]
            score += points
            reasons.append(f"Dangerous functions ({count} found): +{points} pts")

        # Score dangerous imports
        count = len(features.get("dangerous_imports", []))
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_import"]
            score += points
            reasons.append(f"Dangerous imports ({count} found): +{points} pts")

        # Score hardcoded secrets
        count = len(features.get("hardcoded_secrets", []))
        if count > 0:
            points = count * RISK_WEIGHTS["hardcoded_secret"]
            score += points
            reasons.append(f"Hardcoded secrets ({count} found): +{points} pts")

        # Score network calls
        count = len(features.get("network_calls", []))
        if count > 0:
            points = count * RISK_WEIGHTS["network_call"]
            score += points
            reasons.append(f"Network calls ({count} found): +{points} pts")

        # Score file operations
        count = len(features.get("file_operations", []))
        if count > 0:
            points = count * RISK_WEIGHTS["file_operation"]
            score += points
            reasons.append(f"File operations ({count} found): +{points} pts")

    elif features.get("file_type") == "pipeline":

        # Score dangerous commands (unique only to avoid curl+bash+sh triple count)
        unique_commands = set()
        for item in features.get("dangerous_commands", []):
            unique_commands.add(item["command"])
        count = len(unique_commands)
        if count > 0:
            points = count * RISK_WEIGHTS["dangerous_command"]
            score += points
            reasons.append(f"Dangerous commands ({count} unique): +{points} pts")

        # Score credential leaks
        count = len(features.get("credential_leaks", []))
        if count > 0:
            points = count * RISK_WEIGHTS["credential_leak"]
            score += points
            reasons.append(f"Credential leaks ({count} found): +{points} pts")

        # Score external script execution
        count = len(features.get("external_script_execution", []))
        if count > 0:
            points = count * RISK_WEIGHTS["external_script_exec"]
            score += points
            reasons.append(f"External script execution ({count} found): +{points} pts")

    # Cap score at 100
    score = min(score, 100)

    # Determine risk level
    risk_level = "LOW"
    for level, (low, high) in RISK_LEVELS.items():
        if low <= score <= high:
            risk_level = level
            break

    return {
        "filepath":   features.get("filepath"),
        "file_type":  features.get("file_type"),
        "score":      score,
        "risk_level": risk_level,
        "reasons":    reasons
    }


def get_risk_emoji(risk_level):
    return {
        "LOW":    "🟢",
        "MEDIUM": "🟡",
        "HIGH":   "🔴"
    }.get(risk_level, "⚪")