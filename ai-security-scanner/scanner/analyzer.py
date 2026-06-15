import re
import ast

# ─────────────────────────────────────────
# SECURITY RULES DEFINITION
# Each rule has: id, description, severity
# ─────────────────────────────────────────

PYTHON_RULES = [
    {
        "id":          "PY001",
        "name":        "Use of eval()",
        "description": "eval() executes arbitrary code — extremely dangerous",
        "severity":    "HIGH",
        "check":       lambda src: "eval(" in src
    },
    {
        "id":          "PY002",
        "name":        "Use of exec()",
        "description": "exec() executes arbitrary Python code at runtime",
        "severity":    "HIGH",
        "check":       lambda src: "exec(" in src
    },
    {
        "id":          "PY003",
        "name":        "Use of os.system()",
        "description": "os.system() runs shell commands — risk of injection",
        "severity":    "HIGH",
        "check":       lambda src: "os.system(" in src
    },
    {
        "id":          "PY004",
        "name":        "Hardcoded Password",
        "description": "Hardcoded credentials found in source code",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'password\s*=\s*["\'].*["\']', src, re.IGNORECASE))
    },
    {
        "id":          "PY005",
        "name":        "Hardcoded API Key",
        "description": "Hardcoded API key found — should use environment variables",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'api_key\s*=\s*["\'].*["\']', src, re.IGNORECASE))
    },
    {
        "id":          "PY006",
        "name":        "Subprocess Usage",
        "description": "subprocess module used — verify inputs are sanitized",
        "severity":    "MEDIUM",
        "check":       lambda src: "import subprocess" in src or
                                   "from subprocess" in src
    },
    {
        "id":          "PY007",
        "name":        "Pickle Usage",
        "description": "pickle can execute arbitrary code when deserializing",
        "severity":    "MEDIUM",
        "check":       lambda src: "import pickle" in src or
                                   "pickle.load" in src
    },
    {
        "id":          "PY008",
        "name":        "Hardcoded Secret/Token",
        "description": "Hardcoded secret or token found in source code",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'(secret|token)\s*=\s*["\'].*["\']',
                           src, re.IGNORECASE))
    },
    {
        "id":          "PY009",
        "name":        "Shell Injection Risk",
        "description": "String concatenation in shell command — injection risk",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'os\.system\s*\(.*\+.*\)', src))
    },
    {
        "id":          "PY010",
        "name":        "Use of __import__()",
        "description": "__import__() can be used to load malicious modules",
        "severity":    "MEDIUM",
        "check":       lambda src: "__import__(" in src
    },
    {
        "id":          "PY011",
        "name":        "Unsafe Deserialization",
        "description": "shelve or marshal module used — deserialization risk",
        "severity":    "MEDIUM",
        "check":       lambda src: "import shelve" in src or
                                   "import marshal" in src
    },
    {
        "id":          "PY012",
        "name":        "Debug Mode Enabled",
        "description": "debug=True found — never enable in production",
        "severity":    "LOW",
        "check":       lambda src: bool(re.search(
                           r'debug\s*=\s*True', src, re.IGNORECASE))
    },
]


PIPELINE_RULES = [
    {
        "id":          "PL001",
        "name":        "Curl Pipe to Shell",
        "description": "Downloading and executing remote script — supply chain risk",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'curl.*\|\s*(bash|sh)', src))
    },
    {
        "id":          "PL002",
        "name":        "Credential Echo Leak",
        "description": "Sensitive variable echoed to output — credential leak risk",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'echo\s+\$.*?(KEY|SECRET|PASSWORD|TOKEN)',
                           src, re.IGNORECASE))
    },
    {
        "id":          "PL003",
        "name":        "Curl Data Exfiltration",
        "description": "Secret sent via curl to external server",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'curl.*--data.*\$', src))
    },
    {
        "id":          "PL004",
        "name":        "Wget Remote Script",
        "description": "Downloading remote script with wget — execution risk",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'wget.*http', src))
    },
    {
        "id":          "PL005",
        "name":        "Unpinned Dependency",
        "description": "pip install without version pinning — supply chain risk",
        "severity":    "MEDIUM",
        "check":       lambda src: bool(re.search(
                           r'pip install(?!\s+-r)\s+\w+\s*$', src, re.MULTILINE))
    },
    {
        "id":          "PL006",
        "name":        "Chmod Executable",
        "description": "chmod +x makes file executable — verify the source",
        "severity":    "MEDIUM",
        "check":       lambda src: "chmod +x" in src
    },
    {
        "id":          "PL007",
        "name":        "Base64 Encoded Command",
        "description": "base64 decoding used — possible obfuscated payload",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(
                           r'base64\s*--decode|base64\s*-d', src))
    },
    {
        "id":          "PL008",
        "name":        "Netcat Usage",
        "description": "netcat (nc) used — possible reverse shell risk",
        "severity":    "HIGH",
        "check":       lambda src: bool(re.search(r'\bnc\b|\bnetcat\b', src))
    },
    {
        "id":          "PL009",
        "name":        "Unpinned GitHub Action",
        "description": "GitHub Action used without commit SHA pinning",
        "severity":    "LOW",
        "check":       lambda src: bool(re.search(
                           r'uses:\s+\S+@v\d', src))
    },
    {
        "id":          "PL010",
        "name":        "Environment Variable Exposure",
        "description": "Sensitive env variable printed or logged",
        "severity":    "MEDIUM",
        "check":       lambda src: bool(re.search(
                           r'print.*\$?(SECRET|API_KEY|TOKEN|PASSWORD)',
                           src, re.IGNORECASE))
    },
]


# ─────────────────────────────────────────
# SEVERITY COLORS / WEIGHTS
# ─────────────────────────────────────────

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# ─────────────────────────────────────────
# MAIN ANALYZER FUNCTIONS
# ─────────────────────────────────────────

def analyze_python(parse_result):
    """
    Runs all Python security rules against the source code.
    Returns list of triggered rule violations.
    """
    source     = parse_result.get("source", "")
    violations = []

    for rule in PYTHON_RULES:
        try:
            if rule["check"](source):
                violations.append({
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "description": rule["description"],
                    "severity":    rule["severity"],
                })
        except Exception:
            continue

    # Sort by severity: HIGH first
    violations.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return violations


def analyze_pipeline(parse_result):
    """
    Runs all pipeline security rules against raw YAML content.
    Returns list of triggered rule violations.
    """
    raw        = parse_result.get("raw", "")
    violations = []

    for rule in PIPELINE_RULES:
        try:
            if rule["check"](raw):
                violations.append({
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "description": rule["description"],
                    "severity":    rule["severity"],
                })
        except Exception:
            continue

    # Sort by severity: HIGH first
    violations.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return violations


def analyze_file(parse_result):
    """
    Auto-detects file type and runs the right analyzer.
    Returns a full analysis report dict.
    """
    file_type  = parse_result.get("file_type", "")
    filepath   = parse_result.get("filepath", "")

    if file_type == "python":
        violations = analyze_python(parse_result)
    elif file_type == "pipeline":
        violations = analyze_pipeline(parse_result)
    else:
        return {"error": "Unsupported file type"}

    # Count by severity
    high   = sum(1 for v in violations if v["severity"] == "HIGH")
    medium = sum(1 for v in violations if v["severity"] == "MEDIUM")
    low    = sum(1 for v in violations if v["severity"] == "LOW")

    return {
        "filepath":        filepath,
        "file_type":       file_type,
        "total_violations": len(violations),
        "high":            high,
        "medium":          medium,
        "low":             low,
        "violations":      violations,
    }