import ast
import yaml
import os

# ─────────────────────────────────────────
# PYTHON SOURCE CODE PARSER
# ─────────────────────────────────────────

def parse_python_file(filepath):
    """
    Reads a Python file and returns its AST tree + raw source.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source)

        return {
            "status": "success",
            "filepath": filepath,
            "source": source,
            "ast_tree": tree
        }

    except SyntaxError as e:
        return {"status": "error", "filepath": filepath, "error": f"Syntax error: {e}"}
    except Exception as e:
        return {"status": "error", "filepath": filepath, "error": str(e)}


# ─────────────────────────────────────────
# YAML / CI-CD PIPELINE PARSER
# ─────────────────────────────────────────

def parse_pipeline_file(filepath):
    """
    Reads a GitHub Actions YAML or Jenkinsfile-style YAML
    and extracts stages, steps, and commands.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            raw = f.read()

        data = yaml.safe_load(raw)

        stages = []

        # GitHub Actions format: jobs -> steps -> run
        if isinstance(data, dict) and "jobs" in data:
            for job_name, job_data in data["jobs"].items():
                steps = job_data.get("steps", [])
                commands = []
                for step in steps:
                    if "run" in step:
                        commands.append(step["run"])
                    if "uses" in step:
                        commands.append(f"[ACTION] {step['uses']}")

                stages.append({
                    "stage": job_name,
                    "commands": commands
                })

        # Simple list-based pipeline format
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    stages.append(item)

        return {
            "status": "success",
            "filepath": filepath,
            "raw": raw,
            "stages": stages
        }

    except Exception as e:
        return {"status": "error", "filepath": filepath, "error": str(e)}


# ─────────────────────────────────────────
# AUTO DETECT AND PARSE ANY FILE
# ─────────────────────────────────────────

def parse_file(filepath):
    """
    Automatically detects file type and calls the right parser.
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".py":
        result = parse_python_file(filepath)
        result["file_type"] = "python"
        return result

    elif ext in [".yml", ".yaml"]:
        result = parse_pipeline_file(filepath)
        result["file_type"] = "pipeline"
        return result

    else:
        return {
            "status": "error",
            "filepath": filepath,
            "error": f"Unsupported file type: {ext}"
        }