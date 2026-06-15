from scanner.parser import parse_file
from scanner.extractor import extract_features

files = [
    "data/samples/bad_code.py",
    "data/samples/good_code.py",
    "data/samples/pipeline.yml"
]

for filepath in files:
    # Step 1: Parse
    parse_result = parse_file(filepath)

    if parse_result["status"] != "success":
        print(f"Parse error: {parse_result['error']}")
        continue

    # Step 2: Extract features
    features = extract_features(parse_result)

    print(f"\n{'='*55}")
    print(f"📄 File: {features['filepath']}")
    print(f"🔍 Type: {features['file_type']}")

    if features["file_type"] == "python":
        print(f"   Total Lines         : {features['total_lines']}")
        print(f"   Total Functions     : {features['total_functions']}")
        print(f"   Dangerous Functions : {features['dangerous_functions']}")
        print(f"   Dangerous Imports   : {features['dangerous_imports']}")
        print(f"   Hardcoded Secrets   : {len(features['hardcoded_secrets'])} found")
        print(f"   Network Calls       : {features['network_calls']}")
        print(f"   File Operations     : {features['file_operations']}")

    elif features["file_type"] == "pipeline":
        print(f"   Total Stages        : {features['total_stages']}")
        print(f"   Total Commands      : {features['total_commands']}")
        print(f"   Dangerous Commands  : {len(features['dangerous_commands'])} found")
        print(f"   Credential Leaks    : {len(features['credential_leaks'])} found")
        print(f"   Ext. Script Exec    : {len(features['external_script_execution'])} found")

        if features["dangerous_commands"]:
            print(f"\n   ⚠️  Dangerous Commands Detail:")
            for item in features["dangerous_commands"]:
                print(f"      Stage: {item['stage']} | Trigger: {item['trigger']}")
                print(f"      Command: {item['command'][:60]}...")