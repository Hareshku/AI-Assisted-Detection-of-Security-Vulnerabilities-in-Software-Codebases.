from scanner.parser import parse_file
from scanner.extractor import extract_features
from scanner.risk_engine import calculate_risk_score, get_risk_emoji

files = [
    "data/samples/bad_code.py",
    "data/samples/good_code.py",
    "data/samples/pipeline.yml"
]

print("\n" + "="*55)
print("       🛡️  AI SECURITY SCANNER — RISK REPORT")
print("="*55)

for filepath in files:
    # Parse → Extract → Score
    parse_result = parse_file(filepath)
    if parse_result["status"] != "success":
        continue

    features = extract_features(parse_result)
    risk = calculate_risk_score(features)

    emoji = get_risk_emoji(risk["risk_level"])

    print(f"\n{emoji}  {risk['filepath']}")
    print(f"   Risk Level : {risk['risk_level']}")
    print(f"   Risk Score : {risk['score']} / 100")
    print(f"   Reasons:")
    if risk["reasons"]:
        for reason in risk["reasons"]:
            print(f"      ⚠️  {reason}")
    else:
        print(f"      ✅ No threats detected")

print("\n" + "="*55)