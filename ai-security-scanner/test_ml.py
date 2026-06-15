from scanner.ml_model import train_model, predict_vulnerability
from scanner.parser import parse_file
from scanner.extractor import extract_features

# ── Step 1: Train the model ──
print("="*55)
print("  STEP 1: TRAINING THE ML MODEL")
print("="*55)
train_model()

# ── Step 2: Predict on our sample files ──
print("\n" + "="*55)
print("  STEP 2: ML PREDICTIONS ON SAMPLE FILES")
print("="*55)

files = [
    "data/samples/bad_code.py",
    "data/samples/good_code.py",
    "data/samples/pipeline.yml"
]

for filepath in files:
    parse_result = parse_file(filepath)
    if parse_result["status"] != "success":
        continue

    features = extract_features(parse_result)
    result = predict_vulnerability(features)

    prob_percent = result["probability"] * 100
    emoji = "🔴" if result["prediction"] == "VULNERABLE" else "🟢"

    print(f"\n{emoji}  {result['filepath']}")
    print(f"   ML Prediction  : {result['prediction']}")
    print(f"   Vulnerability  : {prob_percent:.1f}% probability")
    print(f"   Feature Vector : {result['feature_vector']}")

print("\n" + "="*55)