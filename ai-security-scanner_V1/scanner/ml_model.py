import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ─────────────────────────────────────────
# FEATURE COLUMNS (must match training data)
# ─────────────────────────────────────────

FEATURE_COLUMNS = [
    "dangerous_functions",
    "dangerous_imports",
    "hardcoded_secrets",
    "network_calls",
    "file_operations",
    "dangerous_commands",
    "credential_leaks",
    "external_script_exec"
]

MODEL_PATH = "models/vulnerability_model.pkl"


# ─────────────────────────────────────────
# TRAIN THE MODEL
# ─────────────────────────────────────────

def train_model(csv_path="data/training/train_data.csv"):
    """
    Trains a Random Forest model on the training CSV.
    Saves the model to disk.
    """
    print("📊 Loading training data...")
    df = pd.read_csv(csv_path)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    print(f"   Total samples  : {len(df)}")
    print(f"   Vulnerable (1) : {sum(y == 1)}")
    print(f"   Safe (0)       : {sum(y == 0)}")

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("\n🤖 Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        max_depth=5
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\n✅ Training Complete!")
    print(f"   Accuracy : {accuracy * 100:.1f}%")
    print(f"\n📋 Classification Report:")
    print(classification_report(y_test, y_pred,
          target_names=["Safe", "Vulnerable"]))

    # Save model
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"💾 Model saved to: {MODEL_PATH}")

    return model


# ─────────────────────────────────────────
# LOAD SAVED MODEL
# ─────────────────────────────────────────

def load_model():
    """Loads the trained model from disk."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "Model not found! Run train_model() first."
        )
    return joblib.load(MODEL_PATH)


# ─────────────────────────────────────────
# PREDICT VULNERABILITY
# ─────────────────────────────────────────

def predict_vulnerability(features):
    """
    Takes extracted features dict and returns
    ML-based vulnerability probability (0.0 to 1.0).
    """
    model = load_model()

    # Build feature vector from extracted features
    if features.get("file_type") == "python":
        feature_vector = {
            "dangerous_functions": len(features.get("dangerous_functions", [])),
            "dangerous_imports":   len(features.get("dangerous_imports", [])),
            "hardcoded_secrets":   len(features.get("hardcoded_secrets", [])),
            "network_calls":       len(features.get("network_calls", [])),
            "file_operations":     len(features.get("file_operations", [])),
            "dangerous_commands":  0,
            "credential_leaks":    0,
            "external_script_exec": 0,
        }

    elif features.get("file_type") == "pipeline":
        unique_cmds = set(
            item["command"]
            for item in features.get("dangerous_commands", [])
        )
        feature_vector = {
            "dangerous_functions": 0,
            "dangerous_imports":   0,
            "hardcoded_secrets":   0,
            "network_calls":       0,
            "file_operations":     0,
            "dangerous_commands":  len(unique_cmds),
            "credential_leaks":    len(features.get("credential_leaks", [])),
            "external_script_exec": len(features.get("external_script_execution", [])),
        }
    else:
        return {"error": "Unsupported file type"}

    # Convert to DataFrame for prediction
    df = pd.DataFrame([feature_vector])[FEATURE_COLUMNS]

    # Get prediction and probability
    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0][1]  # probability of being vulnerable

    return {
        "filepath":       features.get("filepath"),
        "prediction":     "VULNERABLE" if prediction == 1 else "SAFE",
        "probability":    round(float(probability), 3),
        "feature_vector": feature_vector
    }