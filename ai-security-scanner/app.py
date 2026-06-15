import os
import tempfile
from flask import Flask, render_template, request, jsonify
from scanner.parser import parse_file
from scanner.extractor import extract_features
from scanner.risk_engine import calculate_risk_score
from scanner.ml_model import predict_vulnerability

app = Flask(__name__)

ALLOWED_EXTENSIONS = {'.py', '.yml', '.yaml'}

def allowed_file(filename):
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    if 'files' not in request.files:
        return jsonify({"error": "No files uploaded"}), 400

    files = request.files.getlist('files')
    results = []

    for file in files:
        if not file or not allowed_file(file.filename):
            continue

        # Save to temp file
        ext = os.path.splitext(file.filename)[1].lower()
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=ext, mode='wb'
        ) as tmp:
            file.save(tmp)
            tmp_path = tmp.name

        try:
            # Pipeline: Parse → Extract → Score → ML Predict
            parse_result = parse_file(tmp_path)

            if parse_result["status"] != "success":
                results.append({
                    "filename":       file.filename,
                    "error":          parse_result.get("error", "Parse error")
                })
                continue

            features       = extract_features(parse_result)
            risk           = calculate_risk_score(features)
            ml_result      = predict_vulnerability(features)

            results.append({
                "filename":       file.filename,
                "file_type":      features.get("file_type"),
                "risk_score":     risk["score"],
                "risk_level":     risk["risk_level"],
                "reasons":        risk["reasons"],
                "ml_prediction":  ml_result.get("prediction"),
                "ml_probability": ml_result.get("probability", 0),
            })

        finally:
            os.unlink(tmp_path)

    return jsonify({"results": results})


if __name__ == '__main__':
    app.run(debug=True)