# backend/app.py
from flask import Flask, jsonify, request
from flask_cors import CORS
from scanner import scan_target
from ai_analyzer import analyze_with_ai

app = Flask(__name__)
CORS(app)


@app.route("/api/scan", methods=["POST"])
def scan():
    try:
        body = request.get_json(force=True) or {}
    except Exception as e:
        print("JSON parse error:", e)
        return jsonify({"error": f"Invalid JSON: {e}"}), 400

    url = body.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    try:
        data, err = scan_target(url)
    except Exception as e:
        print("Scanner internal error:", e)
        return jsonify({"error": f"Internal scanner error: {e}"}), 500

    if err:
        print("Scanner error:", err)
        return jsonify({"error": f"Scan error: {err}"}), 502

    try:
        ai_response = analyze_with_ai(url, data)
    except Exception as e:
        print("AI analysis crashed unexpectedly:", e)
        ai_response = {
            "summary": f"AI analysis crashed: {e}",
            "vulnerabilities": [],
            "security_headers_suggestions": []
        }

    return jsonify({
        "scan": data,
        "ai": ai_response
    }), 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
