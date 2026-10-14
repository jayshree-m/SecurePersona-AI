import os
import json
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

from database import initialize_database, get_db
from auth import register_user, login_user
from services.sensitive_data_detector import SensitiveDataDetector
from services.persona_service import PersonaService
from services.risk_engine import RiskEngine
from services.dlp_service import DLPService

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

initialize_database()

detector = SensitiveDataDetector()
persona_service = PersonaService()
risk_engine = RiskEngine()
dlp_service = DLPService(detector)


def error_response(message, status=400):
    return jsonify({"success": False, "message": message}), status


def get_user_id(data):
    try:
        user_id = int(data.get("user_id"))
        with get_db() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return user_id if user else None
    except (TypeError, ValueError):
        return None


def run_analysis(data, previous_risk=0, analysis_count=0):
    content = str(data.get("content") or "")
    source = str(data.get("source") or "User Input")
    action = str(data.get("action") or "Send")
    destination = str(data.get("destination") or "External Website")

    if not content.strip():
        raise ValueError("Content cannot be empty.")

    details = detector.detect(content)
    data_types = [item["type"] for item in details]
    sensitivity = detector.calculate_sensitivity(content)

    persona = persona_service.predict(
        sensitive_score=sensitivity,
        detected_data=data_types,
        action=action,
        destination=destination,
        source=source,
        previous_risk=previous_risk,
        analysis_count=analysis_count
    )

    risk = risk_engine.calculate(
        sensitive_score=sensitivity,
        persona_risk=persona["risk_score"],
        action=action,
        destination=destination,
        detected_data=data_types
    )

    dlp = dlp_service.apply_decision(content, risk["decision"])

    return {
        "success": True,
        "persona": persona["persona"],
        "confidence": persona["confidence"],
        "trust_score": persona["trust_score"],
        "persona_risk": persona["risk_score"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "decision": risk["decision"],
        "detected_data": data_types,
        "detected_details": details,
        "reasons": persona["reasons"] + risk["reasons"],
        "data_risk": risk["data_risk"],
        "destination_risk": risk["destination_risk"],
        "action_risk": risk["action_risk"],
        "protected_content": dlp["protected_content"],
        "dlp_action": dlp["action"],
        "allowed": dlp["allowed"],
        "source": source,
        "action_type": action,
        "destination": destination
    }


@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def serve_frontend(path):
    target = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(target):
        return send_from_directory(FRONTEND_DIR, path)
    if os.path.isfile(target + ".html"):
        return send_from_directory(FRONTEND_DIR, path + ".html")
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({
        "status": "online",
        "system": "SecurePersona AI",
        "services": {
            "database": "configured",
            "sensitive_data_detector": "online",
            "persona_engine": "online",
            "risk_engine": "online",
            "dlp_engine": "online"
        }
    })


@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    try:
        result = register_user(
            data.get("name") or data.get("full_name") or "",
            data.get("email") or "",
            data.get("password") or ""
        )
        status = 201 if result.get("success") else 400
        return jsonify(result), status
    except Exception:
        app.logger.exception("Signup failed")
        return error_response("Could not create the account.", 500)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    try:
        result = login_user(
            data.get("email") or "",
            data.get("password") or ""
        )
        status = 200 if result.get("success") else 401
        return jsonify(result), status
    except Exception:
        app.logger.exception("Login failed")
        return error_response("Could not log in.", 500)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    user_id = get_user_id(data)

    if not user_id:
        return error_response("Please log in before analyzing content.", 401)

    content = str(data.get("content") or "")
    if not content.strip():
        return error_response("Please enter content to analyze.")

    if len(content) > 50000:
        return error_response("Content must be 50,000 characters or fewer.")

    try:
        with get_db() as connection:
            previous = connection.execute(
                """SELECT risk_score FROM analyses
                   WHERE user_id = ? ORDER BY id DESC LIMIT 1""",
                (user_id,)
            ).fetchone()
            count_row = connection.execute(
                "SELECT COUNT(*) AS total FROM analyses WHERE user_id = ?",
                (user_id,)
            ).fetchone()

        previous_risk = float(previous["risk_score"]) if previous and previous["risk_score"] is not None else 0.0
        count = int(count_row["total"]) if count_row and count_row["total"] is not None else 0
        result = run_analysis(data, previous_risk, count)

        preview = content[:180]
        with get_db() as connection:
            cursor = connection.execute(
                """INSERT INTO analyses
                (user_id, source, action, destination, persona, confidence,
                 trust_score, risk_score, risk_level, decision, detected_data,
                 reasons, content_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user_id, result["source"], result["action_type"],
                    result["destination"], result["persona"],
                    result["confidence"], result["trust_score"],
                    result["risk_score"], result["risk_level"],
                    result["decision"], json.dumps(result["detected_data"]),
                    json.dumps(result["reasons"]), preview
                )
            )
            analysis_id = cursor.lastrowid

            if result["decision"] == "BLOCK" or result["risk_score"] >= 60:
                connection.execute(
                    """INSERT INTO alerts
                    (user_id, analysis_id, title, message, severity)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        user_id, analysis_id,
                        "High-risk activity detected",
                        f"Risk score {result['risk_score']}/100. "
                        f"Decision: {result['decision']}.",
                        result["risk_level"]
                    )
                )

        result["analysis_id"] = analysis_id
        return jsonify(result)

    except ValueError as error:
        return error_response(str(error))
    except Exception:
        app.logger.exception("Analysis failed")
        return error_response("An internal analysis error occurred.", 500)


@app.route("/api/history", methods=["GET"])
def history():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return error_response("A valid user ID is required.")

    with get_db() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            return error_response("User not found.", 404)

        rows = connection.execute(
            """SELECT id, source, action, destination, persona, risk_score,
                      risk_level, decision, created_at, detected_data, reasons
               FROM analyses WHERE user_id = ?
               ORDER BY id DESC LIMIT 100""",
            (user_id,)
        ).fetchall()

    items = []
    for row in rows:
        item = dict(row)
        item["detected_data"] = json.loads(item["detected_data"] or "[]")
        item["reasons"] = json.loads(item["reasons"] or "[]")
        items.append(item)

    return jsonify({"success": True, "history": items})


@app.route("/api/alerts", methods=["GET"])
def alerts():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return error_response("A valid user ID is required.")

    with get_db() as connection:
        rows = connection.execute(
            """SELECT id, title, message, severity, is_read, created_at
               FROM alerts WHERE user_id = ?
               ORDER BY id DESC LIMIT 100""",
            (user_id,)
        ).fetchall()

    return jsonify({
        "success": True,
        "alerts": [dict(row) for row in rows]
    })


@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def mark_alert_read(alert_id):
    data = request.get_json(silent=True) or {}
    user_id = get_user_id(data)
    if not user_id:
        return error_response("Please log in.", 401)

    with get_db() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET is_read = 1 WHERE id = ? AND user_id = ?",
            (alert_id, user_id)
        )
        if cursor.rowcount == 0:
            return error_response("Alert not found.", 404)

    return jsonify({"success": True, "message": "Alert marked as read."})


@app.route("/api/simulate", methods=["POST"])
def simulate():
    data = request.get_json(silent=True) or {}
    user_id = get_user_id(data)
    if not user_id:
        return error_response("Please log in before using the simulator.", 401)

    if not str(data.get("content") or "").strip():
        return error_response("Enter sample content to simulate.")

    try:
        result = run_analysis(data)
        return jsonify(result)
    except ValueError as error:
        return error_response(str(error))
    except Exception:
        app.logger.exception("Simulation failed")
        return error_response("The simulation could not be completed.", 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)