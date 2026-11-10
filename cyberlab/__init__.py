from flask import Flask, jsonify, render_template, request

from .labs import (
    analyze_url, network_inventory, traffic_summary, web_search,
    password_analyze, password_hash, password_verify, password_benchmark,
    mfa_demo_start, mfa_demo_verify,
)
from .monitor import event_store


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY="local-training-only-change-for-real-deployment",
        MAX_CONTENT_LENGTH=4096,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    def body():
        if not request.is_json:
            return None, (jsonify(error="Send a JSON request body."), 415)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return None, (jsonify(error="A JSON object is required."), 400)
        return data, None

    @app.get("/api/overview")
    def overview():
        return jsonify({
            "version": "1.0.0",
            "modules": ["phishing", "network", "web", "password", "monitoring"],
            "mode": "local synthetic training",
        })

    @app.post("/api/phishing/analyze")
    def phishing_analyze():
        data, error = body()
        if error:
            return error
        url = data.get("url", "")
        if not isinstance(url, str) or len(url) > 2048:
            return jsonify(error="URL must be text under 2048 characters."), 400
        return jsonify(analyze_url(url))

    @app.get("/api/phishing/demo")
    def phishing_demo():
        return jsonify({
            "brand": "Northstar Learning",
            "notice": "FICTIONAL TRAINING PAGE — NOT A REAL LOGIN",
            "headline": "A visual impersonation awareness example",
            "details": [
                "Brand colors and logos can be copied.",
                "A familiar-looking page does not prove who operates it.",
                "Check the hostname and navigate using a saved bookmark.",
            ],
            "credential_collection": False,
        })

    @app.get("/api/network/inventory")
    def network():
        return jsonify(network_inventory())

    @app.get("/api/network/traffic")
    def traffic():
        return jsonify(traffic_summary())

    @app.post("/api/web/search")
    def web_sql_search():
        data, error = body()
        if error:
            return error
        query = data.get("query", "")
        if not isinstance(query, str) or len(query) > 80:
            return jsonify(error="Search text must be 80 characters or fewer."), 400
        return jsonify(web_search(query))

    @app.post("/api/web/session")
    def web_session():
        data, error = body()
        if error:
            return error
        action = data.get("action")
        if action not in ("create", "revoke"):
            return jsonify(error="Action must be create or revoke."), 400
        # A deliberately small in-memory teaching model, not an auth system.
        from flask import session
        if action == "create":
            session["training_session"] = "active"
            return jsonify(status="active", explanation="A demo session flag was created.")
        session.pop("training_session", None)
        return jsonify(status="revoked", explanation="The demo session flag was removed.")

    @app.post("/api/password/analyze")
    def password_analysis():
        data, error = body()
        if error:
            return error
        value = data.get("password", "")
        if not isinstance(value, str) or len(value) > 256:
            return jsonify(error="Enter text up to 256 characters."), 400
        return jsonify(password_analyze(value))

    @app.post("/api/password/hash")
    def password_hash_route():
        data, error = body()
        if error:
            return error
        value = data.get("password", "")
        if not isinstance(value, str) or not value or len(value) > 256:
            return jsonify(error="Enter a non-empty sample password up to 256 characters."), 400
        return jsonify(password_hash(value))

    @app.post("/api/password/verify")
    def password_verify_route():
        data, error = body()
        if error:
            return error
        fields = [data.get(k) for k in ("password", "salt", "digest", "iterations")]
        if not all(isinstance(v, str) for v in fields[:3]) or not isinstance(fields[3], int):
            return jsonify(error="Provide password, salt, digest and integer iterations."), 400
        if len(fields[0]) > 256 or len(fields[1]) > 128 or len(fields[2]) > 256:
            return jsonify(error="Input is too large."), 400
        return jsonify(password_verify(*fields))

    @app.post("/api/password/benchmark")
    def password_benchmark_route():
        data, error = body()
        if error:
            return error
        iterations = data.get("iterations", 150000)
        if not isinstance(iterations, int) or isinstance(iterations, bool):
            return jsonify(error="Iterations must be an integer."), 400
        iterations = max(100000, min(300000, iterations))
        return jsonify(password_benchmark(iterations))

    @app.post("/api/mfa/start")
    def mfa_start():
        data, error = body()
        if error:
            return error
        return jsonify(mfa_demo_start())

    @app.post("/api/mfa/verify")
    def mfa_verify():
        data, error = body()
        if error:
            return error
        code = data.get("code", "")
        if not isinstance(code, str) or len(code) > 12:
            return jsonify(error="Enter the six-digit demo code."), 400
        return jsonify(mfa_demo_verify(code))

    @app.get("/api/monitor/events")
    def monitor_events():
        return jsonify(event_store.snapshot())

    @app.post("/api/monitor/simulate")
    def monitor_simulate():
        data, error = body()
        if error:
            return error
        return jsonify(event_store.add_failed_login())

    return app
