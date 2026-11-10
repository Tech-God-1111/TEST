from cyberlab import create_app
from cyberlab.labs import analyze_url, password_hash, password_verify, web_search


def test_url_analyzer_does_not_open_urls():
    result = analyze_url("http://account-update.example.test/login")
    assert result["hostname"] == "account-update.example.test"
    assert result["risk"] in {"review", "higher"}
    assert any("HTTPS" in item for item in result["signals"])


def test_parameterized_search_returns_training_rows():
    result = web_search("session")
    assert result["query_method"] == "SQLite parameterized query"
    assert result["results"][0]["title"] == "Session security basics"


def test_salted_hash_round_trip():
    record = password_hash("synthetic-example-phrase")
    assert password_verify("synthetic-example-phrase", record["salt"], record["digest"], record["iterations"])["verified"]
    assert not password_verify("wrong-example", record["salt"], record["digest"], record["iterations"])["verified"]


def test_api_headers_and_local_demo():
    app = create_app({"TESTING": True, "SECRET_KEY": "test"})
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert client.get("/api/network/inventory").json["devices"]


def test_api_rejects_non_json():
    app = create_app({"TESTING": True})
    response = app.test_client().post("/api/phishing/analyze", data="hello")
    assert response.status_code == 415


def test_monitor_simulation():
    app = create_app({"TESTING": True})
    client = app.test_client()
    response = client.post("/api/monitor/simulate", json={})
    assert response.status_code == 200
    assert response.json["event"]["type"] == "failed_login"
