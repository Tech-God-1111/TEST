import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import sqlite3
import string
import time
from pathlib import Path
from urllib.parse import urlsplit

DATA = Path(__file__).resolve().parent.parent / "data"
PBKDF2_ITERATIONS = 240_000


def analyze_url(value):
    raw = value.strip()
    result = {"input": raw[:200], "signals": [], "risk": "unknown", "safe_to_open": False}
    if not raw or len(raw) > 2048:
        result["signals"].append("Enter a URL of a reasonable length.")
        return result
    candidate = raw if "://" in raw else "https://" + raw
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme not in ("http", "https") or not host:
            raise ValueError("invalid URL")
        try:
            ipaddress.ip_address(host)
            result["signals"].append("The address uses a raw IP address instead of a recognizable domain.")
        except ValueError:
            pass
        if parts.scheme != "https":
            result["signals"].append("The URL does not use HTTPS.")
        if "@" in parts.netloc:
            result["signals"].append("An @ symbol in the authority can disguise the actual destination.")
        if host.startswith("xn--") or ".xn--" in host:
            result["signals"].append("The hostname contains an internationalized/punycode label; inspect it carefully.")
        if host.count("-") >= 2:
            result["signals"].append("The hostname contains several hyphens.")
        if len(host) > 45:
            result["signals"].append("The hostname is unusually long.")
        if parts.port and parts.port not in (80, 443):
            result["signals"].append("The URL specifies a non-standard port.")
        if parts.username or parts.password:
            result["signals"].append("The URL embeds user information before the @ symbol.")
        if not result["signals"]:
            result["signals"].append("No simple warning patterns were found; this does not prove the site is trustworthy.")
        score = len(result["signals"])
        result["risk"] = "higher" if score >= 3 else "review" if score else "unknown"
        result["hostname"] = host
        result["scheme"] = parts.scheme
        result["signals"].append("This analyzer is heuristic only. It does not visit the URL or verify ownership.")
        return result
    except (ValueError, UnicodeError):
        result["risk"] = "higher"
        result["signals"].append("The value could not be parsed as a normal HTTP or HTTPS URL.")
        return result


def network_inventory():
    # Static fictional lab inventory. No sockets are opened and no scanning occurs.
    return {
        "scope": "Fictional isolated training network — sample data only",
        "devices": [
            {"name": "LAB-GATEWAY", "address": "192.0.2.1", "role": "Router", "services": ["HTTPS admin (simulated)"]},
            {"name": "TRAINING-WEB", "address": "192.0.2.10", "role": "Web server", "services": ["HTTP 8080 (sample)", "SSH 2222 (sample)"]},
            {"name": "ANALYST-PC", "address": "192.0.2.25", "role": "Workstation", "services": ["DNS client (sample)"]},
        ],
        "note": "192.0.2.0/24 is reserved for documentation. These are not discovered devices.",
    }


def traffic_summary():
    path = DATA / "sample_traffic.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    counts = {}
    for row in rows:
        counts[row["protocol"]] = counts.get(row["protocol"], 0) + 1
    return {"scope": "Bundled synthetic traffic records; no live capture", "records": rows, "protocol_counts": counts}


def web_search(term):
    # Small in-memory database and parameterized query. No user-controlled SQL is executed.
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE resources (id INTEGER PRIMARY KEY, title TEXT, category TEXT)")
    connection.executemany(
        "INSERT INTO resources(title, category) VALUES (?, ?)",
        [
            ("Input validation guide", "Defensive coding"),
            ("Session security basics", "Web security"),
            ("Parameterized query tutorial", "Database safety"),
            ("Browser privacy checklist", "Phishing awareness"),
        ],
    )
    rows = connection.execute(
        "SELECT title, category FROM resources WHERE title LIKE ? ORDER BY title",
        (f"%{term}%",),
    ).fetchall()
    connection.close()
    return {
        "results": [{"title": title, "category": category} for title, category in rows],
        "query_method": "SQLite parameterized query",
        "lesson": "User input is treated as data, not executable SQL. This demo never runs injected SQL.",
    }


def _password_metrics(value):
    groups = 0
    groups += bool(any(c.islower() for c in value))
    groups += bool(any(c.isupper() for c in value))
    groups += bool(any(c.isdigit() for c in value))
    groups += bool(any(not c.isalnum() for c in value))
    pool = sum((26 if any(c.islower() for c in value) else 0,
                26 if any(c.isupper() for c in value) else 0,
                10 if any(c.isdigit() for c in value) else 0,
                32 if any(not c.isalnum() for c in value) else 0))
    entropy = len(value) * math.log2(max(pool, 1)) if value else 0
    common = value.lower() in {"password", "123456", "qwerty", "letmein", "admin"}
    score = 0 if not value else min(4, (len(value) >= 12) + (len(value) >= 16) + (groups >= 3) + (entropy >= 70))
    if common:
        score = 0
    return {"length": len(value), "estimated_entropy_bits": round(entropy, 1),
            "strength_label": ["Very weak", "Weak", "Fair", "Good", "Stronger sample"][score],
            "score": score, "common_sample": common,
            "advice": "Use a long, unique passphrase and a password manager. Estimates are educational, not a guarantee."}


def password_analyze(value):
    return _password_metrics(value)


def password_hash(value):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return {"algorithm": "PBKDF2-HMAC-SHA256", "iterations": PBKDF2_ITERATIONS,
            "salt": salt.hex(), "digest": digest.hex(),
            "lesson": "A fresh random salt makes equal passwords produce different stored verifiers. This sample is not saved."}


def password_verify(value, salt_hex, digest_hex, iterations):
    if iterations < 1 or iterations > 2_000_000:
        return {"verified": False, "error": "Iteration value is outside the demo safety limit."}
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return {"verified": False, "error": "Salt or digest is not valid hexadecimal."}
    actual = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, iterations)
    return {"verified": hmac.compare_digest(actual, expected)}


def password_benchmark(iterations):
    start = time.perf_counter()
    hashlib.pbkdf2_hmac("sha256", b"synthetic-benchmark-only", b"training-salt", iterations)
    elapsed = time.perf_counter() - start
    return {"algorithm": "PBKDF2-HMAC-SHA256", "iterations": iterations,
            "elapsed_ms": round(elapsed * 1000, 2),
            "note": "One local benchmark using a fixed synthetic input; not a password-strength verdict."}


_MFA_CODES = {}


def mfa_demo_start():
    token = secrets.token_hex(8)
    code = f"{secrets.randbelow(1_000_000):06d}"
    _MFA_CODES[token] = code
    # The code is deliberately shown because this is a closed training simulation.
    return {"token": token, "demo_code": code,
            "notice": "SIMULATION ONLY: this code is displayed for learning and is not sent by SMS/email."}


def mfa_demo_verify(code):
    # Single active demo code to keep the exercise simple and bounded.
    if not _MFA_CODES:
        return {"verified": False, "message": "Start a new MFA demonstration first."}
    token = next(reversed(_MFA_CODES))
    expected = _MFA_CODES.pop(token)
    ok = hmac.compare_digest(code, expected)
    return {"verified": ok, "message": "Demo second factor accepted." if ok else "Code did not match or has expired."}
