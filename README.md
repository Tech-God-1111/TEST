# Cybersecurity Learning Lab

A local-only Python + Flask education project covering five defensive cybersecurity topics. It uses fictional targets, synthetic event data and bounded demonstrations.

## Modules

1. **Phishing awareness** — heuristic URL inspection and a fictional visual-impersonation example. It never opens submitted URLs and has no credential form.
2. **Network security** — documentation-only device inventory, sample traffic analysis and visual firewall-rule concepts. It performs no network scanning and changes no firewall settings.
3. **Web application security** — an in-memory SQLite resource search using parameterized queries, plus a simple demo session lifecycle.
4. **Password security** — educational strength estimation, salted PBKDF2-HMAC-SHA256 hashing and verification, a bounded KDF benchmark, and a simulated MFA code.
5. **Security monitoring** — synthetic event timeline and a simple failed-login detection rule.

## Requirements

- Python 3.10 or newer
- Windows, macOS or Linux

## Setup (Windows PowerShell)

```powershell
cd D:\PyCharmMiscProject
git clone https://github.com/Tech-God-1111/TEST.git
cd TEST
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

Open **http://127.0.0.1:5055** in your browser. Stop the server with Ctrl+C.

## Setup (Git Bash / macOS / Linux)

```bash
git clone https://github.com/Tech-God-1111/TEST.git
cd TEST
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

## Tests

```bash
python -m pip install -r requirements-dev.txt
pytest
ruff check .
```

## Safety and scope

- The server binds to **127.0.0.1** only. Do not change it to a public interface.
- The URL analyzer parses text only; it does not visit URLs or determine whether a site is genuinely safe.
- The phishing example is fictional and intentionally has no credential fields.
- Network inventory and traffic are bundled sample data. No port scanner, packet capture, or firewall modification is included.
- SQL search uses parameterized queries against a temporary in-memory database. No user-supplied SQL is executed.
- Password examples are processed in memory and are not stored in files or logs. Use made-up samples only, never your real passwords.
- The MFA code is displayed in the interface solely to explain the second-factor concept; it is not delivered through a real messaging channel.
- Monitoring events are synthetic and do not represent real users or machines.

This project is for defensive education in an isolated local environment. Only assess systems you own or are explicitly authorized to test.
