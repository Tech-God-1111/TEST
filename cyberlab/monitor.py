from collections import deque
from datetime import datetime, timezone
from threading import RLock


class EventStore:
    def __init__(self):
        self._events = deque(maxlen=100)
        self._lock = RLock()
        self._counter = 0
        self._seed()

    def _append(self, event_type, source, detail, severity):
        self._counter += 1
        event = {
            "id": self._counter,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "type": event_type,
            "source": source,
            "detail": detail,
            "severity": severity,
        }
        self._events.appendleft(event)
        return event

    def _seed(self):
        with self._lock:
            self._append("login_success", "192.0.2.25", "Synthetic training account signed in.", "info")
            self._append("policy_change", "LAB-GATEWAY", "A sample firewall policy was updated.", "warning")
            self._append("failed_login", "192.0.2.44", "Synthetic failed sign-in event.", "warning")

    def add_failed_login(self):
        with self._lock:
            recent = [e for e in self._events if e["type"] == "failed_login" and e["source"] == "192.0.2.44"]
            event = self._append("failed_login", "192.0.2.44", "Simulated failed sign-in; no account was contacted.", "warning")
            count = len(recent) + 1
            alert = count >= 5
            if alert:
                self._append("alert", "DETECTION RULE", f"{count} synthetic failed logins observed for the sample source.", "high")
            return {"event": event, "failed_logins_in_window": count, "alert_triggered": alert}

    def snapshot(self):
        with self._lock:
            return {"scope": "Synthetic events only", "events": list(self._events),
                    "total": len(self._events)}


event_store = EventStore()
