"""Exportador Prometheus mínimo con métricas etiquetadas por nodo."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .signer import EventSigner
from .verify import load_public_key, read_events, verify_evidence

DATA_DIR = Path(os.environ.get("JADE_DATA", "data"))
DEFAULT_NODE = os.environ.get("JADE_NODE", "demo-node")


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _timestamp(value) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _signer_ready(state_dir: Path, trusted_key) -> bool:
    key_path = state_dir / "ed25519.key"
    state_path = state_dir / "signer-state.json"
    if trusted_key is None or not key_path.is_file() or not state_path.is_file():
        return False
    try:
        signer = EventSigner(state_dir)
        signer._load_state()
        public_key = signer.public_key()
        encoding = serialization.Encoding.Raw
        public_format = serialization.PublicFormat.Raw
        if public_key.public_bytes(encoding, public_format) != trusted_key.public_bytes(
            encoding, public_format
        ):
            return False
        challenge = b"jade-blockchain-signer-health-check"
        trusted_key.verify(signer.private_key.sign(challenge), challenge)
        return True
    except (OSError, ValueError, TypeError, RuntimeError, InvalidSignature):
        return False


def render_metrics() -> str:
    events_path = DATA_DIR / "events.jsonl"
    key_path = DATA_DIR / "trusted-public-key.b64"
    anchors_path = DATA_DIR / "anchors.json"
    try:
        events = read_events(events_path) if events_path.exists() else []
        anchors = json.loads(anchors_path.read_text(encoding="utf-8")) if anchors_path.exists() else []
        if not isinstance(anchors, list):
            raise ValueError("anchors must be an array")
        key = load_public_key(key_path) if key_path.exists() else None
        result = verify_evidence(events, key, anchors if anchors_path.exists() else None)
        state_path = DATA_DIR / "signer" / "signer-state.json"
        signer_ready = int(_signer_ready(state_path.parent, key))
        nodes = sorted(
            {event.get("nodo", DEFAULT_NODE) for event in events}
            | {anchor.get("nodo", DEFAULT_NODE) for anchor in anchors}
            | {DEFAULT_NODE}
        )
        lines = [
            "# HELP jade_exporter_up Exporter is serving metrics.",
            "# TYPE jade_exporter_up gauge",
            "jade_exporter_up 1",
            "# HELP jade_capture_healthy Real host event capture health; synthetic demo has no host capture.",
            "# TYPE jade_capture_healthy gauge",
            "# HELP jade_signer_ready Signer can create a valid signature with its trusted key.",
            "# TYPE jade_signer_ready gauge",
            "# HELP jade_events_total Number of events in the local chain.",
            "# TYPE jade_events_total gauge",
            "# HELP jade_events_unsigned Number of events missing a signature or signature counter.",
            "# TYPE jade_events_unsigned gauge",
            "# HELP jade_pending_events Events after the latest verified local anchor.",
            "# TYPE jade_pending_events gauge",
            "# HELP jade_anchor_delay_seconds Age of the newest local anchor, or unanchored event.",
            "# TYPE jade_anchor_delay_seconds gauge",
            "# HELP jade_anchor_rejected Total recorded anchor failures.",
            "# TYPE jade_anchor_rejected counter",
            "# HELP jade_integrity_ok Whether the local chain and signatures verify.",
            "# TYPE jade_integrity_ok gauge",
        ]
        anchor_errors_path = DATA_DIR / "anchor-errors.json"
        anchor_errors = {}
        try:
            error_state = json.loads(anchor_errors_path.read_text(encoding="utf-8"))
            counts = error_state.get("counts")
            if isinstance(counts, dict):
                anchor_errors.update(
                    {
                        node: count
                        for node, count in counts.items()
                        if isinstance(node, str) and isinstance(count, int) and count >= 0
                    }
                )
            elif isinstance(error_state.get("count"), int):
                anchor_errors[error_state.get("node", DEFAULT_NODE)] = error_state["count"]
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        now = time.time()
        for node in nodes:
            label = _label(node)
            node_events = [event for event in events if event.get("nodo") == node]
            node_anchors = [anchor for anchor in anchors if anchor.get("nodo") == node]
            anchored_counter = max((anchor.get("firma_n", 0) for anchor in node_anchors), default=0)
            unsigned = sum(
                "firma" not in event or "firma_n" not in event for event in node_events
            )
            timestamps = [_timestamp(event.get("fecha")) for event in node_events]
            event_times = [stamp for stamp in timestamps if stamp is not None]
            anchor_times = [
                anchor.get("anchored_at")
                for anchor in node_anchors
                if isinstance(anchor.get("anchored_at"), (int, float))
            ]
            newest_time = max(anchor_times, default=max(event_times, default=now))
            pending = max(0, len(node_events) - anchored_counter)
            integrity = int(result["integrity"]["ok"] and result["authenticity"]["ok"])
            lines.extend(
                [
                    f'jade_capture_healthy{{node="{label}"}} 0',
                    f'jade_signer_ready{{node="{label}"}} {signer_ready}',
                    f'jade_events_total{{node="{label}"}} {len(node_events)}',
                    f'jade_events_unsigned{{node="{label}"}} {unsigned}',
                    f'jade_pending_events{{node="{label}"}} {pending}',
                    f'jade_anchor_delay_seconds{{node="{label}"}} {max(0, now - newest_time):.3f}',
                    f'jade_anchor_rejected{{node="{label}"}} {anchor_errors.get(node, 0)}',
                    f'jade_integrity_ok{{node="{label}"}} {integrity}',
                ]
            )
        return "\n".join(lines) + "\n"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return (
            "# TYPE jade_exporter_up gauge\n"
            "jade_exporter_up 1\n"
            f'jade_integrity_ok{{node="{_label(DEFAULT_NODE)}"}} 0\n'
        )


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/verify":
            events_path = DATA_DIR / "events.jsonl"
            try:
                events = read_events(events_path)
                anchors_path = DATA_DIR / "anchors.json"
                anchors = json.loads(anchors_path.read_text(encoding="utf-8")) if anchors_path.exists() else None
                key_path = DATA_DIR / "trusted-public-key.b64"
                result = verify_evidence(
                    events,
                    load_public_key(key_path) if key_path.exists() else None,
                    anchors,
                )
                result["ledger_sha256"] = hashlib.sha256(events_path.read_bytes()).hexdigest()
                body = json.dumps(result, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                body = json.dumps({"status": "invalid", "error": str(exc)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = render_metrics().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("METRICS_PORT", "9108"))
    host = os.environ.get("METRICS_HOST", "0.0.0.0")
    ThreadingHTTPServer((host, port), MetricsHandler).serve_forever()
