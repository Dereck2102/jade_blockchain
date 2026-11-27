"""Exportador Prometheus y endpoint de verificación local endurecidos."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .protocol import is_positive_int, strict_json_dumps, strict_json_loads
from .signer import EventSigner, verify_signer_status_file
from .verify import load_public_key, parse_events_bytes, verify_evidence

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


def _is_finite_number(value) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _signer_ready(state_dir: Path, trusted_key, status_path: Path | None = None) -> bool:
    if trusted_key is None:
        return False
    manifest_candidates = [p for p in (status_path, state_dir / "signer-status.json") if p is not None]
    key_path = state_dir / "ed25519.key"
    state_path = state_dir / "signer-state.json"

    # Modo aislado (sin acceso a ed25519.key): verifica el manifiesto firmado con la clave pública.
    if not key_path.is_file() and not state_path.is_file():
        return any(verify_signer_status_file(candidate, trusted_key) for candidate in manifest_candidates)

    if not key_path.is_file() or not state_path.is_file():
        return False
    try:
        signer = EventSigner(state_dir)
        signer.counter()
        public_key = signer.public_key()
        encoding = serialization.Encoding.Raw
        public_format = serialization.PublicFormat.Raw
        if public_key.public_bytes(encoding, public_format) != trusted_key.public_bytes(
            encoding, public_format
        ):
            return False
        challenge = b"jade-blockchain-signer-health-check"
        trusted_key.verify(signer.sign_challenge(challenge), challenge)
        return True
    except (OSError, ValueError, TypeError, RuntimeError, InvalidSignature):
        return False


def _load_anchor_errors(anchor_errors_path: Path) -> dict[str, int]:
    anchor_errors: dict[str, int] = {}
    try:
        error_state = strict_json_loads(anchor_errors_path.read_text(encoding="utf-8"))
        if not isinstance(error_state, dict):
            return anchor_errors
        counts = error_state.get("counts")
        if isinstance(counts, dict):
            for node, count in counts.items():
                if (
                    isinstance(node, str)
                    and node
                    and not isinstance(count, bool)
                    and isinstance(count, int)
                    and count >= 0
                ):
                    anchor_errors[node] = count
        else:
            count = error_state.get("count")
            node = error_state.get("node", DEFAULT_NODE)
            if (
                isinstance(node, str)
                and node
                and not isinstance(count, bool)
                and isinstance(count, int)
                and count >= 0
            ):
                anchor_errors[node] = count
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        pass
    return anchor_errors


def render_metrics() -> str:
    events_path = DATA_DIR / "events.jsonl"
    key_path = DATA_DIR / "trusted-public-key.b64"
    anchors_path = DATA_DIR / "anchors.json"
    status_path = DATA_DIR / "signer-status.json"
    try:
        events = parse_events_bytes(events_path.read_bytes()) if events_path.exists() else []
        anchors = (
            strict_json_loads(anchors_path.read_text(encoding="utf-8"))
            if anchors_path.exists()
            else []
        )
        if not isinstance(anchors, list):
            raise ValueError("anchors must be an array")
        key = load_public_key(key_path) if key_path.exists() else None
        result = verify_evidence(events, key, anchors if anchors_path.exists() else None)
        signer_ready = int(_signer_ready(DATA_DIR / "signer", key, status_path=status_path))

        event_nodes = {
            event["nodo"]
            for event in events
            if isinstance(event, dict) and isinstance(event.get("nodo"), str) and event["nodo"]
        }
        anchor_nodes = {
            anchor["nodo"]
            for anchor in anchors
            if isinstance(anchor, dict) and isinstance(anchor.get("nodo"), str) and anchor["nodo"]
        }
        nodes = sorted(event_nodes | anchor_nodes | {DEFAULT_NODE})

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
            "# HELP jade_anchor_delay_seconds Age of the oldest unanchored event in seconds (0 when caught up).",
            "# TYPE jade_anchor_delay_seconds gauge",
            "# HELP jade_anchor_rejected Total recorded anchor failures.",
            "# TYPE jade_anchor_rejected counter",
            "# HELP jade_integrity_ok Whether chain, signatures, and local anchor consistency hold.",
            "# TYPE jade_integrity_ok gauge",
        ]
        anchor_errors = _load_anchor_errors(DATA_DIR / "anchor-errors.json")
        now = time.time()
        verified_prefixes = result["anchor_coverage"]["anchored_prefix_by_node"]
        anchor_status = result["anchor_coverage"]["status"]
        overall_ok = int(result["status"] != "invalid")

        for node in nodes:
            label = _label(node)
            node_events = [
                event for event in events if isinstance(event, dict) and event.get("nodo") == node
            ]
            anchored_counter = verified_prefixes.get(node, 0) if anchor_status != "invalid" else 0
            unsigned = sum(
                "firma" not in event or "firma_n" not in event for event in node_events
            )
            max_event_counter = max(
                (event["firma_n"] for event in node_events if is_positive_int(event.get("firma_n"))),
                default=0,
            )
            pending = max(0, max(len(node_events), max_event_counter) - anchored_counter)
            pending_events = [
                event
                for event in node_events
                if not is_positive_int(event.get("firma_n")) or event["firma_n"] > anchored_counter
            ]
            pending_times = [
                stamp
                for stamp in (_timestamp(event.get("fecha")) for event in pending_events)
                if stamp is not None
            ]
            delay_seconds = max(0.0, now - min(pending_times)) if pending_times else 0.0

            lines.extend(
                [
                    f'jade_capture_healthy{{node="{label}"}} 0',
                    f'jade_signer_ready{{node="{label}"}} {signer_ready}',
                    f'jade_events_total{{node="{label}"}} {len(node_events)}',
                    f'jade_events_unsigned{{node="{label}"}} {unsigned}',
                    f'jade_pending_events{{node="{label}"}} {pending}',
                    f'jade_anchor_delay_seconds{{node="{label}"}} {delay_seconds:.3f}',
                    f'jade_anchor_rejected{{node="{label}"}} {anchor_errors.get(node, 0)}',
                    f'jade_integrity_ok{{node="{label}"}} {overall_ok}',
                ]
            )
        return "\n".join(lines) + "\n"
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        return (
            "# TYPE jade_exporter_up gauge\n"
            "jade_exporter_up 1\n"
            f'jade_integrity_ok{{node="{_label(DEFAULT_NODE)}"}} 0\n'
        )


def evaluate_verification_snapshot(data_dir: Path | None = None) -> dict:
    """Lee el ledger una sola vez (sin TOCTOU) y devuelve resultado + SHA-256 exacto."""
    base = data_dir or DATA_DIR
    events_path = base / "events.jsonl"
    raw_ledger = events_path.read_bytes()
    ledger_sha256 = hashlib.sha256(raw_ledger).hexdigest()
    events = parse_events_bytes(raw_ledger)
    anchors_path = base / "anchors.json"
    anchors = (
        strict_json_loads(anchors_path.read_text(encoding="utf-8"))
        if anchors_path.exists()
        else None
    )
    key_path = base / "trusted-public-key.b64"
    key = load_public_key(key_path) if key_path.exists() else None
    result = verify_evidence(events, key, anchors)
    result["ledger_sha256"] = ledger_sha256
    return result


class BoundedHTTPServer(HTTPServer):
    """Servidor HTTP con pool acotado de hilos para mitigar agotamiento de recursos."""

    def __init__(self, server_address, RequestHandlerClass, max_workers: int = 8):
        super().__init__(server_address, RequestHandlerClass)
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def process_request(self, request, client_address):
        self._executor.submit(self._process_request_thread, request, client_address)

    def _process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def server_close(self):
        super().server_close()
        self._executor.shutdown(wait=False, cancel_futures=True)


class MetricsHandler(BaseHTTPRequestHandler):
    timeout = 5

    def _write_json(self, status_code: int, payload: dict) -> None:
        body = strict_json_dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/verify":
            try:
                result = evaluate_verification_snapshot()
                self._write_json(200, result)
            except FileNotFoundError:
                self._write_json(
                    400,
                    {"status": "invalid", "code": "missing_evidence", "error": "Archivo de eventos ausente"},
                )
            except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
                self._write_json(
                    400,
                    {"status": "invalid", "code": "verification_error", "error": "No fue posible verificar la evidencia local"},
                )
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
    host = os.environ.get("METRICS_HOST", "127.0.0.1")
    BoundedHTTPServer((host, port), MetricsHandler).serve_forever()
