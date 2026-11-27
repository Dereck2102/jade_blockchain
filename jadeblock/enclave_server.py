"""Servicio firmador aislado por socket TCP local (compatible con Gramine direct/SGX)."""

import os
from pathlib import Path
import socketserver
import threading

from .backends import MAX_IPC_LINE_BYTES
from .protocol import strict_json_dumps, strict_json_loads
from .signer import EventSigner


def dispatch_signer_request(signer: EventSigner, raw_line: bytes) -> dict:
    if len(raw_line) > MAX_IPC_LINE_BYTES:
        return {"ok": False, "error": "Solicitud demasiado grande"}
    try:
        request = strict_json_loads(raw_line)
    except Exception:
        return {"ok": False, "error": "JSON inválido"}
    if not isinstance(request, dict):
        return {"ok": False, "error": "La solicitud debe ser un objeto JSON"}

    op = request.get("op")
    try:
        if op == "status":
            return {"ok": True, "status": signer.build_status_manifest()}
        if op == "lookup":
            request_id = request.get("request_id")
            if not isinstance(request_id, str) or not request_id:
                return {"ok": False, "error": "request_id obligatorio"}
            existing = signer.request_result(request_id)
            return {
                "ok": True,
                "event": existing,
                "status": signer.build_status_manifest(),
            }
        if op == "sign":
            body = request.get("body")
            request_id = request.get("request_id")
            if not isinstance(body, dict) or not isinstance(request_id, str):
                return {"ok": False, "error": "Campos body y request_id obligatorios"}
            signed = signer.sign(body, request_id)
            return {
                "ok": True,
                "event": signed,
                "status": signer.build_status_manifest(counter=signed["firma_n"]),
            }
        return {"ok": False, "error": "Operación no soportada"}
    except (ValueError, RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


class _SignerTCPHandler(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self) -> None:
        raw_line = self.rfile.readline(MAX_IPC_LINE_BYTES + 1)
        if not raw_line:
            return
        response = self.server.dispatch(raw_line)  # type: ignore[attr-defined]
        self.wfile.write((strict_json_dumps(response) + "\n").encode("utf-8"))
        self.wfile.flush()


class EnclaveSignerServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], signer: EventSigner):
        super().__init__(server_address, _SignerTCPHandler)
        self._signer = signer
        self._lock = threading.Lock()

    def dispatch(self, raw_line: bytes) -> dict:
        with self._lock:
            return dispatch_signer_request(self._signer, raw_line)


def main() -> int:
    state_dir = Path(os.environ.get("JADE_SIGNER_DIR", "/signer"))
    host = os.environ.get("JADE_SIGNER_HOST", "127.0.0.1")
    port = int(os.environ.get("JADE_SIGNER_PORT", "9201"))
    signer = EventSigner(state_dir)
    signer.write_status_manifest()
    with EnclaveSignerServer((host, port), signer) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
