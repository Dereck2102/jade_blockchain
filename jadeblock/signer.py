"""Firmador Ed25519 con contador persistente, bloqueo e idempotencia durable."""

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .backends import FileEd25519Backend, SignerBackend
from .protocol import (
    MAX_SAFE_COUNTER,
    event_body,
    event_hash,
    public_key_bytes,
    strict_json_dumps,
    strict_json_loads,
    validate_body,
)

MAX_RETAINED_CONFIRMED_REQUESTS = 256


def _fsync_directory(path: Path) -> None:
    """Persiste las entradas del directorio en POSIX.

    Windows no permite abrir directorios con ``os.open``; allí NTFS registra
    los metadatos del ``os.replace`` y se omite este paso.
    """
    if os.name == "nt":
        return
    directory_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def file_lock(lock_path: Path):
    """Bloqueo exclusivo entre procesos sobre un archivo centinela."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _atomic_json(path: Path, value: dict, mode: int = 0o600) -> None:
    atomic_write_text(path, strict_json_dumps(value) + "\n", mode=mode)


def _status_payload(counter: int, pub_b64: str) -> bytes:
    return f"jade-signer-status|{counter}|{pub_b64}".encode("utf-8")


def verify_signer_status_manifest(data: object, trusted_key: Ed25519PublicKey | None) -> bool:
    """Verifica un diccionario de manifiesto de salud contra la clave pública confiable."""
    if trusted_key is None or not isinstance(data, dict):
        return False
    counter = data.get("counter")
    pub_b64 = data.get("public_key")
    sig_b64 = data.get("probe_signature")
    if (
        isinstance(counter, bool)
        or not isinstance(counter, int)
        or counter < 0
        or counter > MAX_SAFE_COUNTER
        or not isinstance(pub_b64, str)
        or not isinstance(sig_b64, str)
    ):
        return False
    expected_pub = base64.b64encode(public_key_bytes(trusted_key)).decode("ascii")
    if pub_b64 != expected_pub:
        return False
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        trusted_key.verify(sig, _status_payload(counter, pub_b64))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def verify_signer_status_file(status_path: Path, trusted_key: Ed25519PublicKey | None) -> bool:
    """Verifica el manifiesto público de salud del firmador sin acceder a la clave privada."""
    if trusted_key is None or not status_path.is_file():
        return False
    try:
        data = strict_json_loads(status_path.read_text(encoding="utf-8"))
        return verify_signer_status_manifest(data, trusted_key)
    except (OSError, UnicodeError, ValueError, TypeError):
        return False


def _prune_requests_dict(
    requests: dict,
    recorded_hashes: set[str],
    max_retained: int = MAX_RETAINED_CONFIRMED_REQUESTS,
) -> dict:
    if len(requests) <= max_retained:
        return requests
    confirmed_ids = [
        req_id
        for req_id, entry in requests.items()
        if isinstance(entry, dict)
        and isinstance(entry.get("event"), dict)
        and entry["event"].get("hash") in recorded_hashes
    ]
    if len(confirmed_ids) <= max_retained:
        return requests
    confirmed_ids.sort(key=lambda req_id: requests[req_id]["event"].get("firma_n", 0))
    to_drop = set(confirmed_ids[: len(confirmed_ids) - max_retained])
    return {req_id: entry for req_id, entry in requests.items() if req_id not in to_drop}


class EventSigner:
    def __init__(self, state_dir: Path, backend: SignerBackend | None = None):
        self.state_dir = Path(state_dir)
        self.key_path = self.state_dir / "ed25519.key"
        self.state_path = self.state_dir / "signer-state.json"
        self.status_path = self.state_dir / "signer-status.json"
        self.lock_path = self.state_dir / ".signer.lock"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with file_lock(self.lock_path):
            if backend is None:
                if not self.key_path.exists() and self.state_path.exists():
                    raise RuntimeError(
                        f"Falta la clave del firmador; no se genera otra para el estado existente: {self.key_path}"
                    )
                self._new_key_created = not self.key_path.exists()
                self.backend: SignerBackend = FileEd25519Backend(self.key_path, _fsync_directory)
            else:
                self._new_key_created = not self.state_path.exists()
                self.backend = backend
        self._pub_b64 = base64.b64encode(public_key_bytes(self.backend.public_key())).decode("ascii")

    def public_key(self) -> Ed25519PublicKey:
        return self.backend.public_key()

    def public_key_b64(self) -> str:
        return self._pub_b64

    def sign_challenge(self, challenge: bytes) -> bytes:
        return self.backend.sign_message(challenge)

    def counter(self) -> int:
        return self._load_state()["counter"]

    def build_status_manifest(self, counter: int | None = None) -> dict:
        current = self.counter() if counter is None else counter
        sig = self.backend.sign_message(_status_payload(current, self._pub_b64))
        return {
            "counter": current,
            "public_key": self._pub_b64,
            "probe_signature": base64.b64encode(sig).decode("ascii"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def write_status_manifest(self, target_path: Path | None = None, counter: int | None = None) -> dict:
        manifest = self.build_status_manifest(counter=counter)
        _atomic_json(target_path or self.status_path, manifest, mode=0o644)
        return manifest

    @staticmethod
    def _extract_events_from_state(state: dict) -> dict[str, dict]:
        requests = state["requests"]
        events: dict[str, dict] = {}
        for request_id, request in requests.items():
            if not isinstance(request, dict) or not isinstance(request.get("event"), dict):
                raise RuntimeError("Registro de solicitud del firmador mal formado")
            events[request_id] = request["event"]
        return events

    def load_requests_snapshot(self) -> tuple[int, dict[str, dict]]:
        """Carga en una sola lectura el contador y el mapa de eventos firmados."""
        state = self._load_state()
        return state["counter"], self._extract_events_from_state(state)

    def request_result(self, request_id: str) -> dict | None:
        requests = self._load_state()["requests"]
        entry = requests.get(request_id)
        if entry is None:
            return None
        if not isinstance(entry, dict) or not isinstance(entry.get("event"), dict):
            raise RuntimeError("Registro de solicitud del firmador mal formado")
        return entry["event"]

    def request_events(self) -> dict[str, dict]:
        return self._extract_events_from_state(self._load_state())

    def prune_confirmed_requests(
        self,
        recorded_hashes: set[str],
        max_retained: int = MAX_RETAINED_CONFIRMED_REQUESTS,
    ) -> None:
        """Acota el historial de solicitudes ya persistidas en el ledger."""
        with file_lock(self.lock_path):
            if not self.state_path.exists():
                return
            state = self._load_state()
            pruned = _prune_requests_dict(state["requests"], recorded_hashes, max_retained)
            if len(pruned) != len(state["requests"]):
                state["requests"] = pruned
                _atomic_json(self.state_path, state)

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            if not self._new_key_created:
                raise RuntimeError(
                    f"Falta el estado del firmador; no se reinicia el contador: {self.state_path}"
                )
            return {"counter": 0, "requests": {}}
        try:
            state = strict_json_loads(self.state_path.read_text(encoding="utf-8"))
            counter = state.get("counter") if isinstance(state, dict) else None
            if (
                not isinstance(state, dict)
                or isinstance(counter, bool)
                or not isinstance(counter, int)
                or counter < 0
                or counter > MAX_SAFE_COUNTER
                or not isinstance(state.get("requests"), dict)
            ):
                raise ValueError("estructura inválida")
            return state
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(
                f"Estado del firmador ilegible; no se reinicia el contador: {self.state_path}"
            ) from exc

    def sign(
        self,
        body: dict,
        request_id: str,
        *,
        status_target: Path | None = None,
        recorded_hashes: set[str] | None = None,
    ) -> dict:
        if not isinstance(request_id, str) or not request_id or len(request_id) > 200:
            raise ValueError("request_id debe ser texto de entre 1 y 200 caracteres")
        request_digest = event_hash(body)
        with file_lock(self.lock_path):
            state = self._load_state()
            previous = state["requests"].get(request_id)
            if previous is not None:
                if not isinstance(previous, dict) or not isinstance(previous.get("event"), dict):
                    raise RuntimeError("Registro de solicitud del firmador mal formado")
                if previous.get("input_hash") != request_digest:
                    raise ValueError("request_id ya utilizado con otro contenido")
                return previous["event"]
            next_counter = state["counter"] + 1
            validate_body(body)
            signature = self.backend.sign_message(f"{next_counter}|{request_digest}".encode("utf-8"))
            event = {
                **event_body(body),
                "hash": request_digest,
                "firma": base64.b64encode(signature).decode("ascii"),
                "firma_n": next_counter,
            }
            state["counter"] = next_counter
            if recorded_hashes is not None:
                state["requests"] = _prune_requests_dict(state["requests"], recorded_hashes)
            state["requests"][request_id] = {"input_hash": request_digest, "event": event}
            _atomic_json(self.state_path, state)
            self._new_key_created = False
            self.write_status_manifest(target_path=status_target, counter=next_counter)
            return event
