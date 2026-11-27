"""Firmador Ed25519 con contador persistente e idempotencia durable."""

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import event_body, event_hash, sign_event


def _atomic_json(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


class EventSigner:
    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.key_path = self.state_dir / "ed25519.key"
        self.state_path = self.state_dir / "signer-state.json"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.private_key = self._load_or_create_key()

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        try:
            raw = base64.b64decode(self.key_path.read_bytes(), validate=True)
        except FileNotFoundError:
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(base64.b64encode(raw))
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(self.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return key
        return Ed25519PrivateKey.from_private_bytes(raw)

    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return {"counter": 0, "requests": {}}
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            if (
                not isinstance(state, dict)
                or not isinstance(state.get("counter"), int)
                or state["counter"] < 0
                or not isinstance(state.get("requests"), dict)
            ):
                raise ValueError("estructura inválida")
            return state
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError(
                f"Estado del firmador ilegible; no se reinicia el contador: {self.state_path}"
            ) from exc

    def sign(self, body: dict, request_id: str) -> dict:
        if not request_id or len(request_id) > 200:
            raise ValueError("request_id debe tener entre 1 y 200 caracteres")
        request_digest = hashlib.sha256(
            json.dumps(event_body(body), sort_keys=True, ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest()
        state = self._load_state()
        previous = state["requests"].get(request_id)
        if previous is not None:
            if previous.get("input_hash") != request_digest:
                raise ValueError("request_id ya utilizado con otro contenido")
            return previous["event"]
        event = sign_event(body, state["counter"] + 1, self.private_key)
        state["counter"] += 1
        state["requests"][request_id] = {"input_hash": request_digest, "event": event}
        _atomic_json(self.state_path, state)
        return event

