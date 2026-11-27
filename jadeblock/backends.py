"""Abstracciones de custodia de clave para firmadores software, HSM/TPM o enclave."""

import base64
import os
from pathlib import Path
import socket
from typing import Callable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import (
    HEX_64_RE,
    is_positive_int,
    strict_json_dumps,
    strict_json_loads,
    verify_signature,
)

MAX_IPC_LINE_BYTES = 65_536


class SignerBackend(Protocol):
    """Contrato mínimo de un proveedor criptográfico Ed25519 (software, TPM/KMS o HSM)."""

    def public_key(self) -> Ed25519PublicKey: ...

    def sign_message(self, message: bytes) -> bytes: ...


class FileEd25519Backend:
    """Custodia local en archivo ed25519.key con permisos 0600."""

    def __init__(self, key_path: Path, fsync_dir: Callable[[Path], None]):
        self.key_path = Path(key_path)
        self._fsync_dir = fsync_dir
        self._private_key = self._load_or_create()

    def _load_or_create(self) -> Ed25519PrivateKey:
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
            self._fsync_dir(self.key_path.parent)
            return key
        return Ed25519PrivateKey.from_private_bytes(raw)

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign_message(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class CallbackSignerBackend:
    """Adaptador para delegar la operación de firma a PKCS#11, Cloud KMS o llave sellada por TPM."""

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        sign_fn: Callable[[bytes], bytes],
    ):
        self._public_key = public_key
        self._sign_fn = sign_fn

    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def sign_message(self, message: bytes) -> bytes:
        signature = self._sign_fn(message)
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise RuntimeError("El proveedor externo devolvió una firma Ed25519 inválida")
        self._public_key.verify(bytes(signature), message)
        return bytes(signature)


def parse_endpoint(endpoint: str) -> tuple[str, int]:
    host, sep, raw_port = endpoint.rpartition(":")
    if not sep or not host:
        raise ValueError("El endpoint del firmador debe tener formato HOST:PUERTO")
    port = int(raw_port)
    if port < 1 or port > 65535:
        raise ValueError("Puerto del firmador fuera de rango (1..65535)")
    return host, port


class EnclaveSignerClient:
    """Cliente IPC hacia un servicio firmador aislado (p. ej. Gramine SGX/direct o micro-VM)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9201, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _request(self, payload: dict) -> dict:
        encoded = (strict_json_dumps(payload) + "\n").encode("utf-8")
        if len(encoded) > MAX_IPC_LINE_BYTES:
            raise ValueError("Solicitud al firmador excede el tamaño máximo permitido")
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as conn:
            conn.sendall(encoded)
            chunks = bytearray()
            while b"\n" not in chunks:
                piece = conn.recv(4096)
                if not piece:
                    break
                chunks.extend(piece)
                if len(chunks) > MAX_IPC_LINE_BYTES:
                    raise RuntimeError("Respuesta del firmador excede el tamaño máximo permitido")
        line = bytes(chunks).split(b"\n", 1)[0]
        if not line:
            raise RuntimeError("El servicio firmador cerró la conexión sin responder")
        response = strict_json_loads(line)
        if not isinstance(response, dict):
            raise RuntimeError("Respuesta mal formada del servicio firmador")
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error", "Error en el servicio firmador")))
        return response

    def status(self) -> dict:
        response = self._request({"op": "status"})
        manifest = response.get("status")
        if not isinstance(manifest, dict):
            raise RuntimeError("Manifiesto de estado ausente en respuesta del firmador")
        return manifest

    def public_key(self) -> Ed25519PublicKey:
        manifest = self.status()
        pub_b64 = manifest.get("public_key")
        if not isinstance(pub_b64, str):
            raise RuntimeError("Clave pública inválida en el servicio firmador")
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))

    def lookup(self, request_id: str) -> tuple[dict | None, dict]:
        response = self._request({"op": "lookup", "request_id": request_id})
        manifest = response.get("status")
        if not isinstance(manifest, dict):
            raise RuntimeError("Manifiesto de estado ausente en respuesta del firmador")
        event = response.get("event")
        if event is None:
            return None, manifest
        if not isinstance(event, dict):
            raise RuntimeError("Evento previo mal formado devuelto por el enclave")
        pub_b64 = manifest.get("public_key")
        if not isinstance(pub_b64, str):
            raise RuntimeError("Clave pública inválida en el servicio firmador")
        pub_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))
        if not verify_signature(event, pub_key):
            raise RuntimeError("La firma del evento recuperado del enclave no verificó")
        return event, manifest

    def sign(self, body: dict, request_id: str) -> tuple[dict, dict]:
        response = self._request({"op": "sign", "body": body, "request_id": request_id})
        event = response.get("event")
        manifest = response.get("status")
        if not isinstance(event, dict) or not isinstance(manifest, dict):
            raise RuntimeError("Respuesta de firma incompleta desde el enclave")
        pub_b64 = manifest.get("public_key")
        if (
            not isinstance(pub_b64, str)
            or not isinstance(event.get("hash"), str)
            or not HEX_64_RE.fullmatch(event["hash"])
            or not is_positive_int(event.get("firma_n"))
        ):
            raise RuntimeError("Metadatos de firma inválidos devueltos por el enclave")
        pub_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64, validate=True))
        if not verify_signature(event, pub_key):
            raise RuntimeError("La firma devuelta por el servicio firmador no verificó")
        return event, manifest
