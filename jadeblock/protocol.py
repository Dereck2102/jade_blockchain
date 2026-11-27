"""Esquema y serialización compatibles con el prototipo documentado."""

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = "1"
ZERO_HASH = "0" * 64
MAX_SAFE_COUNTER = (1 << 53) - 1
HEX_64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SIGNATURE_FIELDS = {"hash", "firma", "firma_n", "firma_error"}
REQUIRED_FIELDS = {"fecha", "nodo", "origen", "tipo", "nivel", "hash_anterior"}


def _reject_nonfinite(token: str):
    raise ValueError(f"Valor JSON no finito no permitido: {token}")


def strict_json_dumps(value, *, indent: int | None = None) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        indent=indent,
    )


def strict_json_loads(raw: str | bytes):
    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw
    return json.loads(text, parse_constant=_reject_nonfinite)


def is_positive_int(value) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and 1 <= value <= MAX_SAFE_COUNTER


def event_body(event: dict) -> dict:
    return {key: value for key, value in event.items() if key not in SIGNATURE_FIELDS}


def event_hash(event: dict) -> str:
    encoded = strict_json_dumps(event_body(event)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_body(body: dict) -> None:
    if not isinstance(body, dict) or not REQUIRED_FIELDS.issubset(body):
        raise ValueError(f"El evento requiere estos campos: {sorted(REQUIRED_FIELDS)}")
    if not all(isinstance(body[field], str) and body[field] for field in REQUIRED_FIELDS):
        raise ValueError("Los campos obligatorios del evento deben ser texto no vacío")
    if not HEX_64_RE.fullmatch(body["hash_anterior"]):
        raise ValueError("hash_anterior debe contener exactamente 64 caracteres hexadecimales")
    strict_json_dumps(event_body(body))


def sign_event(body: dict, counter: int, private_key: Ed25519PrivateKey) -> dict:
    if not is_positive_int(counter):
        raise ValueError("El contador de firma debe ser un entero positivo seguro")
    validate_body(body)
    digest = event_hash(body)
    signature = private_key.sign(f"{counter}|{digest}".encode("utf-8"))
    return {
        **event_body(body),
        "hash": digest,
        "firma": base64.b64encode(signature).decode("ascii"),
        "firma_n": counter,
    }


def verify_signature(event: dict, public_key: Ed25519PublicKey) -> bool:
    if not isinstance(event, dict):
        return False
    raw_sig = event.get("firma")
    raw_hash = event.get("hash")
    counter = event.get("firma_n")
    if (
        not isinstance(raw_sig, str)
        or not isinstance(raw_hash, str)
        or not HEX_64_RE.fullmatch(raw_hash)
        or not is_positive_int(counter)
    ):
        return False
    try:
        signature = base64.b64decode(raw_sig, validate=True)
        public_key.verify(signature, f"{counter}|{raw_hash}".encode("utf-8"))
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
