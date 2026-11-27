"""Esquema y serialización compatibles con el prototipo documentado."""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = "1"
ZERO_HASH = "0" * 64
SIGNATURE_FIELDS = {"hash", "firma", "firma_n", "firma_error"}
REQUIRED_FIELDS = {"fecha", "nodo", "origen", "tipo", "nivel", "hash_anterior"}


def event_body(event: dict) -> dict:
    return {key: value for key, value in event.items() if key not in SIGNATURE_FIELDS}


def event_hash(event: dict) -> str:
    encoded = json.dumps(event_body(event), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def validate_body(body: dict) -> None:
    if not isinstance(body, dict) or not REQUIRED_FIELDS.issubset(body):
        raise ValueError(f"El evento requiere estos campos: {sorted(REQUIRED_FIELDS)}")
    if not all(isinstance(body[field], str) and body[field] for field in REQUIRED_FIELDS):
        raise ValueError("Los campos obligatorios del evento deben ser texto no vacío")
    if len(body["hash_anterior"]) != 64:
        raise ValueError("hash_anterior debe contener 64 caracteres hexadecimales")
    try:
        int(body["hash_anterior"], 16)
    except ValueError as exc:
        raise ValueError("hash_anterior debe contener 64 caracteres hexadecimales") from exc


def sign_event(body: dict, counter: int, private_key: Ed25519PrivateKey) -> dict:
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
    try:
        signature = base64.b64decode(event["firma"], validate=True)
        public_key.verify(
            signature, f"{event['firma_n']}|{event['hash']}".encode("utf-8")
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

