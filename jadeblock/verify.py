"""Verificación separada de integridad, firmas y cobertura de anclaje."""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .protocol import ZERO_HASH, event_hash, verify_signature


def read_events(path: Path) -> list[dict]:
    events = []
    with Path(path).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if line.strip():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"JSON inválido en línea {line_number}") from exc
                if not isinstance(event, dict):
                    raise ValueError(f"Evento inválido en línea {line_number}")
                events.append(event)
    return events


def load_public_key(path: Path | None) -> Ed25519PublicKey | None:
    if path is None:
        return None
    raw = base64.b64decode(Path(path).read_bytes().strip(), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_evidence(
    events: list[dict],
    public_key: Ed25519PublicKey | None,
    anchors: list[dict] | None = None,
) -> dict:
    chain_ok = bool(events)
    signatures_ok = public_key is not None and bool(events)
    previous_hash = ZERO_HASH
    counters: dict[str, int] = {}
    event_by_node_counter: dict[tuple[str, int], dict] = {}
    failures: list[str] = []
    for index, event in enumerate(events, 1):
        if event.get("hash_anterior") != previous_hash:
            chain_ok = False
            failures.append(f"hash_anterior incorrecto en evento {index}")
        try:
            digest = event_hash(event)
        except (TypeError, ValueError):
            digest = None
        if digest is None or event.get("hash") != digest:
            chain_ok = False
            failures.append(f"hash de contenido incorrecto en evento {index}")
        previous_hash = event.get("hash", "")
        node = event.get("nodo")
        counter = event.get("firma_n")
        if not isinstance(node, str) or not isinstance(counter, int) or counter < 1:
            signatures_ok = False
            failures.append(f"contador o nodo inválido en evento {index}")
        elif counter != counters.get(node, 0) + 1:
            signatures_ok = False
            failures.append(f"contador no creciente para {node} en evento {index}")
        else:
            counters[node] = counter
            event_by_node_counter[(node, counter)] = event
        if public_key is None:
            signatures_ok = False
        elif not verify_signature(event, public_key):
            signatures_ok = False
            failures.append(f"firma inválida en evento {index}")

    if not events:
        failures.append("evidencia vacía")
    if public_key is None:
        failures.append("falta una clave pública confiable")
    if events and any("firma" not in event or "firma_n" not in event for event in events):
        signatures_ok = False
        failures.append("hay eventos sin firma")

    anchor_state = "not_checked"
    covered: dict[str, int] = {}
    pending: dict[str, int] = {}
    anchor_ok = False
    if anchors:
        anchor_state = "partial"
        anchor_ok = True
        last_by_node: dict[str, int] = {}
        for anchor in anchors:
            node, counter = anchor.get("nodo"), anchor.get("firma_n")
            if not isinstance(node, str) or not isinstance(counter, int):
                anchor_ok = False
                failures.append("registro de ancla mal formado")
                continue
            if counter <= last_by_node.get(node, 0):
                anchor_ok = False
                failures.append(f"regresión o duplicado de ancla para {node}")
                continue
            last_by_node[node] = counter
            covered_event = event_by_node_counter.get((node, counter))
            if covered_event is None or covered_event.get("hash") != anchor.get("hash"):
                anchor_ok = False
                failures.append(f"ancla no corresponde a evento local: {node}/{counter}")
                continue
            covered[node] = counter
        for node, counter in counters.items():
            if covered.get(node, 0) < counter:
                pending[node] = counter - covered.get(node, 0)
        if not pending and anchor_ok:
            anchor_state = "complete"
        elif not anchor_ok:
            anchor_state = "invalid"

    complete = chain_ok and signatures_ok and anchor_ok and anchor_state == "complete"
    return {
        "schema_version": "1",
        "status": "verified" if complete else (
            "invalid" if not chain_ok or not signatures_ok or anchor_state == "invalid"
            else "incomplete"
        ),
        "integrity": {"checked": True, "ok": chain_ok},
        "authenticity": {
            "checked": public_key is not None,
            "ok": signatures_ok,
        },
        "anchor_coverage": {
            "checked": anchors is not None and len(anchors) > 0,
            "status": anchor_state,
            "anchored_prefix_by_node": covered,
            "pending_events_by_node": pending,
        },
        "event_count": len(events),
        "failures": failures,
    }


def verify_files(events_path: Path, public_key_path: Path | None, anchors_path: Path | None):
    events = read_events(events_path)
    key = load_public_key(public_key_path)
    anchors = None
    if anchors_path is not None and Path(anchors_path).exists():
        anchors = json.loads(Path(anchors_path).read_text(encoding="utf-8"))
        if not isinstance(anchors, list):
            raise ValueError("El archivo de anclas debe contener una lista JSON")
    return verify_evidence(events, key, anchors)

