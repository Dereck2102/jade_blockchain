"""Verificación separada de integridad, firmas y cobertura de anclaje."""

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .protocol import (
    HEX_64_RE,
    ZERO_HASH,
    event_body,
    event_hash,
    is_positive_int,
    strict_json_loads,
    validate_body,
    verify_signature,
)


def parse_events_bytes(raw: bytes) -> list[dict]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Codificación UTF-8 inválida en el archivo de eventos") from exc
    events = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                event = strict_json_loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"JSON inválido en línea {line_number}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"Evento inválido en línea {line_number}")
            events.append(event)
    return events


def read_events(path: Path) -> list[dict]:
    return parse_events_bytes(Path(path).read_bytes())


def load_public_key(path: Path | None) -> Ed25519PublicKey | None:
    if path is None:
        return None
    raw = base64.b64decode(Path(path).read_bytes().strip(), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def _verify_chain_and_signatures(
    events: list[dict],
    public_key: Ed25519PublicKey | None,
) -> tuple[bool, bool, dict[str, int], dict[tuple[str, int], dict], list[str]]:
    chain_ok = bool(events)
    signatures_ok = public_key is not None and bool(events)
    previous_hash = ZERO_HASH
    counters: dict[str, int] = {}
    event_by_node_counter: dict[tuple[str, int], dict] = {}
    failures: list[str] = []
    saw_unsigned = False

    for index, event in enumerate(events, 1):
        if not isinstance(event, dict):
            chain_ok = False
            signatures_ok = False
            failures.append(f"evento mal formado en posición {index}")
            previous_hash = ""
            continue
        if event.get("hash_anterior") != previous_hash:
            chain_ok = False
            failures.append(f"hash_anterior incorrecto en evento {index}")
        try:
            validate_body(event_body(event))
            digest = event_hash(event)
        except (TypeError, ValueError):
            digest = None
        recorded_hash = event.get("hash")
        if (
            digest is None
            or not isinstance(recorded_hash, str)
            or not HEX_64_RE.fullmatch(recorded_hash)
            or recorded_hash != digest
        ):
            chain_ok = False
            failures.append(f"hash o esquema de contenido inválido en evento {index}")
        previous_hash = recorded_hash if isinstance(recorded_hash, str) else ""

        if "firma" not in event or "firma_n" not in event:
            saw_unsigned = True
        node = event.get("nodo")
        counter = event.get("firma_n")
        if not isinstance(node, str) or not node or not is_positive_int(counter):
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
    if saw_unsigned:
        signatures_ok = False
        failures.append("hay eventos sin firma")

    return chain_ok, signatures_ok, counters, event_by_node_counter, failures


def _verify_anchor_coverage(
    anchors: list[dict] | None,
    counters: dict[str, int],
    event_by_node_counter: dict[tuple[str, int], dict],
    chain_ok: bool,
    signatures_ok: bool,
    failures: list[str],
) -> tuple[str, dict[str, int], dict[str, int]]:
    if not anchors:
        pending = dict(counters) if anchors is not None else {}
        return "not_checked", {}, pending

    anchor_state = "partial"
    anchor_ok = True
    covered: dict[str, int] = {}
    pending: dict[str, int] = {}
    last_by_node: dict[str, int] = {}

    for anchor in anchors:
        if not isinstance(anchor, dict):
            anchor_ok = False
            failures.append("registro de ancla mal formado")
            continue
        node, counter, anchor_hash = anchor.get("nodo"), anchor.get("firma_n"), anchor.get("hash")
        if (
            not isinstance(node, str)
            or not node
            or not is_positive_int(counter)
            or not isinstance(anchor_hash, str)
            or not HEX_64_RE.fullmatch(anchor_hash)
        ):
            anchor_ok = False
            failures.append("registro de ancla mal formado")
            continue
        if counter <= last_by_node.get(node, 0):
            anchor_ok = False
            failures.append(f"regresión o duplicado de ancla para {node}")
            continue
        last_by_node[node] = counter
        covered_event = event_by_node_counter.get((node, counter))
        if covered_event is None or covered_event.get("hash") != anchor_hash:
            anchor_ok = False
            failures.append(f"ancla no corresponde a evento local: {node}/{counter}")
            continue
        covered[node] = counter

    for node, counter in counters.items():
        if covered.get(node, 0) < counter:
            pending[node] = counter - covered.get(node, 0)

    if not anchor_ok:
        anchor_state = "invalid"
    elif not chain_ok or not signatures_ok:
        anchor_state = "invalid"
        failures.append("el prefijo cubierto por el ancla no es íntegro o auténtico")
    elif not pending:
        anchor_state = "local_only"

    return anchor_state, covered, pending


def verify_evidence(
    events: list[dict],
    public_key: Ed25519PublicKey | None,
    anchors: list[dict] | None = None,
) -> dict:
    if not isinstance(events, list):
        raise ValueError("La lista de eventos es inválida")
    if anchors is not None and not isinstance(anchors, list):
        raise ValueError("La lista de anclas debe ser un arreglo")

    chain_ok, signatures_ok, counters, event_by_node_counter, failures = _verify_chain_and_signatures(
        events, public_key
    )
    anchor_state, covered, pending = _verify_anchor_coverage(
        anchors, counters, event_by_node_counter, chain_ok, signatures_ok, failures
    )
    is_invalid = not chain_ok or not signatures_ok or anchor_state == "invalid"

    return {
        "schema_version": "1",
        "status": "invalid" if is_invalid else "incomplete",
        "integrity": {"checked": True, "ok": chain_ok},
        "authenticity": {
            "checked": public_key is not None,
            "ok": signatures_ok,
        },
        "anchor_coverage": {
            "checked": False,
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
        anchors = strict_json_loads(Path(anchors_path).read_text(encoding="utf-8"))
        if not isinstance(anchors, list):
            raise ValueError("El archivo de anclas debe contener una lista JSON")
    return verify_evidence(events, key, anchors)
