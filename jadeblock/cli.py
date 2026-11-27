"""CLI reproducible para generar, simular y verificar eventos firmados."""

import argparse
import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import uuid

from .backends import EnclaveSignerClient, parse_endpoint
from .protocol import HEX_64_RE, ZERO_HASH, public_key_bytes, strict_json_dumps
from .serverless import build_function_lifecycle_bodies
from .signer import (
    EventSigner,
    _atomic_json,
    atomic_write_text,
    file_lock,
    verify_signer_status_manifest,
)
from .verify import load_public_key, read_events, verify_files


def _write_utf8_line(stream, text: str) -> None:
    """Escribe UTF-8 sin fallar aunque la consola Windows use cp1252 (Python 3.12)."""
    payload = text + "\n"
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(payload.encode("utf-8"))
        buffer.flush()
        return
    try:
        stream.write(payload)
    except UnicodeEncodeError:
        stream.write(payload.encode("ascii", errors="backslashreplace").decode("ascii"))
    stream.flush()


def _ensure_trusted_public_key_bytes(path: Path, pub_bytes: bytes) -> None:
    expected = base64.b64encode(pub_bytes).decode("ascii")
    if path.exists():
        existing = path.read_text(encoding="ascii").strip()
        if existing != expected:
            raise RuntimeError(
                f"La clave pública confiable existente en {path} no coincide con el firmador"
            )
        return
    atomic_write_text(path, expected + "\n", mode=0o644)


def _index_events_by_hash(events: list[dict]) -> dict[str, dict]:
    indexed: dict[str, dict] = {}
    for event in events:
        digest = event.get("hash")
        if isinstance(digest, str):
            indexed[digest] = event
    return indexed


def _append_one_remote(
    client: EnclaveSignerClient,
    trusted_key,
    *,
    node: str,
    request_id: str,
    body_builder,
    events_by_hash: dict[str, dict],
    previous_hash: str,
    ledger: Path,
    status_target: Path,
) -> dict:
    signed, manifest = client.lookup(request_id)
    if signed is None:
        signed, manifest = client.sign(body_builder(previous_hash), request_id)
    if not verify_signer_status_manifest(manifest, trusted_key):
        raise RuntimeError("Manifiesto de salud inválido devuelto por el servicio firmador")
    if signed.get("nodo") != node:
        raise ValueError("request_id ya utilizado para otro nodo")
    existing = events_by_hash.get(signed["hash"])
    if existing is not None and existing != signed:
        raise RuntimeError("El evento del ledger no coincide con la solicitud firmada")
    if existing is None:
        if signed["hash_anterior"] != previous_hash:
            raise RuntimeError(
                "Solicitud firmada pendiente fuera del final del ledger; se detiene para recuperar"
            )
        with ledger.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(strict_json_dumps(signed) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        events_by_hash[signed["hash"]] = signed
    _atomic_json(status_target, manifest, mode=0o644)
    return signed


def _append_one_local(
    signer: EventSigner,
    *,
    node: str,
    request_id: str,
    body_builder,
    events_by_hash: dict[str, dict],
    previous_hash: str,
    ledger: Path,
    status_target: Path,
) -> dict:
    _, signed_requests = signer.load_requests_snapshot()
    pending_requests: dict[str, dict] = {}
    for pending_id, req_event in signed_requests.items():
        recorded = events_by_hash.get(req_event.get("hash", ""))
        if recorded is None:
            pending_requests[pending_id] = req_event
        elif recorded != req_event:
            raise RuntimeError("El evento del ledger no coincide con la solicitud firmada")

    if pending_requests and request_id not in pending_requests:
        raise RuntimeError(
            "Hay una solicitud firmada pendiente; reintente su request_id antes de generar otro evento"
        )
    signed = signed_requests.get(request_id)
    if signed is not None and signed.get("nodo") != node:
        raise ValueError("request_id ya utilizado para otro nodo")

    recorded_hashes = set(events_by_hash)
    wrote_manifest_in_sign = False
    if signed is None:
        signed = signer.sign(
            body_builder(previous_hash),
            request_id,
            status_target=status_target,
            recorded_hashes=recorded_hashes,
        )
        wrote_manifest_in_sign = True

    existing = events_by_hash.get(signed["hash"])
    if existing is not None and existing != signed:
        raise RuntimeError("El evento del ledger no coincide con la solicitud firmada")
    if existing is None:
        if signed["hash_anterior"] != previous_hash:
            raise RuntimeError(
                "Solicitud firmada pendiente fuera del final del ledger; se detiene para recuperar"
            )
        with ledger.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(strict_json_dumps(signed) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        events_by_hash[signed["hash"]] = signed
    if not wrote_manifest_in_sign:
        signer.write_status_manifest(target_path=status_target)
    return signed


def _load_ledger_tail(ledger: Path) -> tuple[list[dict], str, dict[str, dict]]:
    events = read_events(ledger) if ledger.exists() else []
    if events:
        last_hash = events[-1].get("hash")
        if not isinstance(last_hash, str) or not HEX_64_RE.fullmatch(last_hash):
            raise ValueError("El último evento del ledger carece de un hash válido")
        previous_hash = last_hash
    else:
        previous_hash = ZERO_HASH
    return events, previous_hash, _index_events_by_hash(events)


def generate(args) -> int:
    ledger = Path(args.events)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger_lock = ledger.parent / f".{ledger.name}.lock"
    status_target = (
        Path(getattr(args, "signer_status", None))
        if getattr(args, "signer_status", None)
        else ledger.parent / "signer-status.json"
    )
    endpoint = getattr(args, "signer_endpoint", None) or os.environ.get("JADE_SIGNER_ENDPOINT")
    pub_key_path = Path(args.public_key)

    with file_lock(ledger_lock):
        events, previous_hash, events_by_hash = _load_ledger_tail(ledger)
        request_id = args.request_id or str(uuid.uuid4())
        node_seq = sum(1 for item in events if item.get("nodo") == args.node) + 1

        def build_synthetic(prev_hash: str) -> dict:
            return {
                "fecha": datetime.now(timezone.utc).isoformat(),
                "nodo": args.node,
                "origen": "generador-sintetico",
                "tipo": "archivo_modificado",
                "nivel": "info",
                "hash_anterior": prev_hash,
                "datos": {"mensaje": "evento sintético de demostración", "secuencia": node_seq},
            }

        if endpoint:
            host, port = parse_endpoint(endpoint)
            pinned = load_public_key(pub_key_path) if pub_key_path.exists() else None
            client = EnclaveSignerClient(host=host, port=port, pinned_public_key=pinned)
            trusted_key = client.public_key()
            _ensure_trusted_public_key_bytes(pub_key_path, public_key_bytes(trusted_key))
            client.pinned_public_key = trusted_key
            signed = _append_one_remote(
                client,
                trusted_key,
                node=args.node,
                request_id=request_id,
                body_builder=build_synthetic,
                events_by_hash=events_by_hash,
                previous_hash=previous_hash,
                ledger=ledger,
                status_target=status_target,
            )
        else:
            signer = EventSigner(Path(args.state_dir))
            _ensure_trusted_public_key_bytes(pub_key_path, public_key_bytes(signer.public_key()))
            signed = _append_one_local(
                signer,
                node=args.node,
                request_id=request_id,
                body_builder=build_synthetic,
                events_by_hash=events_by_hash,
                previous_hash=previous_hash,
                ledger=ledger,
                status_target=status_target,
            )

    _write_utf8_line(sys.stdout, strict_json_dumps(signed))
    return 0


def simulate_function(args) -> int:
    ledger = Path(args.events)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger_lock = ledger.parent / f".{ledger.name}.lock"
    status_target = (
        Path(getattr(args, "signer_status", None))
        if getattr(args, "signer_status", None)
        else ledger.parent / "signer-status.json"
    )
    endpoint = getattr(args, "signer_endpoint", None) or os.environ.get("JADE_SIGNER_ENDPOINT")
    pub_key_path = Path(args.public_key)
    invocation_id = args.invocation_id or uuid.uuid4().hex[:8]
    stages = build_function_lifecycle_bodies(
        node=args.node,
        function_name=args.function,
        invocation_id=invocation_id,
        simulate_failure=bool(args.fail),
    )

    emitted: list[dict] = []
    with file_lock(ledger_lock):
        _, previous_hash, events_by_hash = _load_ledger_tail(ledger)
        if endpoint:
            host, port = parse_endpoint(endpoint)
            pinned = load_public_key(pub_key_path) if pub_key_path.exists() else None
            client = EnclaveSignerClient(host=host, port=port, pinned_public_key=pinned)
            trusted_key = client.public_key()
            _ensure_trusted_public_key_bytes(pub_key_path, public_key_bytes(trusted_key))
            client.pinned_public_key = trusted_key
            for suffix, partial in stages:
                signed = _append_one_remote(
                    client,
                    trusted_key,
                    node=args.node,
                    request_id=f"fn-{invocation_id}-{suffix}",
                    body_builder=lambda prev, p=partial: {**p, "hash_anterior": prev},
                    events_by_hash=events_by_hash,
                    previous_hash=previous_hash,
                    ledger=ledger,
                    status_target=status_target,
                )
                previous_hash = signed["hash"]
                emitted.append(signed)
        else:
            signer = EventSigner(Path(args.state_dir))
            _ensure_trusted_public_key_bytes(pub_key_path, public_key_bytes(signer.public_key()))
            for suffix, partial in stages:
                signed = _append_one_local(
                    signer,
                    node=args.node,
                    request_id=f"fn-{invocation_id}-{suffix}",
                    body_builder=lambda prev, p=partial: {**p, "hash_anterior": prev},
                    events_by_hash=events_by_hash,
                    previous_hash=previous_hash,
                    ledger=ledger,
                    status_target=status_target,
                )
                previous_hash = signed["hash"]
                emitted.append(signed)

    for event in emitted:
        _write_utf8_line(sys.stdout, strict_json_dumps(event))
    return 0


def verify(args) -> int:
    result = verify_files(args.events, args.public_key, args.anchors)
    _write_utf8_line(sys.stdout, strict_json_dumps(result, indent=2))
    return 1 if result["status"] == "invalid" else 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="jade")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("generate", help="añade un evento sintético firmado")
    create.add_argument("--events", default="data/events.jsonl")
    create.add_argument("--state-dir", default="data/signer")
    create.add_argument("--public-key", default="data/trusted-public-key.b64")
    create.add_argument("--signer-status", help="ruta opcional del manifiesto público de salud")
    create.add_argument(
        "--signer-endpoint",
        help="endpoint HOST:PUERTO de un servicio firmador aislado (Gramine/enclave)",
    )
    create.add_argument("--node", default="demo-node")
    create.add_argument("--request-id", help="ID estable para reintentar la misma solicitud")
    create.set_defaults(run=generate)

    sim = commands.add_parser(
        "simulate",
        help="registra el ciclo de vida completo de una función efímera (5 eventos)",
    )
    sim.add_argument("--events", default="data/events.jsonl")
    sim.add_argument("--state-dir", default="data/signer")
    sim.add_argument("--public-key", default="data/trusted-public-key.b64")
    sim.add_argument("--signer-status", help="ruta opcional del manifiesto público de salud")
    sim.add_argument("--signer-endpoint", help="endpoint HOST:PUERTO de un servicio firmador aislado")
    sim.add_argument("--node", default="demo-node")
    sim.add_argument("--function", default="autenticar", help="nombre lógico de la función efímera")
    sim.add_argument("--invocation-id", help="ID estable para reintento idempotente de la invocación")
    sim.add_argument("--fail", action="store_true", help="simula fallo con código de salida 1")
    sim.set_defaults(run=simulate_function)

    check = commands.add_parser("verify", help="verifica eventos, firmas y anclas")
    check.add_argument("--events", default="data/events.jsonl")
    check.add_argument("--public-key", default="data/trusted-public-key.b64")
    check.add_argument("--anchors", default="data/anchors.json")
    check.set_defaults(run=verify)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        _write_utf8_line(sys.stderr, strict_json_dumps({"status": "invalid", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
