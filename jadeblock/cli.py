"""CLI reproducible para generar y verificar eventos sintéticos."""

import argparse
import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import uuid

from .protocol import HEX_64_RE, ZERO_HASH, public_key_bytes, strict_json_dumps
from .signer import EventSigner, atomic_write_text, file_lock
from .verify import read_events, verify_files


def _ensure_trusted_public_key(path: Path, signer: EventSigner) -> None:
    expected = base64.b64encode(public_key_bytes(signer.public_key())).decode("ascii")
    if path.exists():
        existing = path.read_text(encoding="ascii").strip()
        if existing != expected:
            raise RuntimeError(
                f"La clave pública confiable existente en {path} no coincide con el firmador"
            )
        return
    atomic_write_text(path, expected + "\n", mode=0o644)


def generate(args) -> int:
    ledger = Path(args.events)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger_lock = ledger.parent / f".{ledger.name}.lock"
    status_target = (
        Path(getattr(args, "signer_status", None))
        if getattr(args, "signer_status", None)
        else ledger.parent / "signer-status.json"
    )

    with file_lock(ledger_lock):
        events = read_events(ledger) if ledger.exists() else []
        if events:
            last_hash = events[-1].get("hash")
            if not isinstance(last_hash, str) or not HEX_64_RE.fullmatch(last_hash):
                raise ValueError("El último evento del ledger carece de un hash válido")
            previous_hash = last_hash
        else:
            previous_hash = ZERO_HASH

        signer = EventSigner(Path(args.state_dir))
        _ensure_trusted_public_key(Path(args.public_key), signer)
        request_id = args.request_id or str(uuid.uuid4())
        signed_requests = signer.request_events()
        recorded_serialized = {strict_json_dumps(event) for event in events}
        pending_requests = {
            pending_id: event
            for pending_id, event in signed_requests.items()
            if strict_json_dumps(event) not in recorded_serialized
        }
        if pending_requests and request_id not in pending_requests:
            raise RuntimeError(
                "Hay una solicitud firmada pendiente; reintente su request_id antes de generar otro evento"
            )
        signed = signer.request_result(request_id)
        if signed is not None and signed.get("nodo") != args.node:
            raise ValueError("request_id ya utilizado para otro nodo")
        if signed is None:
            node_seq = sum(1 for item in events if item.get("nodo") == args.node) + 1
            body = {
                "fecha": datetime.now(timezone.utc).isoformat(),
                "nodo": args.node,
                "origen": "generador-sintetico",
                "tipo": "archivo_modificado",
                "nivel": "info",
                "hash_anterior": previous_hash,
                "datos": {"mensaje": "evento sintético de demostración", "secuencia": node_seq},
            }
            signed = signer.sign(body, request_id)
        matching_events = [event for event in events if event.get("hash") == signed["hash"]]
        if any(event != signed for event in matching_events):
            raise RuntimeError("El evento del ledger no coincide con la solicitud firmada")
        already_recorded = bool(matching_events)
        if not already_recorded and signed["hash_anterior"] != previous_hash:
            raise RuntimeError(
                "Solicitud firmada pendiente fuera del final del ledger; se detiene para recuperar"
            )
        if not already_recorded:
            with ledger.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(strict_json_dumps(signed) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            recorded_hashes = {
                event.get("hash") for event in events if isinstance(event.get("hash"), str)
            } | {signed["hash"]}
            signer.prune_confirmed_requests(recorded_hashes)
        signer.write_status_manifest(target_path=status_target)

    print(strict_json_dumps(signed))
    return 0


def verify(args) -> int:
    result = verify_files(args.events, args.public_key, args.anchors)
    print(strict_json_dumps(result, indent=2))
    return 1 if result["status"] == "invalid" else 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="jade")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate", help="añade un evento sintético firmado")
    create.add_argument("--events", default="data/events.jsonl")
    create.add_argument("--state-dir", default="data/signer")
    create.add_argument("--public-key", default="data/trusted-public-key.b64")
    create.add_argument("--signer-status", help="ruta opcional del manifiesto público de salud")
    create.add_argument("--node", default="demo-node")
    create.add_argument("--request-id", help="ID estable para reintentar la misma solicitud")
    create.set_defaults(run=generate)
    check = commands.add_parser("verify", help="verifica eventos, firmas y anclas")
    check.add_argument("--events", default="data/events.jsonl")
    check.add_argument("--public-key", default="data/trusted-public-key.b64")
    check.add_argument("--anchors", default="data/anchors.json")
    check.set_defaults(run=verify)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(strict_json_dumps({"status": "invalid", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
