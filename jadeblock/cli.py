"""CLI reproducible para generar y verificar eventos sintéticos."""

import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid

from cryptography.hazmat.primitives import serialization

from .protocol import ZERO_HASH, public_key_bytes
from .signer import EventSigner
from .verify import read_events, verify_files


def _write_public_key(path: Path, signer: EventSigner) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        base64.b64encode(public_key_bytes(signer.public_key())).decode("ascii") + "\n",
        encoding="ascii",
    )


def generate(args) -> int:
    ledger = Path(args.events)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    events = read_events(ledger) if ledger.exists() else []
    previous_hash = events[-1]["hash"] if events else ZERO_HASH
    signer = EventSigner(Path(args.state_dir))
    body = {
        "fecha": datetime.now(timezone.utc).isoformat(),
        "nodo": args.node,
        "origen": "generador-sintetico",
        "tipo": "archivo_modificado",
        "nivel": "info",
        "hash_anterior": previous_hash,
        "datos": {"mensaje": "evento sintético de demostración", "secuencia": len(events) + 1},
    }
    signed = signer.sign(body, args.request_id or str(uuid.uuid4()))
    if not any(event.get("hash") == signed["hash"] for event in events):
        with ledger.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(signed, ensure_ascii=False, sort_keys=True) + "\n")
            stream.flush()
    _write_public_key(Path(args.public_key), signer)
    print(json.dumps(signed, ensure_ascii=False, sort_keys=True))
    return 0


def verify(args) -> int:
    result = verify_files(args.events, args.public_key, args.anchors)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if result["status"] == "verified":
        return 0
    if result["status"] == "incomplete":
        return 2
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="jade")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("generate", help="añade un evento sintético firmado")
    create.add_argument("--events", default="data/events.jsonl")
    create.add_argument("--state-dir", default="data/signer")
    create.add_argument("--public-key", default="data/trusted-public-key.b64")
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
    except (OSError, ValueError, RuntimeError) as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

