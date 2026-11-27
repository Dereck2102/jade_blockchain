import json
import tempfile
import unittest
from pathlib import Path
from argparse import Namespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jadeblock.cli import generate
from jadeblock.protocol import ZERO_HASH, event_hash, sign_event
from jadeblock.signer import EventSigner
from jadeblock.verify import verify_evidence


BODY = {
    "fecha": "2025-01-02T03:04:05Z",
    "nodo": "nodo-á",
    "origen": "prueba",
    "tipo": "cambio",
    "nivel": "info",
    "hash_anterior": ZERO_HASH,
    "datos": {"mensaje": "café 雪", "opcional": True},
}
EXPECTED_HASH = "5ef6c7f9a35ac9a93a817861ae0b7f016a886a56c13756f49b67656d53a17c85"


class EventProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "signer"
        self.key = Ed25519PrivateKey.generate()
        self.event = sign_event(BODY, 1, self.key)

    def test_hash_vector_preserves_unicode_and_optional_fields(self):
        self.assertEqual(event_hash(BODY), EXPECTED_HASH)
        self.assertEqual(self.event["hash"], EXPECTED_HASH)

    def test_valid_event_and_anchor(self):
        result = verify_evidence(
            [self.event],
            self.key.public_key(),
            [{"nodo": "nodo-á", "firma_n": 1, "hash": EXPECTED_HASH}],
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["anchor_coverage"]["status"], "local_only")
        self.assertFalse(result["anchor_coverage"]["checked"])

    def test_content_tampering_fails_chain_integrity(self):
        changed = {**self.event, "datos": {"mensaje": "alterado"}}
        result = verify_evidence([changed], self.key.public_key(), [])
        self.assertFalse(result["integrity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_invalid_signature_fails_authenticity(self):
        changed = {**self.event, "firma": "invalid"}
        result = verify_evidence([changed], self.key.public_key(), [])
        self.assertFalse(result["authenticity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_missing_trusted_key_is_not_strictly_valid(self):
        result = verify_evidence([self.event], None, [])
        self.assertFalse(result["authenticity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_unsigned_event_is_rejected(self):
        unsigned = {key: value for key, value in self.event.items() if key != "firma"}
        result = verify_evidence([unsigned], self.key.public_key(), [])
        self.assertFalse(result["authenticity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_empty_evidence_is_rejected(self):
        result = verify_evidence([], self.key.public_key(), [])
        self.assertEqual(result["status"], "invalid")

    def test_absent_anchors_are_reported_as_unchecked(self):
        result = verify_evidence([self.event], self.key.public_key(), None)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["anchor_coverage"]["status"], "not_checked")

    def test_partial_anchor_reports_unanchored_events(self):
        first = self.event
        second_body = {**BODY, "hash_anterior": first["hash"], "tipo": "segundo"}
        second = sign_event(second_body, 2, self.key)
        result = verify_evidence(
            [first, second],
            self.key.public_key(),
            [{"nodo": "nodo-á", "firma_n": 1, "hash": first["hash"]}],
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["anchor_coverage"]["pending_events_by_node"], {"nodo-á": 1}
        )

    def test_anchor_counter_regression_is_rejected(self):
        result = verify_evidence(
            [self.event, sign_event({**BODY, "hash_anterior": self.event["hash"], "tipo": "x"}, 2, self.key)],
            self.key.public_key(),
            [
                {"nodo": "nodo-á", "firma_n": 2, "hash": "0" * 64},
                {"nodo": "nodo-á", "firma_n": 1, "hash": self.event["hash"]},
            ],
        )
        self.assertEqual(result["anchor_coverage"]["status"], "invalid")
        self.assertEqual(result["status"], "invalid")

    def test_checkpoint_anchor_covers_verified_prefix(self):
        second = sign_event(
            {**BODY, "hash_anterior": self.event["hash"], "tipo": "segundo"},
            2,
            self.key,
        )
        result = verify_evidence(
            [self.event, second],
            self.key.public_key(),
            [{"nodo": "nodo-á", "firma_n": 2, "hash": second["hash"]}],
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["anchor_coverage"]["status"], "local_only")
        self.assertEqual(result["anchor_coverage"]["anchored_prefix_by_node"], {"nodo-á": 2})
        self.assertEqual(result["anchor_coverage"]["pending_events_by_node"], {})

    def test_checkpoint_anchor_does_not_cover_broken_prefix(self):
        second = sign_event(
            {**BODY, "hash_anterior": self.event["hash"], "tipo": "segundo"},
            2,
            self.key,
        )
        result = verify_evidence(
            [second],
            self.key.public_key(),
            [{"nodo": "nodo-á", "firma_n": 2, "hash": second["hash"]}],
        )
        self.assertEqual(result["anchor_coverage"]["status"], "invalid")
        self.assertEqual(result["status"], "invalid")

    def test_duplicate_anchor_is_rejected(self):
        result = verify_evidence(
            [self.event],
            self.key.public_key(),
            [
                {"nodo": "nodo-á", "firma_n": 1, "hash": self.event["hash"]},
                {"nodo": "nodo-á", "firma_n": 1, "hash": self.event["hash"]},
            ],
        )
        self.assertEqual(result["anchor_coverage"]["status"], "invalid")
        self.assertEqual(result["status"], "invalid")


class SignerPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "signer"

    def test_retries_are_idempotent_across_restart(self):
        first = EventSigner(self.state)
        event = first.sign(BODY, "request-1")
        restarted = EventSigner(self.state)
        retried = restarted.sign(BODY, "request-1")
        self.assertEqual(retried, event)
        second = restarted.sign({**BODY, "tipo": "otro"}, "request-2")
        self.assertEqual(second["firma_n"], 2)

    def test_request_id_cannot_be_reused_for_different_content(self):
        signer = EventSigner(self.state)
        signer.sign(BODY, "request-1")
        with self.assertRaises(ValueError):
            signer.sign({**BODY, "tipo": "otro"}, "request-1")

    def test_corrupt_state_does_not_reset_counter(self):
        signer = EventSigner(self.state)
        signer.sign(BODY, "request-1")
        (self.state / "signer-state.json").write_text("{broken", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            EventSigner(self.state).sign(BODY, "request-2")

    def test_missing_state_or_key_does_not_silently_reset(self):
        signer = EventSigner(self.state)
        signer.sign(BODY, "request-1")
        (self.state / "signer-state.json").unlink()
        with self.assertRaises(RuntimeError):
            EventSigner(self.state).sign(BODY, "request-2")
        (self.state / "signer-state.json").write_text("{}", encoding="utf-8")
        (self.state / "ed25519.key").unlink()
        with self.assertRaises(RuntimeError):
            EventSigner(self.state)

    def test_generator_retry_appends_the_same_request_once(self):
        events_path = Path(self.temporary.name) / "events.jsonl"
        state_dir = Path(self.temporary.name) / "cli-signer"
        public_key_path = Path(self.temporary.name) / "trusted.b64"
        args = Namespace(
            events=str(events_path),
            state_dir=str(state_dir),
            public_key=str(public_key_path),
            node="demo-node",
            request_id="stable-request",
        )
        generate(args)
        generate(args)
        lines = events_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(EventSigner(state_dir).request_result("stable-request")["firma_n"], 1)

    def test_pending_signed_request_blocks_new_request_and_can_be_retried(self):
        events_path = Path(self.temporary.name) / "pending-events.jsonl"
        public_key_path = Path(self.temporary.name) / "pending-trusted.b64"
        signer = EventSigner(self.state)
        pending = signer.sign(BODY, "pending-request")
        args = Namespace(
            events=str(events_path),
            state_dir=str(self.state),
            public_key=str(public_key_path),
            node=BODY["nodo"],
            request_id="different-request",
        )

        with self.assertRaisesRegex(RuntimeError, "solicitud firmada pendiente"):
            generate(args)
        self.assertEqual(EventSigner(self.state)._load_state()["counter"], 1)

        args.request_id = "pending-request"
        generate(args)
        self.assertEqual(
            json.loads(events_path.read_text(encoding="utf-8").splitlines()[0]),
            pending,
        )

    def test_modified_ledger_signature_does_not_count_as_recorded_request(self):
        events_path = Path(self.temporary.name) / "modified-events.jsonl"
        public_key_path = Path(self.temporary.name) / "modified-trusted.b64"
        signer = EventSigner(self.state)
        pending = signer.sign(BODY, "pending-request")
        altered = {**pending, "firma": "altered"}
        events_path.write_text(
            json.dumps(altered, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        args = Namespace(
            events=str(events_path),
            state_dir=str(self.state),
            public_key=str(public_key_path),
            node=BODY["nodo"],
            request_id="pending-request",
        )

        with self.assertRaisesRegex(RuntimeError, "no coincide"):
            generate(args)

    def test_strict_validation_rejects_nan_bad_hex_bool_counter_and_missing_fields(self):
        with self.assertRaises(ValueError):
            sign_event({**BODY, "datos": {"x": float("nan")}}, 1, self.key if hasattr(self, "key") else Ed25519PrivateKey.generate())
        key = Ed25519PrivateKey.generate()
        with self.assertRaises(ValueError):
            sign_event({**BODY, "hash_anterior": "0x" + "0" * 62}, 1, key)
        with self.assertRaises(ValueError):
            sign_event({**BODY, "hash_anterior": "0_" + "0" * 62}, 1, key)
        with self.assertRaises(ValueError):
            sign_event(BODY, True, key)
        with self.assertRaises(ValueError):
            sign_event(BODY, 0, key)

        valid = sign_event(BODY, 1, key)
        missing_type = {k: v for k, v in valid.items() if k != "tipo"}
        result = verify_evidence([missing_type], key.public_key(), None)
        self.assertFalse(result["integrity"]["ok"])
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(verify_evidence(["no-es-dict"], key.public_key(), None)["status"], "invalid")

    def test_interleaved_multinode_chain_and_checkpoints_verify(self):
        key = Ed25519PrivateKey.generate()
        e1 = sign_event({**BODY, "nodo": "nodo-1", "hash_anterior": ZERO_HASH}, 1, key)
        e2 = sign_event({**BODY, "nodo": "nodo-2", "hash_anterior": e1["hash"]}, 1, key)
        e3 = sign_event({**BODY, "nodo": "nodo-1", "hash_anterior": e2["hash"]}, 2, key)
        anchors = [
            {"nodo": "nodo-1", "firma_n": 2, "hash": e3["hash"]},
            {"nodo": "nodo-2", "firma_n": 1, "hash": e2["hash"]},
        ]
        result = verify_evidence([e1, e2, e3], key.public_key(), anchors)
        self.assertTrue(result["integrity"]["ok"])
        self.assertTrue(result["authenticity"]["ok"])
        self.assertEqual(result["anchor_coverage"]["status"], "local_only")
        self.assertEqual(
            result["anchor_coverage"]["anchored_prefix_by_node"],
            {"nodo-1": 2, "nodo-2": 1},
        )

    def test_cli_main_exit_codes_trusted_key_protection_and_pruning(self):
        from jadeblock.cli import main

        events_path = Path(self.temporary.name) / "cli-main-events.jsonl"
        state_dir = Path(self.temporary.name) / "cli-main-signer"
        pub_path = Path(self.temporary.name) / "cli-main-pub.b64"
        anchors_path = Path(self.temporary.name) / "cli-main-anchors.json"

        code_gen = main(
            [
                "generate",
                "--events",
                str(events_path),
                "--state-dir",
                str(state_dir),
                "--public-key",
                str(pub_path),
                "--request-id",
                "r-1",
            ]
        )
        self.assertEqual(code_gen, 0)
        code_verify_incomplete = main(
            [
                "verify",
                "--events",
                str(events_path),
                "--public-key",
                str(pub_path),
                "--anchors",
                str(anchors_path),
            ]
        )
        self.assertEqual(code_verify_incomplete, 2)

        # No debe sobrescribir una clave pública confiable distinta ya existente.
        other_signer_dir = Path(self.temporary.name) / "other-signer"
        other_pub_path = Path(self.temporary.name) / "other-pub.b64"
        code_other = main(
            [
                "generate",
                "--events",
                str(Path(self.temporary.name) / "other-events.jsonl"),
                "--state-dir",
                str(other_signer_dir),
                "--public-key",
                str(other_pub_path),
            ]
        )
        self.assertEqual(code_other, 0)
        code_mismatch = main(
            [
                "generate",
                "--events",
                str(events_path),
                "--state-dir",
                str(state_dir),
                "--public-key",
                str(other_pub_path),
                "--request-id",
                "r-2",
            ]
        )
        self.assertEqual(code_mismatch, 1)
        self.assertEqual(EventSigner(state_dir).counter(), 1)

        # Poda de solicitudes confirmadas conserva solicitudes pendientes.
        signer = EventSigner(state_dir)
        recorded = {e["hash"] for e in json.loads("[" + ",".join(events_path.read_text(encoding="utf-8").splitlines()) + "]")}
        e2 = signer.sign({**BODY, "hash_anterior": next(iter(recorded))}, "r-2")
        e3_pending = signer.sign({**BODY, "hash_anterior": e2["hash"]}, "r-3-pending")
        signer.prune_confirmed_requests(recorded | {e2["hash"]}, max_retained=1)
        remaining = signer.request_events()
        self.assertNotIn("r-1", remaining)
        self.assertIn("r-2", remaining)
        self.assertEqual(remaining["r-3-pending"], e3_pending)

    def test_cli_handles_cp1252_stdout_without_unicode_error(self):
        import io
        from unittest.mock import patch
        from jadeblock.cli import main

        events_path = Path(self.temporary.name) / "cp1252-events.jsonl"
        state_dir = Path(self.temporary.name) / "cp1252-signer"
        pub_path = Path(self.temporary.name) / "cp1252-pub.b64"

        signer = EventSigner(state_dir)
        signer.sign(BODY, "unicode-snow")  # Contiene '雪' (\u96ea), no representable en cp1252

        raw_out = io.BytesIO()
        cp1252_stdout = io.TextIOWrapper(raw_out, encoding="cp1252", errors="strict")
        with patch("sys.stdout", cp1252_stdout):
            exit_code = main(
                [
                    "generate",
                    "--events",
                    str(events_path),
                    "--state-dir",
                    str(state_dir),
                    "--public-key",
                    str(pub_path),
                    "--node",
                    BODY["nodo"],
                    "--request-id",
                    "unicode-snow",
                ]
            )
        self.assertEqual(exit_code, 0)
        decoded = raw_out.getvalue().decode("utf-8")
        self.assertIn("café 雪", decoded)

    def test_callback_backend_and_enclave_ipc_protocol(self):
        from unittest.mock import patch
        from jadeblock.backends import CallbackSignerBackend, EnclaveSignerClient
        from jadeblock.cli import main
        from jadeblock.enclave_server import dispatch_signer_request
        from jadeblock.protocol import strict_json_dumps

        key = Ed25519PrivateKey.generate()
        bad_backend = CallbackSignerBackend(key.public_key(), lambda _msg: b"short")
        with self.assertRaises(RuntimeError):
            EventSigner(Path(self.temporary.name) / "bad-backend", backend=bad_backend).sign(
                BODY, "bad-1"
            )

        enclave_dir = Path(self.temporary.name) / "enclave-state"
        enclave_signer = EventSigner(
            enclave_dir,
            backend=CallbackSignerBackend(key.public_key(), key.sign),
        )

        def fake_request(_self, payload: dict) -> dict:
            raw = (strict_json_dumps(payload) + "\n").encode("utf-8")
            resp = dispatch_signer_request(enclave_signer, raw)
            if not resp.get("ok"):
                raise RuntimeError(resp.get("error", "err"))
            return resp

        events_path = Path(self.temporary.name) / "ipc-events.jsonl"
        pub_path = Path(self.temporary.name) / "ipc-pub.b64"
        status_path = Path(self.temporary.name) / "ipc-status.json"
        with patch.object(EnclaveSignerClient, "_request", fake_request):
            rc1 = main(
                [
                    "generate",
                    "--signer-endpoint",
                    "127.0.0.1:9201",
                    "--events",
                    str(events_path),
                    "--public-key",
                    str(pub_path),
                    "--signer-status",
                    str(status_path),
                    "--node",
                    "enclave-node",
                    "--request-id",
                    "ipc-1",
                ]
            )
            rc1_retry = main(
                [
                    "generate",
                    "--signer-endpoint",
                    "127.0.0.1:9201",
                    "--events",
                    str(events_path),
                    "--public-key",
                    str(pub_path),
                    "--signer-status",
                    str(status_path),
                    "--node",
                    "enclave-node",
                    "--request-id",
                    "ipc-1",
                ]
            )
        self.assertEqual(rc1, 0)
        self.assertEqual(rc1_retry, 0)
        lines = events_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["firma_n"], 1)


if __name__ == "__main__":
    unittest.main()
