import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jadeblock.metrics import _signer_ready
from jadeblock.signer import EventSigner


class SignerMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state_dir = Path(self.temporary.name) / "signer"
        self.signer = EventSigner(self.state_dir)
        self.signer.sign(
            {
                "fecha": "2025-01-02T03:04:05Z",
                "nodo": "demo-node",
                "origen": "test",
                "tipo": "test",
                "nivel": "info",
                "hash_anterior": "0" * 64,
            },
            "health-test",
        )

    def test_signing_probe_checks_key_and_does_not_increment_counter(self):
        state_path = self.state_dir / "signer-state.json"
        counter_before = json.loads(state_path.read_text(encoding="utf-8"))["counter"]

        self.assertTrue(_signer_ready(self.state_dir, self.signer.public_key()))

        counter_after = json.loads(state_path.read_text(encoding="utf-8"))["counter"]
        self.assertEqual(counter_after, counter_before)

    def test_signing_probe_rejects_mismatched_trusted_key(self):
        self.assertFalse(
            _signer_ready(self.state_dir, Ed25519PrivateKey.generate().public_key())
        )

    def test_signing_probe_rejects_corrupt_state(self):
        (self.state_dir / "signer-state.json").write_text("{broken", encoding="utf-8")
        self.assertFalse(_signer_ready(self.state_dir, self.signer.public_key()))

    def test_signing_probe_does_not_create_missing_identity(self):
        missing_state = Path(self.temporary.name) / "missing"
        self.assertFalse(_signer_ready(missing_state, self.signer.public_key()))
        self.assertFalse(missing_state.exists())

    def test_checkpoint_anchor_clears_pending_events_metric(self):
        import base64
        from unittest.mock import patch
        from jadeblock import metrics
        from jadeblock.protocol import public_key_bytes

        data_dir = Path(self.temporary.name) / "metrics-data"
        signer_dir = data_dir / "signer"
        signer = EventSigner(signer_dir)
        e1 = signer.sign(
            {
                "fecha": "2025-01-02T03:04:05Z",
                "nodo": "demo-node",
                "origen": "test",
                "tipo": "uno",
                "nivel": "info",
                "hash_anterior": "0" * 64,
            },
            "m-1",
        )
        e2 = signer.sign(
            {
                "fecha": "2025-01-02T03:04:06Z",
                "nodo": "demo-node",
                "origen": "test",
                "tipo": "dos",
                "nivel": "info",
                "hash_anterior": e1["hash"],
            },
            "m-2",
        )
        (data_dir / "events.jsonl").write_text(
            json.dumps(e1) + "\n" + json.dumps(e2) + "\n", encoding="utf-8"
        )
        (data_dir / "trusted-public-key.b64").write_text(
            base64.b64encode(public_key_bytes(signer.public_key())).decode("ascii") + "\n",
            encoding="ascii",
        )
        (data_dir / "anchors.json").write_text(
            json.dumps([{"nodo": "demo-node", "firma_n": 2, "hash": e2["hash"]}]),
            encoding="utf-8",
        )
        with patch.object(metrics, "DATA_DIR", data_dir):
            rendered = metrics.render_metrics()
        self.assertIn('jade_pending_events{node="demo-node"} 0', rendered)
        self.assertIn('jade_anchor_delay_seconds{node="demo-node"} 0.000', rendered)
        self.assertIn('jade_integrity_ok{node="demo-node"} 1', rendered)

    def test_wipe_and_restart_attack_sets_integrity_metric_to_zero(self):
        import base64
        from unittest.mock import patch
        from jadeblock import metrics
        from jadeblock.protocol import public_key_bytes

        data_dir = Path(self.temporary.name) / "attack5-metrics"
        signer = EventSigner(data_dir / "signer")
        restarted = signer.sign(
            {
                "fecha": "2026-11-05T10:00:01Z",
                "nodo": "demo-node",
                "origen": "test",
                "tipo": "reinicio",
                "nivel": "info",
                "hash_anterior": "0" * 64,
            },
            "a5-1",
        )
        (data_dir / "events.jsonl").write_text(json.dumps(restarted) + "\n", encoding="utf-8")
        (data_dir / "trusted-public-key.b64").write_text(
            base64.b64encode(public_key_bytes(signer.public_key())).decode("ascii") + "\n",
            encoding="ascii",
        )
        (data_dir / "anchors.json").write_text(
            json.dumps([{"nodo": "demo-node", "firma_n": 4, "hash": "a" * 64}]),
            encoding="utf-8",
        )
        with patch.object(metrics, "DATA_DIR", data_dir):
            rendered = metrics.render_metrics()
        self.assertIn('jade_integrity_ok{node="demo-node"} 0', rendered)

    def test_isolated_signer_manifest_and_http_endpoints(self):
        import base64
        import hashlib
        import io
        from unittest.mock import patch
        from jadeblock import metrics
        from jadeblock.protocol import public_key_bytes

        class _InMemorySocket:
            def __init__(self, raw_request: bytes):
                self._rfile = io.BytesIO(raw_request)
                self.output = io.BytesIO()
                self.timeout = None

            def settimeout(self, value):
                self.timeout = value

            def makefile(self, mode: str, *_args, **_kwargs):
                return self._rfile if "r" in mode else self.output

            def sendall(self, data: bytes):
                self.output.write(data)

        def invoke_http(path_str: str) -> tuple[int, str]:
            sock = _InMemorySocket(f"GET {path_str} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("ascii"))
            metrics.MetricsHandler(sock, ("127.0.0.1", 12345), None)
            raw_resp = sock.output.getvalue().decode("utf-8", errors="replace")
            header_block, _, body = raw_resp.partition("\r\n\r\n")
            status_code = int(header_block.splitlines()[0].split()[1])
            return status_code, body

        isolated_signer_dir = Path(self.temporary.name) / "isolated-signer"
        data_dir = Path(self.temporary.name) / "public-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        signer = EventSigner(isolated_signer_dir)
        ev = signer.sign(
            {
                "fecha": "2026-11-05T10:00:01Z",
                "nodo": "demo-node",
                "origen": "test",
                "tipo": "creado",
                "nivel": "info",
                "hash_anterior": "0" * 64,
            },
            "iso-1",
        )
        ledger_bytes = (json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        (data_dir / "events.jsonl").write_bytes(ledger_bytes)
        (data_dir / "trusted-public-key.b64").write_text(
            base64.b64encode(public_key_bytes(signer.public_key())).decode("ascii") + "\n",
            encoding="ascii",
        )
        signer.write_status_manifest(target_path=data_dir / "signer-status.json")

        # Sin ed25519.key en data_dir/signer, el exportador valida el manifiesto firmado.
        self.assertTrue(
            _signer_ready(
                data_dir / "signer",
                signer.public_key(),
                status_path=data_dir / "signer-status.json",
            )
        )

        with patch.object(metrics, "DATA_DIR", data_dir):
            code_m, body_m = invoke_http("/metrics")
            self.assertEqual(code_m, 200)
            self.assertIn('jade_signer_ready{node="demo-node"} 1', body_m)

            code_v, body_v = invoke_http("/verify")
            verified = json.loads(body_v)
            self.assertEqual(code_v, 200)
            self.assertEqual(
                verified["ledger_sha256"],
                hashlib.sha256(ledger_bytes).hexdigest(),
            )

            code_404, _ = invoke_http("/nope")
            self.assertEqual(code_404, 404)

            (data_dir / "events.jsonl").unlink()
            code_400, body_400 = invoke_http("/verify")
            self.assertEqual(code_400, 400)
            err_payload = json.loads(body_400)
            self.assertEqual(err_payload["code"], "missing_evidence")
            self.assertNotIn(str(data_dir), err_payload["error"])


if __name__ == "__main__":
    unittest.main()
