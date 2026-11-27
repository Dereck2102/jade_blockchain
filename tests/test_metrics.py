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
        self.assertIn('jade_integrity_ok{node="demo-node"} 1', rendered)


if __name__ == "__main__":
    unittest.main()
