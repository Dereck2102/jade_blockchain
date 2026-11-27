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


if __name__ == "__main__":
    unittest.main()
