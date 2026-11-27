"""Pruebas de la matriz de seis ataques sobre registros (MITRE ATT&CK TA0005)."""

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from jadeblock.protocol import ZERO_HASH, event_hash, sign_event
from jadeblock.signer import EventSigner
from jadeblock.verify import verify_evidence


def _build_signed_chain(key: Ed25519PrivateKey, count: int = 4) -> list[dict]:
    events: list[dict] = []
    previous_hash = ZERO_HASH
    for index in range(1, count + 1):
        body = {
            "fecha": f"2026-11-05T10:00:0{index}Z",
            "nodo": "nodo-prueba",
            "origen": "archivos",
            "tipo": "modificado",
            "nivel": "info",
            "hash_anterior": previous_hash,
            "datos": {"ruta": f"/opt/apps/app_{index}.conf"},
        }
        signed = sign_event(body, index, key)
        events.append(signed)
        previous_hash = signed["hash"]
    return events


def _rehash_chain(events: list[dict]) -> list[dict]:
    rebuilt: list[dict] = []
    previous_hash = ZERO_HASH
    for index, event in enumerate(events, 1):
        copy = {**event, "hash_anterior": previous_hash, "firma_n": index}
        copy["hash"] = event_hash(copy)
        rebuilt.append(copy)
        previous_hash = copy["hash"]
    return rebuilt


class AttackMatrixTests(unittest.TestCase):
    """Replica los seis escenarios de la Tabla 4 del prototipo."""

    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.events = _build_signed_chain(self.key, count=4)
        self.anchors = [
            {
                "nodo": "nodo-prueba",
                "firma_n": 4,
                "hash": self.events[-1]["hash"],
            }
        ]

    def test_attack_1_edit_event_t1565_001_detected_by_hash_chain(self):
        tampered = [*self.events]
        tampered[1] = {**tampered[1], "nivel": "critico"}

        result = verify_evidence(tampered, self.key.public_key(), self.anchors)

        self.assertFalse(result["integrity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_attack_2_delete_event_t1070_detected_by_hash_chain(self):
        tampered = [self.events[0], self.events[2], self.events[3]]

        result = verify_evidence(tampered, self.key.public_key(), self.anchors)

        self.assertFalse(result["integrity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_attack_3_delete_and_rehash_t1070_bypasses_hash_chain_but_caught_by_signature(self):
        tampered = _rehash_chain([self.events[0], self.events[2], self.events[3]])

        result = verify_evidence(tampered, self.key.public_key(), self.anchors)

        self.assertTrue(result["integrity"]["ok"])
        self.assertFalse(result["authenticity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_attack_4_forge_content_and_rehash_t1565_001_bypasses_hash_chain_but_caught_by_signature(self):
        tampered = [*self.events]
        tampered[1] = {**tampered[1], "datos": {"ruta": "/opt/apps/limpio.conf"}}
        tampered = _rehash_chain(tampered)

        result = verify_evidence(tampered, self.key.public_key(), self.anchors)

        self.assertTrue(result["integrity"]["ok"])
        self.assertFalse(result["authenticity"]["ok"])
        self.assertEqual(result["status"], "invalid")

    def test_attack_5_wipe_and_restart_log_t1070_002_caught_only_by_anchors(self):
        # El atacante vacía el log y genera una nueva cadena válida desde n=1
        restarted_chain = _build_signed_chain(self.key, count=2)

        without_anchors = verify_evidence(restarted_chain, self.key.public_key(), None)
        self.assertTrue(without_anchors["integrity"]["ok"])
        self.assertTrue(without_anchors["authenticity"]["ok"])

        with_anchors = verify_evidence(restarted_chain, self.key.public_key(), self.anchors)
        self.assertEqual(with_anchors["anchor_coverage"]["status"], "invalid")
        self.assertEqual(with_anchors["status"], "invalid")

    def test_attack_6_rollback_signer_counter_t1565_caught_by_signer_and_anchors(self):
        from jadeblock.backends import CallbackSignerBackend

        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "signer"
            raw_key = Ed25519PrivateKey.generate()
            backend = CallbackSignerBackend(raw_key.public_key(), raw_key.sign)
            signer = EventSigner(state_dir, backend=backend)
            first = signer.sign(
                {
                    "fecha": "2026-11-05T10:00:01Z",
                    "nodo": "nodo-prueba",
                    "origen": "archivos",
                    "tipo": "creado",
                    "nivel": "info",
                    "hash_anterior": ZERO_HASH,
                },
                "req-1",
            )
            second = signer.sign(
                {
                    "fecha": "2026-11-05T10:00:02Z",
                    "nodo": "nodo-prueba",
                    "origen": "archivos",
                    "tipo": "modificado",
                    "nivel": "info",
                    "hash_anterior": first["hash"],
                },
                "req-2",
            )
            anchors = [{"nodo": "nodo-prueba", "firma_n": 2, "hash": second["hash"]}]

            # Si existe clave en disco y se borra signer-state.json, el firmador por archivo se detiene.
            file_state_dir = Path(tmp) / "file-signer"
            file_signer = EventSigner(file_state_dir)
            file_signer.sign(
                {
                    "fecha": "2026-11-05T10:00:01Z",
                    "nodo": "nodo-prueba",
                    "origen": "archivos",
                    "tipo": "creado",
                    "nivel": "info",
                    "hash_anterior": ZERO_HASH,
                },
                "req-f1",
            )
            (file_state_dir / "signer-state.json").unlink()
            with self.assertRaises(RuntimeError):
                EventSigner(file_state_dir).sign(
                    {
                        "fecha": "2026-11-05T10:00:03Z",
                        "nodo": "nodo-prueba",
                        "origen": "archivos",
                        "tipo": "falso",
                        "nivel": "info",
                        "hash_anterior": ZERO_HASH,
                    },
                    "req-rollback",
                )

            # Incluso con un snapshot antiguo que reemita n=1, el verificador detecta la regresión frente al ancla n=2.
            replayed_from_snapshot = [
                sign_event(
                    {
                        "fecha": "2026-11-05T10:00:03Z",
                        "nodo": "nodo-prueba",
                        "origen": "archivos",
                        "tipo": "reversion",
                        "nivel": "info",
                        "hash_anterior": ZERO_HASH,
                    },
                    1,
                    raw_key,
                )
            ]
            result = verify_evidence(replayed_from_snapshot, signer.public_key(), anchors)
            self.assertEqual(result["anchor_coverage"]["status"], "invalid")
            self.assertEqual(result["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
