"""Pruebas unitarias del escáner de higiene contra secretos y fugas locales."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


def _load_hygiene_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "check_repo_hygiene.py"
    spec = importlib.util.spec_from_file_location("check_repo_hygiene", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepoHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hygiene = _load_hygiene_module()

    def test_detects_forbidden_files_case_insensitively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".ENV.PROD").write_text("PORT=1\n", encoding="utf-8")
            (root / "SECRET.KEY").write_text("abc\n", encoding="utf-8")
            (root / "events.jsonl").write_text("{}\n", encoding="utf-8")
            findings = self.hygiene.scan_paths([".ENV.PROD", "SECRET.KEY", "events.jsonl"], root=root)
            self.assertEqual(len(findings), 3)

    def test_blocks_context_and_document_archives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blocked = [
                "Contexto.zip",
                "Tesis_Final.docx",
                "borrador.pdf",
                "contexto/notas.txt",
                "Ingenieria_inversa_codigo_y_replicacion.txt",
                "Inventario_y_plan_de_replicacion.txt",
                "Manifiesto_codigo_observado.json",
            ]
            for rel in blocked:
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("x\n", encoding="utf-8")
            findings = self.hygiene.scan_paths(blocked, root=root)
            self.assertEqual(len(findings), len(blocked))

    def test_scans_allowed_example_files_for_leaked_content_and_utf16(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Construimos patrones en tiempo de ejecución para no activar reglas estáticas.
            fake_token = "ghp_" + "A" * 24
            (root / ".env.example").write_text(f"TOKEN={fake_token}\n", encoding="utf-8")
            win_path = "C:" + "\\Users\\dev\\secret.txt"
            (root / "utf16.txt").write_bytes(win_path.encode("utf-16"))
            hex_key = "0x" + "ab" * 32
            (root / "key.txt").write_text(f"KEY={hex_key}\n", encoding="utf-8")
            (root / "clean.txt").write_text("IP_DOC=192.0.2.21\nZERO=" + "0x" + "0" * 64 + "\n", encoding="utf-8")

            findings = self.hygiene.scan_paths(
                [".env.example", "utf16.txt", "key.txt", "clean.txt"],
                root=root,
            )
            joined = "\n".join(findings)
            self.assertIn(".env.example:1", joined)
            self.assertIn("utf16.txt:1", joined)
            self.assertIn("key.txt:1", joined)
            self.assertNotIn("clean.txt", joined)


if __name__ == "__main__":
    unittest.main()

