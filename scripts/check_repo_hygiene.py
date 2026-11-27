"""Comprueba que los archivos del repositorio no incluyan secretos ni datos locales."""

from pathlib import Path
import re
import subprocess
import sys

FORBIDDEN_PATH_PATTERNS = (
    re.compile(r"(^|/)\.env(\..+)?$", re.IGNORECASE),
    re.compile(r"\.(key|pem|p12|pfx|jks|kdbx|tfstate|tfstate\..*|tfplan)$", re.IGNORECASE),
    re.compile(r"\.(docx?|pdf|zip)$", re.IGNORECASE),
    re.compile(r"(^|/)terraform\.tfvars$", re.IGNORECASE),
    re.compile(r"(^|/)ansible/inventory/generated", re.IGNORECASE),
    re.compile(r"(^|/)(events\.jsonl|signer-state\.json|anchors\.json|contract\.json)$", re.IGNORECASE),
    re.compile(r"(^|/)(backups|contexto)/", re.IGNORECASE),
    re.compile(
        r"(contexto|inventario_y_plan|ingenieria_inversa|manifiesto_codigo|"
        r"bloques_replicacion|pruebas_locales_verificadores|lector_inventario|"
        r"acceso_inventario|lectura_codigo|lectura_configuracion)",
        re.IGNORECASE,
    ),
)
ALLOWED_PATH_EXCEPTIONS = {
    ".env.example",
    "infrastructure/proxmox/terraform.tfvars.example",
}

CONTENT_RULES = (
    (
        "bloque de clave privada PEM o PGP",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----"),
    ),
    (
        "token o credencial conocida",
        re.compile(
            r"(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
            r"tskey-[A-Za-z0-9-]+|xox[bap]-[A-Za-z0-9-]+|"
            r"![A-Za-z0-9._-]+=[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        ),
    ),
    (
        "clave hexadecimal de 32 bytes (0x...)",
        re.compile(r"\b0x(?!0{64})[0-9a-fA-F]{64}\b"),
    ),
    (
        "ruta local de usuario",
        re.compile(r"([A-Za-z]:\\{1,2}Users\\{1,2}|/home/[a-zA-Z0-9._-]+/|/Users/[a-zA-Z0-9._-]+/)"),
    ),
    (
        "identificador local de máquina o usuario",
        re.compile(r"\b(DESKTOP-[A-Z0-9-]+|LAPTOP-[A-Z0-9-]+|STJFN1P|Hanssel31)\b"),
    ),
    (
        "IP privada RFC1918 o Tailscale",
        re.compile(
            r"(?<![0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|"
            r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}|"
            r"172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|"
            r"100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3})"
        ),
    ),
)

FAST_LINE_PREFILTER = re.compile(
    r"(-----BEGIN|ghp_|gho_|ghs_|github_pat_|AKIA|AIza|tskey-|xox[bap]-|"
    r"![A-Za-z0-9._-]+=[0-9a-fA-F]{8}-|\b0x[0-9a-fA-F]{16}|"
    r":\\{1,2}Users\\|/home/|/Users/|DESKTOP-|LAPTOP-|STJFN1P|Hanssel31|"
    r"(?:10|192\.168|172\.|100\.)[0-9])"
)

SKIP_CONTENT_FILES = {
    "chain/package-lock.json",
    "scripts/check_repo_hygiene.py",
    "tests/test_hygiene.py",
}


def tracked_and_unignored_files() -> list[str]:
    raw = subprocess.check_output(
        [
            "git",
            "-c",
            "core.quotepath=false",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ]
    )
    return sorted({entry.decode("utf-8", errors="surrogateescape") for entry in raw.split(b"\0") if entry})


def _read_text_with_fallback(file_path: Path) -> str | None:
    raw = file_path.read_bytes()
    for encoding in ("utf-8", "utf-16"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def scan_paths(paths: list[str], root: Path = Path(".")) -> list[str]:
    findings: list[str] = []
    for rel_path in paths:
        normalized = rel_path.replace("\\", "/")
        if normalized not in ALLOWED_PATH_EXCEPTIONS:
            for pattern in FORBIDDEN_PATH_PATTERNS:
                if pattern.search(normalized):
                    findings.append(f"{normalized}: archivo sensible no permitido")
                    break
        if normalized in SKIP_CONTENT_FILES:
            continue
        file_path = root / normalized
        if not file_path.is_file():
            continue
        content = _read_text_with_fallback(file_path)
        if content is None:
            continue
        for line_number, line in enumerate(content.splitlines(), 1):
            if not FAST_LINE_PREFILTER.search(line):
                continue
            for label, regex in CONTENT_RULES:
                if regex.search(line):
                    findings.append(f"{normalized}:{line_number}: posible {label}")
    return findings


def _write_utf8(stream, text: str) -> None:
    payload = text + "\n"
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(payload.encode("utf-8"))
        buffer.flush()
        return
    stream.write(payload.encode("ascii", errors="backslashreplace").decode("ascii"))
    stream.flush()


def main() -> int:
    findings = scan_paths(tracked_and_unignored_files())
    if findings:
        for item in findings:
            _write_utf8(sys.stderr, item)
        return 1
    _write_utf8(sys.stdout, "Higiene del repositorio verificada sin hallazgos.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
