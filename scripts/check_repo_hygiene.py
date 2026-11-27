"""Comprueba que los archivos versionados no incluyan secretos ni datos locales."""

from pathlib import Path
import re
import subprocess
import sys

FORBIDDEN_PATH_PATTERNS = (
    re.compile(r"(^|/)\.env(\..+)?$"),
    re.compile(r"\.(key|pem|p12|pfx|jks|kdbx|tfstate|tfstate\..*|tfplan)$"),
    re.compile(r"(^|/)terraform\.tfvars$"),
    re.compile(r"(^|/)ansible/inventory/generated"),
)
ALLOWED_EXACT_PATHS = {".env.example", "infrastructure/proxmox/terraform.tfvars.example"}

CONTENT_RULES = (
    ("clave privada PEM", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "token o credencial conocida",
        re.compile(
            r"(ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|"
            r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
            r"tskey-[A-Za-z0-9-]+|xox[bap]-[A-Za-z0-9-]+)"
        ),
    ),
    (
        "ruta local de usuario",
        re.compile(r"([A-Za-z]:\\\\Users\\\\|/home/[a-zA-Z0-9._-]+/|/Users/[a-zA-Z0-9._-]+/)"),
    ),
    (
        "identificador local de máquina o usuario",
        re.compile(r"\b(DESKTOP-[A-Z0-9]+|LAPTOP-[A-Z0-9]+|STJFN1P|Hanssel31)\b"),
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

SKIP_FILES = {"chain/package-lock.json", "scripts/check_repo_hygiene.py"}


def tracked_files() -> list[str]:
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        text=True,
        encoding="utf-8",
    )
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def main() -> int:
    findings: list[str] = []
    for rel_path in tracked_files():
        if rel_path in ALLOWED_EXACT_PATHS:
            continue
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.search(rel_path):
                findings.append(f"{rel_path}: archivo sensible versionado")
        if rel_path in SKIP_FILES:
            continue
        file_path = Path(rel_path)
        if not file_path.is_file():
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(content.splitlines(), 1):
            for label, regex in CONTENT_RULES:
                if regex.search(line):
                    findings.append(f"{rel_path}:{line_number}: posible {label}")
    if findings:
        for item in findings:
            print(item, file=sys.stderr)
        return 1
    print("Higiene del repositorio verificada sin hallazgos.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
