# Contribuir

Las contribuciones pequeñas, revisables y reproducibles son bienvenidas. No conectes cambios o runners públicos con el laboratorio ni uses datos, credenciales o eventos reales.

## Desarrollo local

Requisitos: Python 3.12, Node.js/npm compatibles con `chain/package-lock.json`, Docker Compose v2 para la integración y herramientas Terraform/Ansible para validar infraestructura.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install .
python -m unittest discover -s tests -v

npm ci --prefix chain
npm audit --prefix chain --audit-level=low
npm test --prefix chain
npm run --prefix chain compile

docker compose config --quiet
terraform fmt -check -recursive infrastructure/proxmox
terraform -chdir=infrastructure/proxmox init -backend=false
terraform -chdir=infrastructure/proxmox validate
(cd ansible && ansible-playbook --syntax-check -i inventory/example.yml site.yml)
```

Para la demostración, sigue el inicio rápido del README. El stack descarga imágenes y crea identidades locales; no ejecutes `terraform apply` en una infraestructura que no hayas autorizado.

## Cambios y pull requests

- Añade pruebas focalizadas para nuevas reglas de serialización, firma, contador, cobertura de ancla o autorización.
- Mantén compatible la serialización v1. Un cambio incompatible requiere una versión nueva de esquema y nota de migración.
- Declara qué fue implementado, qué se probó realmente y qué sigue pendiente; identifica explícitamente cualquier mock.
- No incluyas claves, `.env`, state/planes Terraform, backups, logs reales, datos personales ni tokens.
- CI de pull request no requiere secretos y no tiene credenciales ni ruta de red al laboratorio.
- Revisa los avisos/licencias de dependencias nuevas y conserva sus avisos aplicables.

## Mensajes de commit

Los commits siguen [Conventional Commits 1.0.0](https://www.conventionalcommits.org/es/v1.0.0/). La plantilla [.gitmessage](.gitmessage) resume el formato; actívala con `git config commit.template .gitmessage`.

```text
<tipo>(<alcance>): <descripción en imperativo, en español, ≤ 72 caracteres>

<cuerpo opcional: qué cambia, por qué y qué se probó>

<pies opcionales>
```

- **Tipos:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `revert`.
- **Alcances habituales:** `protocol`, `signer`, `verify`, `cli`, `metrics`, `chain`, `contract`, `compose`, `infra`, `ansible`, `observability`, `ci`, `docs`, `deps`.
- **Cambios incompatibles** (por ejemplo, del esquema de evento v1): `!` tras el alcance y un pie `BREAKING CHANGE:` con la migración.
- Un commit por cambio lógico; no mezcles refactor y corrección en el mismo commit.

### Atribución

- **Personas:** usa `Co-authored-by: Nombre <correo>` ([formato reconocido por GitHub](https://docs.github.com/es/pull-requests/committing-changes-to-your-project/creating-and-editing-commits/creating-a-commit-with-multiple-authors)) cuando otra persona escribió parte del cambio.
- **Herramientas de IA:** declara su uso con `Assisted-by: <Herramienta>:<modelo> [herramientas auxiliares]`, formato tomado de la [guía de asistentes de código del kernel Linux](https://docs.kernel.org/process/coding-assistants.html). Nombra solo las herramientas que intervinieron en ese commit. La IA no figura como autora ni firma `Signed-off-by`; la persona que hace el commit revisó el cambio y responde por él.
- Los créditos generales de autoría y de IA están en [CREDITS.md](CREDITS.md).

Ejemplo:

```text
fix(signer): omitir fsync de directorio en Windows

Windows no permite abrir directorios con os.open; 11 de 22 pruebas
fallaban con PermissionError. En POSIX el comportamiento no cambia.

Assisted-by: Claude:claude-opus-5.5 Antigravity
```

## Versiones y cambios

- Versionado [SemVer 2.0.0](https://semver.org/lang/es/): `fix` → PATCH, `feat` → MINOR, `BREAKING CHANGE` → MAJOR.
- Registra los cambios visibles en [CHANGELOG.md](CHANGELOG.md) siguiendo [Keep a Changelog 1.1.0](https://keepachangelog.com/es-ES/1.1.0/).
- Ramas: `main` estable, `Dev` integración y ramas de trabajo `tipo/descripcion-corta` (por ejemplo, `feat/inspector-docker`) con pull request hacia `Dev`.
