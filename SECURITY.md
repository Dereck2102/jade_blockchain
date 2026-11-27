# Seguridad

Esta es una base de investigación y una demostración local, no un producto endurecido. No la uses como sistema de auditoría o evidencia judicial ni la conectes a producción.

No se deben enviar claves privadas, credenciales, state Terraform, eventos de anfitriones ni datos personales a issues o pull requests. Este repositorio no declara un correo ni un canal privado de contacto para reportes; no presupongas que GitHub Private Vulnerability Reporting está habilitado.

El firmador de demo no está aislado por hardware; la clave vive en un volumen local. Protege permisos y respaldos. La cadena usa un solo validador, y quien controle el host de Docker controla el entorno local y sus datos. La protección efectiva de puertos Docker/UFW/IPv6 debe revisarse en cada host.

La CI pública solo ejecuta validaciones con datos sintéticos, sin secretos, sin acceso a infraestructura y sin despliegue automático. El estado Terraform puede contener valores sensibles: el atributo `sensitive` no lo cifra.
