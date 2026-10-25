# MediNet-Core · Módulo 11 AUD

Auditoría y trazabilidad de seguridad: recibe los eventos de los demás módulos y los guarda en un registro inmutable. Hoja de ruta en [ROADMAP.md](ROADMAP.md).

## Requisitos

Go 1.23 o superior, Docker con Compose y `psql`.

## Desarrollo local

```sh
cp .env.example .env              # reemplazar cada change-me
docker compose up -d --wait db    # Postgres; crea los roles aud_owner y aud_app
docker compose run --rm migrate up
go run ./cmd/api
curl localhost:8080/health        # {"status":"ok"}
```

`migrate` corre `golang-migrate` dentro de un contenedor como `aud_owner`; acepta cualquier subcomando (`down 1`, `version`…).

## Pruebas

```sh
go test -race ./...
golangci-lint run
```

## Estructura

```
cmd/api/                    arranque: config, servidor HTTP, apagado ordenado
internal/audit/domain/      modelo del evento e invariantes, sin dependencias
internal/audit/application/ casos de uso
internal/audit/ports/       interfaces que necesita la aplicación
internal/audit/adapters/    httpapi, postgres, queue
internal/config/            configuración desde variables de entorno
migrations/                 esquema (golang-migrate)
deploy/initdb/              creación de roles al iniciar la BD
```

## Inmutabilidad de `audit_logs`

1. **Permisos:** `aud_app`, el rol de la aplicación, solo tiene `INSERT` y `SELECT`.
2. **Trigger:** rechaza `UPDATE`, `DELETE` y `TRUNCATE` incluso para el dueño.
3. **Cadena de hashes:** cada fila guarda `hash = SHA256(prev_hash || evento)`; `UNIQUE (prev_hash)` impide bifurcarla.
