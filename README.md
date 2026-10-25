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

Los roles se crean **solo en el primer arranque**, con el volumen vacío. Si después cambian una contraseña en `.env`, no se aplica sola: hay que hacer `ALTER ROLE … PASSWORD …` como `postgres`, o, en desarrollo, borrar el volumen con `docker compose down -v`.

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
2. **Trigger:** rechaza `UPDATE`, `DELETE` y `TRUNCATE` aunque el rol tenga el permiso. El dueño (`aud_owner`) sí puede desactivarlo con `ALTER TABLE`, por eso sus credenciales nunca se usan en tiempo de ejecución.
3. **Cadena de hashes:** cada fila guarda `hash = SHA256(prev_hash || evento)`, así que una alteración hecha por el dueño queda a la vista al verificar la cadena. `UNIQUE (prev_hash)` impide bifurcarla.
