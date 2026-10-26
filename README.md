# MediNet-Core · Módulo 11 AUD

Auditoría y trazabilidad de seguridad: recibe los eventos de los demás módulos y los guarda en un registro inmutable. Hoja de ruta en [ROADMAP.md](ROADMAP.md). Los módulos que envían eventos deben seguir el [contrato de ingesta](docs/CONTRATO_INGESTA.md).

## Requisitos

Go 1.23 o superior, Docker con Compose y `psql`.

## Desarrollo local

```sh
cp .env.example .env              # reemplazar cada change-me
docker compose up -d --wait db    # Postgres; crea los roles aud_owner y aud_app
docker compose run --rm migrate up
export DATABASE_URL="postgres://aud_app:<AUD_APP_PASSWORD>@localhost:<DB_PORT>/<POSTGRES_DB>?sslmode=disable"
export AUD_SECRET_KEY=...         # ver "Clientes de ingesta"
go run ./cmd/api
curl localhost:8080/health        # {"status":"ok"}
```

Variables de la API: `DATABASE_URL` (obligatoria, rol `aud_app`), `AUD_SECRET_KEY` (obligatoria, base64 de 32 bytes), `HTTP_ADDR` (`:8080`), `LOG_LEVEL` (`info`) y `QUEUE_CAPACITY` (`1024` envíos en espera).

## Ingesta

`POST /api/v1/events` y `POST /api/v1/events/batch`, firmados con HMAC, según el [contrato](docs/CONTRATO_INGESTA.md). La API valida, responde `202` y encola; un único writer guarda los eventos en orden dentro de la cadena de hashes. Si la base de datos se cae, el writer reintenta y la cola se llena: los emisores reciben `503` con `Retry-After` en vez de perder eventos. Al apagarse (`SIGTERM`) deja de aceptar peticiones y vacía la cola antes de salir.

`migrate` corre `golang-migrate` dentro de un contenedor como `aud_owner`; acepta cualquier subcomando (`down 1`, `version`…).

Los roles se crean **solo en el primer arranque**, con el volumen vacío. Si después cambian una contraseña en `.env`, no se aplica sola: hay que hacer `ALTER ROLE … PASSWORD …` como `postgres`, o, en desarrollo, borrar el volumen con `docker compose down -v`.

## Consulta

Solo para roles `auditor` o `admin`, con `Authorization: Bearer <jwt>` (ver "Tokens de consulta"). Sin token o con uno inválido responde `401`; con un token válido sin el rol, `403`.

- `GET /api/v1/events/{event_id}`: un evento, con su posición (`id`) y sus hashes. `404` si no existe y `400` si el id no es un UUID.

## Clientes de ingesta

Cada módulo emisor necesita un `client_id` y un secreto. Se crean con `audctl`, que se conecta como `aud_owner` (nunca lo usa la API):

```sh
export AUD_SECRET_KEY=$(openssl rand -base64 32)   # una sola vez; va en el .env y no se cambia
export AUD_ADMIN_DATABASE_URL="postgres://aud_owner:<pass>@localhost:<DB_PORT>/<POSTGRES_DB>?sslmode=disable"
go run ./cmd/audctl client create lab-service LAB   # imprime el secreto UNA vez
go run ./cmd/audctl client disable lab-service
```

El secreto se guarda cifrado con AES-256-GCM (`api_clients.secret_enc`), ligado a su `client_id`. Si se pierde `AUD_SECRET_KEY`, hay que emitir clientes nuevos.

## Tokens de consulta (stub de IAM)

La API de consulta exige un JWT `Bearer` firmado con RS256 y con el claim `roles` (`auditor` o `admin`). Mientras IAM no emita tokens reales, `audctl` hace de emisor local:

```sh
go run ./cmd/audctl jwt keygen ./secrets      # crea ./secrets con jwt-private.pem (600) y jwt-public.pem; nunca sobrescribe
export AUD_JWT_PUBLIC_KEY_FILE=./secrets/jwt-public.pem
go run ./cmd/audctl jwt mint -key ./secrets/jwt-private.pem -sub ana -roles auditor -ttl 1h
```

Variables: `AUD_JWT_PUBLIC_KEY_FILE` (sin ella, la API de consulta queda deshabilitada), `AUD_JWT_ISSUER` y `AUD_JWT_AUDIENCE` (opcionales; si se definen, el token debe traer ese `iss` y ese `aud`, y `jwt mint` los usa por defecto). El token debe traer `sub` y `exp`; se aceptan 30 s de desfase de reloj.

## Pruebas

```sh
go test -race ./...         # los tests de integración levantan Postgres con Docker (testcontainers)
go test -short ./...        # solo tests unitarios
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
