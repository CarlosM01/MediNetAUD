# Hoja de ruta — Módulo 11: Auditoría y Trazabilidad de Seguridad (AUD)

**Grupo 1:** Jacob Liguen · Carlos Mac-Iver · Roberto Fuentes
**Stack:** Go + PostgreSQL · **Evaluación:** EVA02 (CI3064), 25% de la nota

## Cómo usar esta hoja

- Sigan las etapas en orden. Dentro de una etapa, los pasos también van en orden, salvo que se diga lo contrario.
- Cada paso tiene un **Listo cuando**. Marquen la casilla solo cuando eso se cumpla de verdad: que funcione, no que "esté casi".
- Las Etapas 3, 4 y 5 no dependen entre sí: pueden avanzar en paralelo una vez cerrada la Etapa 2.
- Cada paso termina en un PR pequeño hacia `main`.

### Dependencias entre etapas

```
Etapa 0 ─► Etapa 1 ─► Etapa 2 ─┬─► Etapa 3 ─┐
                               ├─► Etapa 4 ─┼─► Etapa 6 ─► Etapa 8
                               └─► Etapa 5 ─┘
                 Etapa 7 (informe): se arma en paralelo desde la Etapa 3
```

---

## Etapa 0: Preparación

- [ ] **0.1 Fecha de entrega.** Confirmar con el profesor y repartir las etapas en semanas.
  _Listo cuando:_ cada etapa tiene una fecha objetivo escrita en este archivo.
- [ ] **0.2 Repositorio.** Crear el repo en GitHub, proteger `main` (PR obligatorio, 1 aprobación y CI en verde) y acordar Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`…).
  _Listo cuando:_ un push directo a `main` es rechazado.
- [ ] **0.3 Herramientas.** Instalar Go 1.26 o superior, Docker con Compose, `golangci-lint`, `migrate` (golang-migrate) y `psql`.
  _Listo cuando:_ `go version`, `docker compose version` y `migrate -version` responden en todos los equipos de desarrollo.
- [ ] **0.4 Coordinación con IAM (Grupo 2).** Acordar el formato del JWT: algoritmo (ideal RS256), dónde publican la clave pública (JWKS o archivo) y el claim de roles (ej. `roles: ["auditor"]`).
  _Listo cuando:_ el acuerdo queda escrito, aunque sea provisorio.

## Etapa 1: Esqueleto del proyecto

- [x] **1.1 Estructura.** Correr `go mod init` y crear las carpetas `cmd/api`, `internal/audit/{domain,application,ports,adapters/{http,postgres,queue}}` y `migrations`. El `main.go` lee la config desde variables de entorno y expone `GET /health`.
  _Listo cuando:_ `go run ./cmd/api` y `curl localhost:8080/health` devuelven 200.
- [x] **1.2 Postgres local.** Crear un `docker-compose.yml` con el servicio `db`, un `.env.example` versionado y agregar `.env` al `.gitignore`.
  _Listo cuando:_ `docker compose up db` levanta y `psql` conecta usando solo los valores del `.env`.
- [x] **1.3 Primera migración.** Crear la tabla `audit_logs`, con los índices y la cadena de hashes definidos en el plan, y la tabla `api_clients`. Crear también los roles `aud_owner` (dueño, corre migraciones) y `aud_app` (solo `INSERT` y `SELECT`), y el trigger `BEFORE UPDATE OR DELETE` que lanza una excepción.
  _Listo cuando:_ `migrate up` y `migrate down` funcionan, y un `UPDATE` hecho como `aud_app` falla.
- [ ] **1.4 CI mínimo.** Crear `.github/workflows/ci.yml` con `golangci-lint` y `go test ./...` en cada push y PR. Va temprano para que todo lo que venga después ya esté chequeado.
  _Listo cuando:_ un PR muestra el check en verde.

> **Corrección al plan:** `api_clients` **no** puede guardar un *hash* del secreto. Para verificar una firma HMAC, el servidor necesita el secreto original. Hay que guardarlo cifrado (`secret_enc`, con AES-GCM y la llave en el `.env`) o cargarlo desde variables de entorno.

## Etapa 2: Contrato de ingesta (hito crítico, prioridad máxima)

Los otros 11 grupos dependen de esto. Mientras no esté publicado, no pueden integrarse con ustedes.

- [x] **2.1 Esquema del evento.** Definir los campos (`event_id` UUID, `source_module`, `event_type`, `severity`, `actor_id`, `actor_type`, `target_resource`, `source_ip`, `occurred_at` en RFC 3339 y `payload`), cuáles son obligatorios y el tamaño máximo.
- [x] **2.2 Catálogo.** Listar los `event_type` permitidos (ej. `auth.login_failed`, `auth.account_locked`, `access.denied`, `iam.role_changed`, `data.export`…) y las severidades `INFO | LOW | MEDIUM | HIGH | CRITICAL`, con un criterio de cuándo usar cada una.
- [x] **2.3 Firma HMAC.** Especificar los headers:
  - `X-AUD-Client-Id`
  - `X-AUD-Timestamp` (en segundos Unix)
  - `X-AUD-Signature: sha256=<hex>`, donde `<hex>` es `HMAC-SHA256(secreto, timestamp + "." + body_crudo)`

  Las peticiones fuera de una ventana de ±5 min se rechazan.
- [x] **2.4 Respuestas.** Documentar `202 Accepted` (evento encolado), `400` (inválido), `401` (firma o timestamp inválidos), `202` idempotente si el `event_id` está repetido, `413` (demasiado grande) y `429` (rate limit).
- [ ] **2.5 Publicar.** Crear `docs/CONTRATO_INGESTA.md` con un ejemplo en `curl` y un snippet de firma, más el OpenAPI de `POST /events`, y enviarlo a los grupos.
  _Listo cuando:_ los grupos confirmaron que lo recibieron y cada uno tiene su `client_id` y su secreto entregados por un canal privado.
  _Avance:_ [`docs/CONTRATO_INGESTA.md`](docs/CONTRATO_INGESTA.md) y [`docs/openapi-ingesta.yaml`](docs/openapi-ingesta.yaml) listos; falta enviarlos y entregar las credenciales.

## Etapa 3: Ingesta

- [x] **3.1 Dominio.** Crear la entidad `Event` con su constructor validado (whitelist de `source_module` y `event_type`, rango de severidad, `occurred_at` no futuro más allá de una tolerancia y tamaño de `payload`).
  _Listo cuando:_ hay tests unitarios por cada regla, con casos válidos e inválidos.
- [x] **3.2 Cadena de hashes.** Implementar `hash = SHA256(prev_hash || serialización canónica del evento)`.
  _Listo cuando:_ un test demuestra que cambiar cualquier campo cambia el hash.
- [x] **3.3 Repositorio Postgres.** Usar `pgx/v5` con consultas parametrizadas. La inserción toma el último hash y escribe dentro de una transacción con `pg_advisory_xact_lock`. Si el `event_id` ya existe, no se inserta y la cadena no avanza.
  _Listo cuando:_ hay un test de integración (testcontainers-go o Postgres de CI) que inserta N eventos y la cadena es válida.
- [x] **3.4 Middleware HMAC.** Hacer la verificación con `hmac.Equal` (comparación en tiempo constante), la ventana anti-replay y `http.MaxBytesReader`.
  _Listo cuando:_ hay tests de firma válida, firma inválida, timestamp viejo y body alterado.
- [x] **3.5 Cola asíncrona.** Usar un canal con buffer más un único writer, que mantiene el orden de la cadena. `POST /events` responde 202, `POST /events/batch` acepta hasta 100 eventos, y el *graceful shutdown* vacía la cola antes de salir. Si la cola está llena, se responde 503.
  _Listo cuando:_ al enviar 1.000 eventos, los 1.000 quedan en la BD, ordenados y con la cadena válida.

## Etapa 4: Consulta y Swagger

- [x] **4.1 Middleware JWT.** Validar firma, `exp` y roles (`auditor` y `admin`). Mientras IAM no esté listo, usar un *issuer stub* local.
  _Listo cuando:_ hay tests de token válido, expirado, con firma incorrecta y sin rol.
- [x] **4.2 `GET /events`.** Filtros `event_type`, `severity`, `from`, `to`, `actor_id` y `source_module`; paginación keyset con cursor `(occurred_at, id)`; `limit` máximo de 100; `from <= to` y un rango máximo de días.
  _Listo cuando:_ los tests cubren cada filtro, la combinación de filtros y los parámetros maliciosos (`' OR 1=1--`, fechas inválidas), todos con respuesta 400 o un resultado correcto, nunca 500.
- [x] **4.3 `GET /events/{id}`.** Devuelve 404 si no existe y 400 si el id no es válido.
- [x] **4.4 `GET /stats/suspicious`.** Devuelve logins fallidos por hora, accesos denegados por actor y top IPs por eventos HIGH o CRITICAL dentro de un rango.
  _Listo cuando:_ con datos de prueba, los números cuadran con un `SELECT` hecho a mano.
- [x] **4.5 `GET /integrity/verify`.** Solo para `admin`. Recorre la cadena en un rango y devuelve `ok` o el primer id donde se rompe.
- [ ] **4.6 Swagger completo** (huma v2 en `/docs`): cada endpoint con descripción, parámetros, esquemas, ejemplos, **todos** los códigos de respuesta y los *security schemes* (HMAC y Bearer). Los errores van en formato RFC 7807.
  _Listo cuando:_ alguien de otro grupo puede usar la API solo con `/docs`.
  _Avance:_ `/docs` (Swagger UI sobre `/openapi.json`) documenta ingesta, consulta y `/health` con ambos *security schemes*, todos los códigos y un ejemplo en cada parámetro, cuerpo y respuesta (un test lo exige), y pasa el linter de Redocly; falta que alguien de otro grupo lo pruebe.

## Etapa 5: Contenedores, CI/CD y AWS

- [x] **5.1 Dockerfile.** Multi-stage: compilar en `golang:1.26-alpine` con `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`, y correr en `alpine` con un usuario `app` (uid 10001) y `USER app`. Agregar `HEALTHCHECK` y `.dockerignore`.
  _Listo cuando:_ `docker run … id` muestra uid 10001 y la imagen pesa menos de 30 MB.
- [x] **5.2 Compose endurecido.** Separar las redes: `backend` y `db` en una red `internal: true`, con la BD **sin** puertos publicados. Usar un volumen nombrado para la BD. En la API: `read_only: true`, `cap_drop: [ALL]` y `security_opt: [no-new-privileges:true]`. Toda la config sale del `.env`.
  _Listo cuando:_ `docker compose up` deja todo sano y `grep` no encuentra credenciales en el repo.
- [ ] **5.3 Seguridad en CI.** Agregar `gosec` (SAST), `govulncheck` (SCA) y `trivy image`, de modo que el pipeline falle ante hallazgos HIGH o CRITICAL.
  _Listo cuando:_ una dependencia vulnerable introducida a propósito hace fallar el pipeline. Después hay que revertirla.
  _Avance:_ en local, con `pgx` v5.7.5, `govulncheck` y `trivy` fallan y `gosec` falla sin las anotaciones; falta verlo en GitHub Actions.
- [ ] **5.4 Build y push.** Publicar la imagen en GHCR (o ECR) con el tag `${{ github.sha }}`, más `latest` en `main`.
  _Avance:_ job `image` listo (también publica `audctl-<sha>`); falta el primer push a GitHub.
- [ ] **5.5 EC2.** Crear una instancia t3.micro con Docker instalado. Security Group: 80/443 (o solo el puerto de la API) abiertos al mundo, 22 **solo** desde las IPs del grupo, y 5432 **nunca** abierto. El `.env` queda en el servidor con permisos `600`.
  _Listo cuando:_ `nmap` desde fuera muestra solo los puertos permitidos.
  _Avance:_ guía en [docs/DESPLIEGUE.md](docs/DESPLIEGUE.md) y *user data* en `deploy/ec2/user-data.sh`; falta crear la instancia (requiere la cuenta de AWS del grupo).
- [ ] **5.6 CD.** Un job en `main` hace SSH a EC2, ejecuta `docker compose pull && docker compose up -d`, aplica las migraciones y hace un health check que **falla el job** si no responde 200. Las credenciales SSH van en los *GitHub Secrets*.
  _Listo cuando:_ un commit en `main` aparece desplegado en EC2 con el tag del SHA, sin que nadie toque el servidor.
  _Avance:_ job `deploy` listo; se simuló en local contra un registro propio (pull, migraciones, `up --wait`, health check y tag del SHA). Falta la EC2 y los secretos.

## Etapa 6: Endurecimiento y pruebas de seguridad

- [ ] **6.1 Inmutabilidad.** Tests que demuestren que `UPDATE`, `DELETE` y `TRUNCATE` como `aud_app` fallan, y que una alteración hecha como `aud_owner` es detectada por `/integrity/verify`.
- [ ] **6.2 Rechazos.** Tests de HMAC inválido, replay, payload de más de 64 KB, `event_type` fuera del catálogo y JWT manipulado (incluido `alg: none`).
- [ ] **6.3 Defensas transversales.** Rate limit por cliente e IP, timeouts del servidor HTTP (`ReadHeaderTimeout` y otros), errores sin stack traces y logs propios en JSON (`slog`) sin datos sensibles.
- [ ] **6.4 Prueba end-to-end en EC2.** Correr los 8 pasos de "Verificación end-to-end" del plan contra la URL pública.
  _Listo cuando:_ los 8 pasos pasan, con capturas guardadas para el informe.

## Etapa 7: Informe técnico

- [ ] **7.1 Diagramas.** Diagrama ER (`audit_logs`, `api_clients`) y diagrama de arquitectura hexagonal y de despliegue (EC2, contenedores, redes, SG).
- [ ] **7.2 ISO 27034.** Describir el ONF y el ANF del módulo y el nivel de confianza objetivo, y armar una tabla de **ASC** que vincule cada control con su evidencia (ej. "registros inmutables → roles de BD + trigger + hash chain → `migrations/0001…`, test X").
- [ ] **7.3 Ciclo de vida seguro.** Explicar cómo se aplicó la seguridad en cada fase: requisitos, diseño, implementación, verificación (tests y SAST/SCA) y despliegue.
- [ ] **7.4 OWASP Top 10.** Una tabla con riesgo, cómo aplica al módulo, mitigación y evidencia. Destacar A09 (fallas de registro y monitoreo): este módulo ES la mitigación de A09 para todo MediNet-Core.
- [ ] **7.5 Evidencias.** Capturas de `/docs`, del pipeline en verde, del Security Group, de `nmap`, del `UPDATE` rechazado y de la verificación de integridad.

## Etapa 8: Cierre (checklist contra la rúbrica)

- [ ] **Backend y Swagger:** todos los endpoints funcionan, la BD tiene PK, FK e índices, y `/docs` está completo con todos los códigos.
- [ ] **Docker:** multi-stage, alpine, no-root, redes aisladas, volumen y `.env`, con cero secretos en el repo.
- [ ] **AWS:** la API y la BD operan en EC2, con un Security Group mínimo.
- [ ] **CI/CD:** build, test, análisis de seguridad y deploy en verde en cada push.
- [ ] **Informe:** formal, con ISO 27034 vinculado a evidencia concreta y OWASP Top 10.
- [ ] **Ensayo final:** clonar el repo desde cero, seguir el README y que todo levante.

---

## Decisiones de diseño tomadas

Decisiones que el código solo no explica. Antes de "arreglar" algo de esta lista, revisen por qué se hizo así.

### Etapa 1: Esqueleto y base de datos

- Los roles `aud_owner` y `aud_app` se crean en `deploy/initdb/01-roles.sh`, con contraseñas del `.env`. La migración solo otorga permisos. El script corre una sola vez, cuando el volumen está vacío.
- La carpeta `adapters/http` se llama `adapters/httpapi` para no tapar el paquete `net/http`.
- La tabla `source_modules` es el catálogo de módulos. La FK compuesta `(client_id, source_module) -> api_clients` impide que un cliente emita eventos en nombre de otro módulo.
- `UNIQUE(prev_hash)` impide que la cadena se bifurque. Además del trigger de `UPDATE`/`DELETE`, hay uno para `TRUNCATE`.
- `golang-migrate` corre desde el perfil `tools` de Compose; no hace falta instalarlo.
- El path del módulo `github.com/medinetcore/aud` es provisorio hasta que exista el repo en GitHub.

### Etapa 3: Ingesta

- La ingesta usa handlers de `net/http` (sin huma), porque el middleware HMAC necesita el body crudo y los errores siguen el formato del contrato (`errors[{field,message}]`).
- **Serialización canónica:** campos con prefijo de largo en orden fijo (`NULL` distinto de vacío), y `occurred_at`/`received_at` en UTC truncados a microsegundos (la precisión de `timestamptz`).
- **Hash con las formas de Postgres:** el `payload` se hashea como `jsonb::text` y la IP como `host(inet)`, ambos obtenidos dentro de la transacción de inserción. Así `/integrity/verify` puede recalcular el hash desde la fila. Ejemplo: Go imprime `::102:304` y Postgres `::1.2.3.4`; hashear la forma de Go rompía la cadena.
- Antes del 202 el `payload` se re-codifica en Go (llaves ordenadas, números tal cual) y se limita a rango `float64`, profundidad 32, sin `NUL` y sin números de más de 16383 decimales. Así `jsonb` nunca rechaza un evento ya aceptado (`1e-20000` pasaba `ParseFloat` y después fallaba en la BD).
- El secreto de cada cliente se guarda cifrado con AES-256-GCM, con el `client_id` como dato adicional.
- Los errores de la BD de clase SQLSTATE 22/23 descartan ese evento con un log `ERROR`. Cualquier otro error se reintenta sin límite, así que la cola se llena y los emisores reciben 503.
- `golangci-lint` corre con su imagen de Docker (la versión está en `.github/workflows/ci.yml`).

### Etapa 4: Consulta y Swagger

- `huma` corre con `humago` sobre el mismo `ServeMux`. Quedó en v2.35.0, la última compatible con Go 1.23.
- Los errores de huma se convierten al mismo formato RFC 7807 del contrato, y el 422 de huma se responde como 400.
- JWT con `golang-jwt/jwt/v5` v5.3.1 y `WithValidMethods(["RS256"])`, para rechazar `alg: none` y la confusión HS256 con clave pública. Formato provisorio hasta acordarlo con IAM (0.4): clave pública en un archivo PEM, roles en el claim `roles: [...]` y `iss`/`aud` opcionales. Token ausente o inválido → 401; token válido sin el rol → 403.
- El *issuer stub* local es `audctl jwt keygen|mint`.
- `{id}` en `GET /events/{id}` es el `event_id` público (UUID). Las respuestas también traen el `id` interno de secuencia.
- Las rutas de consulta solo se registran si `AUD_JWT_PUBLIC_KEY_FILE` está definido (falla cerrado).
- `GET /events`: el rango por defecto es de 7 días y el máximo de 31.
- `/integrity/verify` recorre un rango de ids dentro de una transacción de solo lectura `REPEATABLE READ`, y enlaza la primera fila con la fila guardada anterior.
- Hay un único OpenAPI 3.1 en `/openapi.json` y `/openapi.yaml`: junta las operaciones de huma con `docs/openapi-ingesta.yaml`, que es la fuente de la ingesta. Swagger UI 5.17.14 se sirve en `/docs` con SRI.

### Etapa 5: Contenedores, CI/CD y AWS

- **Go 1.26 en vez de 1.23.** Go 1.23 dejó de recibir parches en agosto de 2025, y `govulncheck` encontró 13 vulnerabilidades alcanzables (entre ellas GO-2026-5004, una inyección SQL en `pgx`). Las versiones corregidas de `pgx` y `golang.org/x/*` exigen Go 1.26. Con 1.23, el escaneo de 5.3 no podía quedar en verde.
- `audctl` va en su propia imagen (`--target audctl`). Con los dos binarios, la imagen pesaba 30,15 MB y superaba los 30 MB de 5.1. Separada, además, la herramienta que usa `aud_owner` no queda dentro del contenedor del servicio.
- La BD no publica puertos en `docker-compose.yml`. Para `go run` en local, `docker-compose.dev.yml` la publica en `127.0.0.1` y se activa con `COMPOSE_FILE` en el `.env` de desarrollo, nunca en el servidor.
- La clave pública del JWT entra como *secret* de Compose. Si falta, `api` no arranca: en el contenedor la API de consulta no queda deshabilitada en silencio.
- **Escáneres en CI:** `gosec -severity high`, `govulncheck` (falla con cualquier vulnerabilidad alcanzable) y `trivy` sobre las dos imágenes (HIGH y CRITICAL, también las que aún no tienen parche). Todos van con versión fija: los de Go por el *checksum database* y `trivy` por *digest*. Se probó con `pgx` v5.7.5 a propósito: `govulncheck` y `trivy` hacen fallar el pipeline.
- Los 9 hallazgos HIGH de `gosec` eran falsos positivos (rutas que elige el operador, conversiones acotadas y credenciales de un contenedor de prueba). Quedan anotados con `#nosec` y el motivo en la misma línea.
- Las *actions* están fijadas por SHA, con la versión en un comentario. No se usan *actions* de terceros para Docker ni para `trivy`: el CLI de Docker alcanza.
- **Imágenes en GHCR:** `ghcr.io/<repo en minúsculas>:<sha>` y `:audctl-<sha>` en cada push; además `:latest` y `:audctl-latest` en `main`. Los PR solo construyen y escanean.
- **SSH del CD:** el 22 solo admite las IPs del grupo, y los runners de GitHub cambian de IP. Por eso el job `deploy` agrega la IP de su runner al Security Group, hace el SSH y la quita al final, aunque el job falle. Las credenciales de AWS solo tienen permiso para eso. La rúbrica no exige SSH; esta forma cumple a la vez 5.5 y 5.6.
- El CD copia solo `docker-compose.yml`, `deploy/` y `migrations/`: el servidor no tiene el código. El token de GHCR viaja por stdin y se borra después del `pull`. La llave del host va fijada en `EC2_KNOWN_HOSTS`, no se acepta la primera que aparezca.

### Pendientes conocidos

- Si la BD se cae, la búsqueda del cliente falla primero y los emisores reciben 500 (reintentable según el contrato), no el 503 que promete el README. Se resuelve en 6.3 con un caché o timeout, o corrigiendo el README.
- La capacidad de la cola cuenta envíos, no eventos. Un error permanente no clasificado bloquea la cola. El apagado comparte un único plazo de 15 s.

## Decisiones pendientes

| Tema | Con quién | Estado |
|---|---|---|
| Fecha de entrega | Profesor | Pendiente |
| Formato del JWT y claim de roles | Grupo 2 (IAM) | Pendiente. Supuesto provisorio: RS256, llave pública en PEM, claims `sub`, `exp` y `roles` (ver README) |
| Dominio con TLS (Caddy) o solo IP pública | Grupo | Pendiente |
| Respuesta ante `event_id` repetido: `409` o `202` idempotente | Grupo | Decidido: `202` idempotente (ver `docs/CONTRATO_INGESTA.md`) |
