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
- [ ] **0.3 Herramientas.** Instalar Go 1.23 o superior, Docker con Compose, `golangci-lint`, `migrate` (golang-migrate) y `psql`.
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

- [ ] **3.1 Dominio.** Crear la entidad `Event` con su constructor validado (whitelist de `source_module` y `event_type`, rango de severidad, `occurred_at` no futuro más allá de una tolerancia y tamaño de `payload`).
  _Listo cuando:_ hay tests unitarios por cada regla, con casos válidos e inválidos.
- [ ] **3.2 Cadena de hashes.** Implementar `hash = SHA256(prev_hash || serialización canónica del evento)`.
  _Listo cuando:_ un test demuestra que cambiar cualquier campo cambia el hash.
- [ ] **3.3 Repositorio Postgres.** Usar `pgx/v5` con consultas parametrizadas. La inserción toma el último hash y escribe dentro de una transacción con `pg_advisory_xact_lock`. Si el `event_id` ya existe, no se inserta y la cadena no avanza.
  _Listo cuando:_ hay un test de integración (testcontainers-go o Postgres de CI) que inserta N eventos y la cadena es válida.
- [ ] **3.4 Middleware HMAC.** Hacer la verificación con `hmac.Equal` (comparación en tiempo constante), la ventana anti-replay y `http.MaxBytesReader`.
  _Listo cuando:_ hay tests de firma válida, firma inválida, timestamp viejo y body alterado.
- [ ] **3.5 Cola asíncrona.** Usar un canal con buffer más un único writer, que mantiene el orden de la cadena. `POST /events` responde 202, `POST /events/batch` acepta hasta 100 eventos, y el *graceful shutdown* vacía la cola antes de salir. Si la cola está llena, se responde 503.
  _Listo cuando:_ al enviar 1.000 eventos, los 1.000 quedan en la BD, ordenados y con la cadena válida.

## Etapa 4: Consulta y Swagger

- [ ] **4.1 Middleware JWT.** Validar firma, `exp` y roles (`auditor` y `admin`). Mientras IAM no esté listo, usar un *issuer stub* local.
  _Listo cuando:_ hay tests de token válido, expirado, con firma incorrecta y sin rol.
- [ ] **4.2 `GET /events`.** Filtros `event_type`, `severity`, `from`, `to`, `actor_id` y `source_module`; paginación keyset con cursor `(occurred_at, id)`; `limit` máximo de 100; `from <= to` y un rango máximo de días.
  _Listo cuando:_ los tests cubren cada filtro, la combinación de filtros y los parámetros maliciosos (`' OR 1=1--`, fechas inválidas), todos con respuesta 400 o un resultado correcto, nunca 500.
- [ ] **4.3 `GET /events/{id}`.** Devuelve 404 si no existe y 400 si el id no es válido.
- [ ] **4.4 `GET /stats/suspicious`.** Devuelve logins fallidos por hora, accesos denegados por actor y top IPs por eventos HIGH o CRITICAL dentro de un rango.
  _Listo cuando:_ con datos de prueba, los números cuadran con un `SELECT` hecho a mano.
- [ ] **4.5 `GET /integrity/verify`.** Solo para `admin`. Recorre la cadena en un rango y devuelve `ok` o el primer id donde se rompe.
- [ ] **4.6 Swagger completo** (huma v2 en `/docs`): cada endpoint con descripción, parámetros, esquemas, ejemplos, **todos** los códigos de respuesta y los *security schemes* (HMAC y Bearer). Los errores van en formato RFC 7807.
  _Listo cuando:_ alguien de otro grupo puede usar la API solo con `/docs`.

## Etapa 5: Contenedores, CI/CD y AWS

- [ ] **5.1 Dockerfile.** Multi-stage: compilar en `golang:1.23-alpine` con `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`, y correr en `alpine` con un usuario `app` (uid 10001) y `USER app`. Agregar `HEALTHCHECK` y `.dockerignore`.
  _Listo cuando:_ `docker run … id` muestra uid 10001 y la imagen pesa menos de 30 MB.
- [ ] **5.2 Compose endurecido.** Separar las redes: `backend` y `db` en una red `internal: true`, con la BD **sin** puertos publicados. Usar un volumen nombrado para la BD. En la API: `read_only: true`, `cap_drop: [ALL]` y `security_opt: [no-new-privileges:true]`. Toda la config sale del `.env`.
  _Listo cuando:_ `docker compose up` deja todo sano y `grep` no encuentra credenciales en el repo.
- [ ] **5.3 Seguridad en CI.** Agregar `gosec` (SAST), `govulncheck` (SCA) y `trivy image`, de modo que el pipeline falle ante hallazgos HIGH o CRITICAL.
  _Listo cuando:_ una dependencia vulnerable introducida a propósito hace fallar el pipeline. Después hay que revertirla.
- [ ] **5.4 Build y push.** Publicar la imagen en GHCR (o ECR) con el tag `${{ github.sha }}`, más `latest` en `main`.
- [ ] **5.5 EC2.** Crear una instancia t3.micro con Docker instalado. Security Group: 80/443 (o solo el puerto de la API) abiertos al mundo, 22 **solo** desde las IPs del grupo, y 5432 **nunca** abierto. El `.env` queda en el servidor con permisos `600`.
  _Listo cuando:_ `nmap` desde fuera muestra solo los puertos permitidos.
- [ ] **5.6 CD.** Un job en `main` hace SSH a EC2, ejecuta `docker compose pull && docker compose up -d`, aplica las migraciones y hace un health check que **falla el job** si no responde 200. Las credenciales SSH van en los *GitHub Secrets*.
  _Listo cuando:_ un commit en `main` aparece desplegado en EC2 con el tag del SHA, sin que nadie toque el servidor.

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

## Decisiones pendientes

| Tema | Con quién | Estado |
|---|---|---|
| Fecha de entrega | Profesor | Pendiente |
| Formato del JWT y claim de roles | Grupo 2 (IAM) | Pendiente |
| Dominio con TLS (Caddy) o solo IP pública | Grupo | Pendiente |
| Respuesta ante `event_id` repetido: `409` o `202` idempotente | Grupo | Decidido: `202` idempotente (ver `docs/CONTRATO_INGESTA.md`) |
