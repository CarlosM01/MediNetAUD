# Contrato de ingesta de eventos — AUD (Módulo 11)

Todos los módulos de MediNet-Core envían sus eventos de seguridad a AUD con `POST /api/v1/events`. Cada petición va firmada con HMAC-SHA256 usando un secreto propio de cada módulo. AUD valida el evento, lo encola y responde `202 Accepted`. Después lo guarda en un registro inmutable, encadenado por hashes.

- **Versión del contrato:** 1.0 (2026-10-25)
- **Especificación máquina:** [`openapi-ingesta.yaml`](openapi-ingesta.yaml) (OpenAPI 3.1)
- **Contacto:** Grupo 1 (Jacob Liguen, Carlos Mac-Iver, Roberto Fuentes)

## Ruta rápida

1. Reciban su `client_id` y su secreto por un canal privado. **Nunca** los suban a un repositorio: van en el `.env` de su servicio.
2. Armen el evento en JSON ([§1](#1-esquema-del-evento)) con un `event_type` del catálogo ([§2](#2-catálogo-de-eventos)).
3. Fírmenlo ([§3](#3-firma-hmac)): `HMAC-SHA256(secreto, timestamp + "." + body)`.
4. Envíenlo y traten la respuesta según [§4](#4-respuestas). `202` significa que AUD lo recibió.

```bash
BODY='{"event_id":"0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f","source_module":"IAM","event_type":"auth.login_failed","severity":"LOW","actor_id":"user-1042","actor_type":"user","source_ip":"203.0.113.24","occurred_at":"2026-10-25T14:03:11Z","payload":{"reason":"invalid_password","attempt":3}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac "$AUD_SECRET" -hex | awk '{print $2}')

curl -i https://<host-aud>/api/v1/events \
  -H 'Content-Type: application/json' \
  -H "X-AUD-Client-Id: $AUD_CLIENT_ID" \
  -H "X-AUD-Timestamp: $TS" \
  -H "X-AUD-Signature: sha256=$SIG" \
  --data-raw "$BODY"
```

> **URL base:** se publicará cuando el servicio esté desplegado en AWS. En desarrollo local es `http://localhost:8080`.

---

## 1. Esquema del evento

El body es un objeto JSON en UTF-8 con `Content-Type: application/json`. Los campos desconocidos se rechazan con `400`, para detectar errores de tipeo a tiempo.

| Campo | Tipo | Obligatorio | Reglas |
|---|---|---|---|
| `event_id` | string (UUID) | Sí | UUID en formato canónico (`8-4-4-4-12`, hex en minúsculas). Lo genera el emisor (se recomienda v7 o v4). Es la clave de idempotencia: si reintentan, usen el **mismo** `event_id`. |
| `source_module` | string | Sí | Código de su módulo: `IAM`, `PAC`, `MED`, `AGT`, `HCE`, `PAB`, `LAB`, `FAR`, `TRG`, `FAC`, `AUD` o `TEL`. Debe coincidir con el módulo de su `client_id`; si no, `403`. |
| `event_type` | string | Sí | Uno del [catálogo](#2-catálogo-de-eventos). Máximo 64 caracteres. |
| `severity` | string | Sí | `INFO`, `LOW`, `MEDIUM`, `HIGH` o `CRITICAL` (en mayúsculas). Ver [criterio](#criterio-de-severidad). |
| `occurred_at` | string | Sí | Momento en que ocurrió el hecho, en RFC 3339 con zona horaria (`2026-10-25T14:03:11Z` o `2026-10-25T11:03:11-03:00`). No puede estar más de 5 minutos en el futuro respecto del reloj de AUD. |
| `actor_id` | string | No | Quién hizo la acción: el id interno del usuario o del servicio. Máximo 128 caracteres. Si se informa, `actor_type` es obligatorio. |
| `actor_type` | string | Condicional | `user`, `service` o `anonymous`. |
| `target_resource` | string | No | Recurso afectado, con la forma `<tipo>/<id>` (ej. `patient/8812`, `lab_result/77`). Máximo 256 caracteres. |
| `source_ip` | string | No | IPv4 o IPv6 del **usuario final** que originó la acción, no la de su servidor. |
| `user_agent` | string | No | User-Agent del usuario final. Máximo 512 caracteres. |
| `payload` | objeto | No | Detalle propio del evento. Debe ser un objeto JSON (no un arreglo ni un valor suelto). Máximo 16 KiB serializado. Si no se envía, se guarda `{}`. |

### Límites

| Límite | Valor | Si se excede |
|---|---|---|
| Body de `POST /events` | 64 KiB (65 536 bytes) | `413` |
| `payload` serializado | 16 KiB (16 384 bytes) | `400` |
| Eventos por lote en `POST /events/batch` | 100 | `400` |
| Body de `POST /events/batch` | 1 MiB (1 048 576 bytes) | `413` |

### Datos que NO van en un evento

Los registros de AUD son inmutables: lo que entra no se puede borrar. Por eso:

- **Nunca** envíen contraseñas, tokens, secretos, números de tarjeta ni el contenido de una ficha clínica (diagnósticos, notas, resultados).
- Identifiquen a las personas por su id interno (`actor_id`, `target_resource`), no por RUN, nombre ni correo.
- En `payload` va el **contexto** del hecho (motivo, contador de intentos, rol anterior y nuevo), no los datos del paciente.

## 2. Catálogo de eventos

El `event_type` tiene la forma `<dominio>.<acción>` en minúsculas (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`). Solo se aceptan los de esta tabla; cualquier otro recibe `400`.

¿Necesitan uno nuevo? Pídanlo al Grupo 1 con el nombre, cuándo se emite y la severidad sugerida. Lo agregamos a este documento y al servicio antes de que lo empiecen a enviar.

### Autenticación e identidades

| `event_type` | Cuándo emitirlo | Severidad sugerida | Emisor típico |
|---|---|---|---|
| `auth.login_succeeded` | Inicio de sesión correcto. | `INFO` | IAM |
| `auth.login_failed` | Inicio de sesión rechazado (credenciales inválidas, usuario inexistente). | `LOW` | IAM |
| `auth.account_locked` | Cuenta bloqueada por intentos fallidos. | `HIGH` | IAM |
| `auth.logout` | Cierre de sesión. | `INFO` | IAM |
| `auth.password_changed` | Cambio o restablecimiento de contraseña. | `MEDIUM` | IAM |
| `auth.token_rejected` | Se presentó un JWT inválido, expirado o manipulado. | `MEDIUM` | Todos |
| `iam.user_created` | Alta de un usuario. | `INFO` | IAM, MED |
| `iam.user_disabled` | Baja o suspensión de un usuario. | `MEDIUM` | IAM, MED |
| `iam.role_changed` | Se asignó o quitó un rol. | `HIGH` | IAM |
| `iam.permission_changed` | Cambió la matriz de permisos de un rol. | `HIGH` | IAM |

### Acceso y datos

| `event_type` | Cuándo emitirlo | Severidad sugerida | Emisor típico |
|---|---|---|---|
| `access.denied` | Se negó una acción por falta de permisos (`403`). | `MEDIUM` | Todos |
| `access.idor_attempt` | Alguien intentó acceder a un recurso de otra persona cambiando un id. | `HIGH` | HCE, TEL, LAB, PAC |
| `data.sensitive_read` | Lectura de un registro sensible (ficha clínica, receta, resultado). | `INFO` | HCE, LAB, TEL |
| `data.record_created` | Se creó un registro sensible. | `INFO` | Todos |
| `data.record_updated` | Se modificó un registro sensible. | `INFO` | Todos |
| `data.record_deleted` | Se eliminó o anuló un registro sensible. | `MEDIUM` | Todos |
| `data.export` | Exportación o descarga masiva de datos. | `MEDIUM` | Todos |

### Integridad y defensa

| `event_type` | Cuándo emitirlo | Severidad sugerida | Emisor típico |
|---|---|---|---|
| `input.rejected` | Se rechazó una entrada sospechosa (patrones de SQLi o XSS, formato manipulado). | `MEDIUM` | Todos |
| `file.upload_rejected` | Se rechazó un archivo (extensión o MIME no permitidos, ejecutable disfrazado). | `HIGH` | LAB |
| `business.rule_violation` | Se bloqueó una operación que rompía una regla crítica: stock negativo, precio manipulado desde el cliente, doble reserva de un bloque, triage fuera de rango. | `HIGH` | FAR, FAC, AGT, PAB, TRG |
| `security.rate_limited` | Un cliente superó el rate limit. | `LOW` | Todos |
| `security.config_changed` | Cambió una configuración de seguridad (política de contraseñas, tiempos de sesión). | `HIGH` | IAM |

### Criterio de severidad

La severidad sugerida es el punto de partida. Súbanla si el contexto lo amerita (ej. un `access.denied` sobre una ficha clínica que se repite 20 veces en un minuto).

| Severidad | Úsenla cuando… | Ejemplo |
|---|---|---|
| `INFO` | La operación fue legítima y exitosa; se registra para trazabilidad. | Un médico abre una ficha que le corresponde. |
| `LOW` | Hubo un fallo aislado y esperable, sin indicio de ataque. | Una contraseña mal escrita una vez. |
| `MEDIUM` | Hubo un rechazo que podría ser un intento indebido, o un cambio que conviene revisar. | Acceso denegado a un recurso; exportación de datos. |
| `HIGH` | Hay un indicio concreto de ataque, o cambió un privilegio. | Cuenta bloqueada por fuerza bruta; cambio de rol; archivo malicioso. |
| `CRITICAL` | Hay un compromiso probable que exige acción inmediata. | Escalamiento a administrador sin autorización; exportación masiva no autorizada. |

## 3. Firma HMAC

Cada petición lleva tres headers:

| Header | Valor |
|---|---|
| `X-AUD-Client-Id` | Su `client_id` (ej. `lab-service`). |
| `X-AUD-Timestamp` | Hora actual en segundos Unix, como entero decimal (ej. `1792936991`). |
| `X-AUD-Signature` | `sha256=` seguido de 64 caracteres hex en minúsculas. |

La firma se calcula así:

```
mensaje = X-AUD-Timestamp + "." + body
firma   = hex( HMAC-SHA256( secreto, mensaje ) )
```

Tres detalles que causan la mayoría de los errores:

1. **Firmen los bytes exactos que envían.** Si serializan el JSON una vez para firmar y otra vez para enviar, el orden de las claves o los espacios pueden cambiar y la firma no coincide. Serialicen una vez y usen ese mismo string para ambas cosas.
2. **El secreto se usa tal cual, como texto.** No lo decodifiquen desde hex ni base64.
3. **La ventana es de ±5 minutos.** Si `X-AUD-Timestamp` se aleja más de 300 segundos del reloj de AUD, la petición se rechaza con `401`. Mantengan el reloj sincronizado (NTP) y generen el timestamp justo antes de enviar.

AUD no indica qué parte falló (cliente, timestamp o firma): todas responden `401` con el mismo mensaje. Así no se le entrega información a un atacante.

### Vector de prueba

Usen estos valores para verificar su implementación antes de conectarse:

| Dato | Valor |
|---|---|
| Secreto | `ejemplo-secreto-no-usar-en-produccion` |
| `X-AUD-Timestamp` | `1792936991` |
| Body (282 bytes, sin salto de línea final) | `{"event_id":"0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f","source_module":"IAM","event_type":"auth.login_failed","severity":"LOW","actor_id":"user-1042","actor_type":"user","source_ip":"203.0.113.24","occurred_at":"2026-10-25T14:03:11Z","payload":{"reason":"invalid_password","attempt":3}}` |
| `X-AUD-Signature` esperado | `sha256=8bfc6b22344c1172da861ecd04ba336baff71b9b5a342e87a3df55f07ea5f5c8` |

### Snippets de firma

**Python 3**

```python
import hashlib, hmac, json, os, time, urllib.request, uuid

def send_event(event: dict) -> int:
    body = json.dumps(event, separators=(",", ":")).encode("utf-8")
    ts = str(int(time.time()))
    sig = hmac.new(os.environ["AUD_SECRET"].encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        os.environ["AUD_URL"] + "/api/v1/events",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-AUD-Client-Id": os.environ["AUD_CLIENT_ID"],
            "X-AUD-Timestamp": ts,
            "X-AUD-Signature": "sha256=" + sig,
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status
```

**Node.js (18 o superior)**

```js
import { createHmac } from "node:crypto";

export async function sendEvent(event) {
  const body = JSON.stringify(event);
  const ts = Math.floor(Date.now() / 1000).toString();
  const sig = createHmac("sha256", process.env.AUD_SECRET).update(`${ts}.${body}`).digest("hex");
  const res = await fetch(`${process.env.AUD_URL}/api/v1/events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-AUD-Client-Id": process.env.AUD_CLIENT_ID,
      "X-AUD-Timestamp": ts,
      "X-AUD-Signature": `sha256=${sig}`,
    },
    body,
    signal: AbortSignal.timeout(5000),
  });
  return res.status;
}
```

## 4. Respuestas

Los errores usan el formato RFC 7807 (`Content-Type: application/problem+json`):

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "event validation failed",
  "errors": [
    { "field": "severity", "message": "must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL" }
  ]
}
```

| Código | Significado | ¿Reintentar? |
|---|---|---|
| `202 Accepted` | El evento quedó encolado. También se responde `202` si el `event_id` ya se había recibido: el duplicado se descarta sin error (ver [Idempotencia](#idempotencia)). | No |
| `400 Bad Request` | JSON mal formado, campo faltante o inválido, `event_type` fuera del catálogo, `payload` sobre 16 KiB o lote vacío o de más de 100 eventos. `errors` indica qué campo falló. | No: corrijan el evento. |
| `401 Unauthorized` | Falta un header, el `client_id` no existe o está inactivo, la firma no coincide o el timestamp está fuera de la ventana. | Solo si fue el reloj: sincronícenlo y vuelvan a firmar. |
| `403 Forbidden` | `source_module` no corresponde al módulo de su `client_id`. | No |
| `413 Content Too Large` | El body supera 64 KiB (o 1 MiB en un lote). | No |
| `415 Unsupported Media Type` | El `Content-Type` no es `application/json`. | No |
| `429 Too Many Requests` | Superaron el rate limit de su cliente. Esperen lo que indica el header `Retry-After` (segundos). | Sí, después de `Retry-After`. |
| `503 Service Unavailable` | La cola interna está llena o el servicio se está apagando. Respeten `Retry-After`. | Sí, con backoff. |
| `500 Internal Server Error` | Error inesperado de AUD. | Sí, con backoff. |

Cuerpo de un `202` en `POST /events`:

```json
{ "status": "accepted", "event_id": "0192f3a4-7b1c-7d2e-9f10-3a4b5c6d7e8f" }
```

> `202` significa "recibido y encolado", no "ya está en la base de datos". El evento aparece en las consultas unos instantes después.

### Idempotencia

`event_id` identifica al evento para siempre. Si AUD recibe dos veces el mismo `event_id`, guarda solo el primero y responde `202` a ambos. Por eso:

- Generen el `event_id` **una vez**, al crear el evento, y guárdenlo junto a él hasta recibir el `202`.
- Si reintentan, reenvíen el mismo evento con el mismo `event_id`, pero con un **timestamp y una firma nuevos**: la firma anterior puede haber quedado fuera de la ventana de 5 minutos.
- Reenviar el mismo `event_id` con otro contenido no cambia nada: se conserva el primero.

### Reintentos recomendados

Reintenten ante `429`, `503`, `500` y errores de red (timeout, conexión rechazada), con backoff exponencial: 1 s, 2 s, 4 s… hasta 5 intentos. Si hay `Retry-After`, úsenlo en vez del backoff. No reintenten los demás códigos.

Enviar a AUD no debe bloquear su flujo principal: un login no debería fallar porque AUD esté caído. Envíen en segundo plano y, si se agotan los intentos, registren el evento en sus propios logs.

## 5. Envío por lote

`POST /api/v1/events/batch` recibe hasta 100 eventos en un arreglo `events`. Se firma igual que un evento individual, sobre el body completo.

```json
{
  "events": [
    { "event_id": "…", "source_module": "LAB", "event_type": "data.sensitive_read", "severity": "INFO", "occurred_at": "2026-10-25T14:03:11Z" },
    { "event_id": "…", "source_module": "LAB", "event_type": "file.upload_rejected", "severity": "HIGH", "occurred_at": "2026-10-25T14:03:12Z" }
  ]
}
```

- **Todo o nada:** si un evento es inválido, se rechaza el lote completo con `400` y no se encola ninguno. `errors[].field` indica la posición, por ejemplo `events[1].severity`.
- Los `event_id` repetidos (dentro del lote o con eventos anteriores) se descartan sin error, igual que en `POST /events`.
- Respuesta `202`:

```json
{ "status": "accepted", "count": 2 }
```

## 6. Alta de clientes

Cada grupo recibe un `client_id` y un secreto por un canal privado (nunca por un chat grupal, un issue ni un correo con copia a otros grupos). AUD guarda el secreto cifrado con AES-256-GCM.

Si el secreto se filtra, avisen al Grupo 1: desactivamos ese cliente y emitimos uno nuevo.

## Historial de cambios

| Versión | Fecha | Cambio |
|---|---|---|
| 1.0 | 2026-10-25 | Versión inicial. |
