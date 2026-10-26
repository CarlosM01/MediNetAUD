# Despliegue en AWS EC2

Esta guía deja la API y la BD corriendo en una EC2 t3.micro, y deja configurado que cada push a `main` se despliegue solo con el tag del commit (job `deploy` de [`ci.yml`](../.github/workflows/ci.yml)). Los pasos 1 a 5 se hacen **una sola vez**. El job queda inactivo hasta que exista la variable `EC2_HOST`.

## Ruta rápida

1. Crear la llave de despliegue y el Security Group.
2. Lanzar la instancia con [`deploy/ec2/user-data.sh`](../deploy/ec2/user-data.sh).
3. Dejar el `.env` y la clave pública del JWT en el servidor.
4. Cargar las variables y los secretos en GitHub.
5. Hacer push a `main` y comprobar con `nmap` y `curl`.

## 1. Llave y Security Group

```sh
ssh-keygen -t ed25519 -f ~/.ssh/aud-deploy -C aud-deploy -N ''   # la usa el CD; no sale de GitHub Secrets
```

En la consola de EC2, importen `~/.ssh/aud-deploy.pub` como *key pair* (cada integrante puede sumar su propia llave después en `~/.ssh/authorized_keys`).

Security Group `aud-sg`, solo con estas reglas de entrada:

| Puerto | Origen | Para qué |
|--------|--------|----------|
| `8080/tcp` (o el `API_PORT` elegido) | `0.0.0.0/0` | La API |
| `22/tcp` | La IP de cada integrante, como `/32` | Administración |
| `5432` | **Ninguno** | La BD no publica puertos ni en Docker |

El CD agrega por un momento la IP de su runner al puerto 22 y la quita al terminar (las reglas se llaman `ci-deploy-<run_id>`). Si un job muere a la mitad, borren a mano las reglas `ci-deploy-*` que hayan quedado.

## 2. Instancia

- **AMI:** Ubuntu Server 24.04 LTS. **Tipo:** t3.micro. **Disco:** 20 GB gp3.
- **Red:** el Security Group `aud-sg` y el *key pair* del paso 1.
- **User data:** el contenido de `deploy/ec2/user-data.sh` (instala Docker con Compose y crea 1 GB de swap).
- **Elastic IP:** asígnenle una, porque el CD y `known_hosts` dependen de que la IP no cambie.

## 3. Servidor

```sh
ssh -i ~/.ssh/aud-deploy ubuntu@<IP>
mkdir -p ~/aud/secrets && chmod 700 ~/aud
```

Desde su máquina, copien el `.env` de producción y la clave pública del JWT:

```sh
scp -i ~/.ssh/aud-deploy .env.prod ubuntu@<IP>:aud/.env
scp -i ~/.ssh/aud-deploy secrets/jwt-public.pem ubuntu@<IP>:aud/secrets/
ssh -i ~/.ssh/aud-deploy ubuntu@<IP> 'chmod 600 ~/aud/.env'
```

El `.env` de producción lleva las mismas variables que `.env.example`, con valores propios (`openssl rand -hex 24` para las contraseñas y `openssl rand -base64 32` para `AUD_SECRET_KEY`), y además:

```sh
AUD_IMAGE=ghcr.io/<owner-en-minúsculas>/<repo-en-minúsculas>
AUD_TAG=latest          # tras cada despliegue exitoso, el CD escribe aquí el SHA desplegado
API_PORT=8080
```

No lleven `COMPOSE_FILE` al servidor: `docker-compose.dev.yml` es solo para desarrollo.

## 4. GitHub

En *Settings → Secrets and variables → Actions*:

| Tipo | Nombre | Valor |
|------|--------|-------|
| Variable | `EC2_HOST` | La Elastic IP |
| Variable | `EC2_USER` | `ubuntu` |
| Variable | `API_PORT` | `8080` |
| Variable | `AWS_REGION` | Ej. `us-east-1` |
| Variable | `EC2_SECURITY_GROUP_ID` | El id de `aud-sg` (`sg-…`) |
| Secreto | `EC2_SSH_KEY` | El contenido de `~/.ssh/aud-deploy` (la privada) |
| Secreto | `EC2_KNOWN_HOSTS` | La salida de `ssh-keyscan -t ed25519 <IP>` |
| Secreto | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Credenciales con permiso solo para el paso del CD |
| Secreto | `AWS_SESSION_TOKEN` | Solo si las credenciales son temporales; si no, se deja sin crear |

Antes de guardar `EC2_KNOWN_HOSTS`, comparen la huella con la que muestra *EC2 → Actions → Monitor → Get system log*. Si no coinciden, la llave no es la de su instancia.

Las credenciales de AWS solo necesitan este permiso:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress"],
      "Resource": "arn:aws:ec2:<región>:<cuenta>:security-group/<sg-id>"
    }
  ]
}
```

En AWS Academy no se pueden crear usuarios IAM. Ahí se usan las credenciales temporales de *AWS Details* (las tres), y hay que actualizarlas en GitHub cada vez que se inicia el laboratorio.

La imagen en GHCR es privada por defecto. El CD inicia sesión con el `GITHUB_TOKEN` del job solo durante el `pull`. Para correr `audctl` a mano en el servidor, hagan `docker login ghcr.io` con un token personal con permiso `read:packages`.

## 5. Primer despliegue y verificación

Un push a `main` corre `lint`, `test`, `security` e `image`, y después `deploy`. El job `deploy` copia `docker-compose.yml`, `deploy/` y `migrations/`, baja la imagen `:<sha>`, aplica las migraciones, reinicia `api` y falla si `/health` no responde 200 o si el contenedor no corre ese SHA.

```sh
curl http://<IP>:8080/health                       # {"status":"ok"}
nmap -Pn -p 22,80,443,5432,8080 <IP>                # desde fuera de la lista del 22: solo 8080 open
ssh -i ~/.ssh/aud-deploy ubuntu@<IP> 'cd ~/aud && docker compose ps'
```

Para crear un cliente de ingesta:

```sh
ssh -i ~/.ssh/aud-deploy ubuntu@<IP>
cd ~/aud && docker compose run --rm audctl client create lab-service LAB
```

## Checklist (5.5 y 5.6)

- [ ] `nmap` desde fuera muestra solo el puerto de la API (y el 22 solo desde las IPs del grupo).
- [ ] `stat -c %a ~/aud/.env` en el servidor imprime `600`.
- [ ] Un commit en `main` termina con el job `deploy` en verde y `docker compose ps` muestra la imagen `:<sha>`.
- [ ] No quedan reglas `ci-deploy-*` en `aud-sg`.
