# **PAUTA DE EVALUACIÓN 02: Desarrollo Seguro (CI3064)**

**Ponderación:** 25% de la nota semestral.

**Modalidad:** Grupal (según distribución de los 12 módulos de MediNet-Core)

**Objetivo:** Desarrollar el Backend, Base de Datos, documentación de API, conteinerización segura, despliegue operativo en AWS y automatización de CI/CD para el módulo asignado, aplicando el ciclo de vida seguro (ISO 27034).

## ** Detalle de Entregables Obligatorios**

### **1\. Código Fuente del Backend, Base de Datos y Documentación Swagger**

* **Endpoints REST:** Implementación funcional de la lógica de negocio del módulo asignado.  
* **Modelo de Base de Datos Relacional:** Tablas creadas correctamente con llaves primarias, foráneas e índices donde aplique.  
* **Documentación Interactiva (Swagger/OpenAPI):** Endpoints debidamente documentados y accesibles vía interfaz web (ej. /docs o /swagger), especificando parámetros, esquemas de entrada y códigos de respuesta HTTP.  
* **Validación de Entradas:** Sanitización de parámetros para prevenir inyecciones (SQLi, Path Traversal, etc) en el backend.

### **2\. Conteinezación Segura (Docker & Docker Compose)**

* **Dockerfile con Hardening:** Uso de multi-stage builds, imágenes base ligeras (Alpine) y prohibición de ejecución como usuario root (USER nonroot).  
* **docker-compose.yml:** Orquestación de contenedores (Backend \+ Base de Datos) utilizando redes virtuales internas y volúmenes persistentes para la BD. Uso estricto de archivos .env (cero credenciales quemadas en el código).

### **3\. Despliegue en la Nube (AWS)**

* El sistema completo (Backend y Base de Datos) debe estar desplegado y accesible operativamente en una instancia de AWS EC2 (o infraestructura cloud equivalente).  
* Configuración adecuada de grupos de seguridad (Security Groups) en AWS para permitir únicamente el tráfico necesario (ej. puerto del API Gateway o Backend y puertos de administración seguros).

### **4\. Pipeline de CI/CD (GitHub Actions o GitLab CI)**

* Configuración de un archivo de pipeline automatizado en el repositorio.  
* El pipeline debe ejecutar al menos:  
  * **Build:** Construcción automática de la imagen Docker.  
  * **Test:** Ejecución de pruebas unitarias o de integración del backend.  
  * **Security Scan:** Análisis estático de código o dependencias (SAST/SCA) para detectar vulnerabilidades.  
  * **Continous Deployment:** despliegue de cambios de código (imagenes docker con tag) hacia la instancia EC2 de AWS.

### **5\. Informe Técnico (Norma ISO 27034 y Ciclo de Vida Seguro)**

Documento formal que incluya:

* Diagrama y explicación del modelo de datos y la arquitectura del backend.  
* Justificación de cómo se aplicaron los controles de la norma ISO 27034 durante el desarrollo.  
* Análisis de mitigación de riesgos del OWASP Top 10 aplicados al módulo.

## ** Rúbrica de Evaluación 02**

| Criterio / Indicador | Logrado (100%) | Medianamente Logrado (60%) | No Logrado (0%)   |
| :---- | :---- | :---- | :---- |
| **1\. Backend y Swagger (OpenAPI)** | Desarrolla todos los endpoints funcionales del módulo, implementa la BD correctamente y presenta una documentación Swagger impecable y navegable. | La API funciona parcialmente o carece de documentación completa en Swagger; hay errores en códigos de respuesta o parámetros. | El backend no cumple con los endpoints mínimos solicitados o no cuenta con documentación Swagger. |
| **2\. Docker y Contenedorización Segura** | Utiliza Dockerfiles optimizados (multi-stage), evita el usuario root, usa redes aisladas y gestiona secretos mediante variables de entorno en Docker Compose. | Los contenedores levantan, pero tienen malas prácticas de seguridad (ej. corren como root, credenciales expuestas en el Dockerfile o falta de volúmenes). | Los contenedores no están correctamente orquestados, fallan al levantar o no utilizan Docker. |
| **3\. Despliegue Operativo en AWS** | La aplicación (Backend \+ BD) está desplegada, es accesible y opera correctamente en una instancia de AWS EC2 con los Security Groups bien configurados. | El despliegue en AWS presenta problemas de conectividad, los servicios no se comunican correctamente o los Security Groups son inseguros (ej. todo abierto). | No se realizó el despliegue en AWS o la aplicación no se encuentra operativa en la nube. |
| **4\. Pipeline de CI/CD (GitHub Actions / GitLab CI)** | Configura un pipeline automatizado que ejecuta con éxito la compilación, las pruebas unitarias y el análisis de seguridad ante cada git push. | El pipeline está creado pero falla en alguna de sus etapas, o carece de las etapas de pruebas/seguridad automatizada. | No implementa pipeline de CI/CD en el repositorio. |
| **5\. Informe Técnico (ISO 27034 y Seguridad)** | Presenta un informe formal, estructurado, que detalla rigurosamente la aplicación del ciclo de vida seguro (ISO 27034\) y la mitigación de vulnerabilidades del módulo. | El informe es superficial, incompleto o no vincula correctamente los conceptos de la norma ISO 27034 con el desarrollo realizado. | No entrega el informe técnico. |

