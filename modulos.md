# **Especificación Funcional por Módulo ("MediNet-Core")**

## ---

**1\. Módulo de Autenticación y Gestión de Identidades (IAM)**

* **Frontend:** Vistas de Login con validación de formularios, panel de administración de usuarios, matriz de asignación de roles y permisos, y vista de perfil personal.  
* **Backend & Lógica de Negocio:** Emisión y validación de tokens JWT con tiempos de expiración y Refresh Tokens. Hashing robusto de contraseñas (Bcrypt/Argon2) con políticas estrictas de complejidad (longitud, símbolos, mayúsculas). Control de bloqueo de cuentas tras múltiples intentos fallidos.

***Base de Datos:** Tablas relacionales para users, roles, permissions y user\_sessions.*

## **2\. Módulo de Gestión de Pacientes y Admisión (PAC)**

* **Frontend:** Formulario de registro con validación en tiempo real del RUN chileno (algoritmo Módulo 11), selector de previsión de salud (Fonasa/Isapre/Capredena/Dipreca), y buscador avanzado de pacientes con paginación.  
* **Backend & Lógica de Negocio:** Sanitización estricta de entradas para prevenir inyecciones SQL y XSS. Lógica de normalización de datos demográficos y control de duplicidad por RUN.

***Base de Datos:** Tabla patients con restricciones de unicidad e índices optimizados para búsqueda por RUN y apellidos.*

## **3\. Módulo de Gestión de Personal Clínico y Médicos (MED)**

* **Frontend:** Panel para el registro de profesionales, asignación de especialidades médicas, definición de matriz de turnos semanales y directorio público/interno de médicos.  
* **Backend & Lógica de Negocio:** Validación de formato de registro médico legal. Control de autorización estricta (solo roles con privilegios de administración pueden dar de alta a un médico).

***Base de Datos:** Tablas relacionales doctors, specialties y doctor\_schedules.*

## **4\. Módulo de Agenda y Citaciones (AGT)**

* **Frontend:** Calendario interactivo de reservas con vista por médico y especialidad, selección de bloques horarios disponibles en tiempo real, y panel de cancelación o reprogramación de citas.  
* **Backend & Lógica de Negocio:** Control de concurrencia y prevención de race conditions (evitar que dos pacientes reserven el mismo bloque exacto al mismo tiempo mediante bloqueos a nivel de base de datos o transacciones serializables). Implementación de máquina de estados para la cita (Agendada → Confirmada → En Proceso → Atendida o Cancelada).

***Base de Datos:** Tabla appointments con restricciones de exclusión temporal por médico.*

## **5\. Módulo de Historia Clínica Electrónica (HCE)**

* **Frontend:** Interfaz de línea de tiempo (timeline) del paciente, formulario clínico para el médico (anamnesis, diagnóstico, notas de evolución) y módulo de emisión de recetas médicas asociadas.  
* **Backend & Lógica de Negocio:** Mitigación estricta de vulnerabilidades IDOR (Insecure Direct Object References), asegurando que el médico o paciente solo accedan a registros autorizados mediante validación cruzada de tokens. Cifrado lógico de notas sensibles.

***Base de Datos:** Tablas relacionales medical\_records y prescriptions.*

## **6\. Módulo de Pabellones y Quirófanos (PAB)**

* **Frontend:** Tablero visual en tiempo real (Dashboard) del estado de los quirófanos (Disponible, Ocupado, En Sanitización, En Mantención) y formulario de programación de cirugías electivas o de urgencia.  
* **Backend & Lógica de Negocio:** Validación cruzada de disponibilidad triple (quirófano libre \+ equipo médico sin tope de horario \+ paciente sin otra intervención simultánea). Gestión de estados del procedimiento quirúrgico.

***Base de Datos:** Tablas operating\_rooms y surgeries.*

## **7\. Módulo de Laboratorio Clínico y Exámenes (LAB)**

* **Frontend:** Interfaz para que el médico solicite exámenes, consola para el laboratorista (carga de archivos de resultados) y vista del paciente para visualizar/descargar sus informes.  
* **Backend & Lógica de Negocio:** Seguridad en la subida de archivos: validación estricta en el backend de extensiones y tipos MIME (rechazar ejecutables disfrazados), almacenamiento seguro de archivos en volúmenes persistentes y control de acceso al recurso.

***Base de Datos:** Tablas lab\_orders y lab\_results (con metadatos de archivos).*

## **8\. Farmacia e Insumos (FAR)**

* **Frontend:** Dashboard de control de stock con umbrales visuales de alerta temprana (stock crítico en rojo), buscador de fármacos y panel de registro de despacho por receta médica.  
* **Backend & Lógica de Negocio:** Transacciones ACID estrictas: al despachar un medicamento, la rebaja de inventario en la tabla de stock y la creación del registro de dispensación deben ocurrir en una transacción atómica para prevenir inconsistencias o inventarios negativos por concurrencia.

***Base de Datos:** Tablas inventory y dispensing\_logs.*

## **9\. Módulo de Urgencias y Triage (TRG)**

* **Frontend:** Pantalla de admisión rápida de pacientes de urgencia, formulario de categorización clínica y cola de espera en tiempo real ordenada automáticamente por gravedad (escala C1 a C5) y tiempo de llegada.  
* **Backend & Lógica de Negocio:** Validación de rangos estrictos en la escala de triage en el backend. Lógica de reordenamiento dinámico de la lista de espera según prioridad clínica.

***Base de Datos:** Tabla triage\_queue.*

## **10\. Módulo de Facturación y Convenios (FAC)**

* **Frontend:** Vista de la cuenta de cobro desglosada del paciente, cálculo automatizado de copagos según el sistema de salud (Fonasa/Isapre) y pasarela simulada de pago.  
* **Backend & Lógica de Negocio:** Manejo preciso de cálculos monetarios (evitar errores de punto flotante). Validación cruzada de montos para impedir manipulación de precios desde el cliente web.

***Base de Datos:** Tablas invoices y payments.*

## **11\. Módulo de Auditoría y Trazabilidad de Seguridad (AUD)**

* **Frontend:** Consola de monitoreo de seguridad con filtros avanzados por tipo de evento, severidad, rango de fechas e identificación del actor, además de gráficos de actividad sospechosa.  
* **Backend & Lógica de Negocio:** API de Ingesta de Eventos (Webhook interno): los otros 11 módulos están obligados a enviar notificaciones asíncronas de eventos críticos (intentos de login fallidos, accesos denegados, cambios de roles) a este módulo. Los registros deben ser inmutables.

***Base de Datos:** Tabla audit\_logs con restricciones de solo escritura para aplicaciones y protección contra borrado.*

## **12\. Módulo de Portal del Paciente y Telemedicina (TEL)**

* **Frontend:** Panel centralizado del paciente (próximas horas médicas, recetas vigentes, resultados de laboratorio) y una interfaz de sala de videoasistencia integrada para teleconsultas.  
* **Backend & Lógica de Negocio:** Autorización basada estrictamente en tokens de paciente para evitar fuga de información entre usuarios. Gestión de enlaces seguros para la sala de video.

***Base de Datos:** Tablas teleconsultations y patient\_notifications.*

*Grupo 1*

*Jacob Liguen*

*Carlos Mac-Iver*

*Roberto Fuentes*

*Módulo de Auditoría y Trazabilidad de Seguridad (AUD) (Módulo 11\)*

*Grupo 2*

*Benjamin Medina*

*Antony Durán*

*Módulo de Autenticación y Gestión de Identidades (IAM) (Módulo 1\)*

*Grupo 3*

*Martín Arroyo*

*Moisés Bascur*

*José Antiman*

*Pablo Velasquez*

*Módulo de Laboratorio Clínico y Exámenes (LAB) (Módulo 7\)*

*Grupo 4*

*Jasser Flores*

*José Alvarado*

*Andrés Chandia*

*Christopher Salazar*

*Módulo de Agenda y Citaciones (AGT) (Módulo 4\)*

*Grupo 5*

*Alejandro Fernández*

*Joaquin Figueroa*

*Matias Madrid*

*Farmacia e Insumos (FAR) (Módulo 8\)*

*Grupo 6*

*Joseph Burgos*

*Leonardo Aravena*

*Benjamín Kreps*

*Cristobal Barriga*

*Módulo de Gestión de Pacientes y Admisión (PAC) (Módulo 2\)*

Grupo 7 

Claudio Godoy

Matías Gubelin

*Módulo de Pabellones y Quirófanos (PAB) (Módulo 6\)*

Grupo 8

Matías Gajardo

Benjamín Cheuquemilla

Módulo de Gestión de Personal Clínico y Médicos (MED) (Módulo 3\)

Grupo 9

Luciano cabeza

Módulo de Urgencias y Triage (TRG) (Módulo 9\)

