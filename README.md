# GymFlow

SaaS multi-tenant para la gestión de gimnasios (prototipo académico de Ingeniería de Software).
Cada gimnasio se registra, tiene sus propios usuarios y administra socios, planes, control de
acceso (check-in) y reserva de clases. Los datos de un gimnasio nunca son visibles para otro.
La portada publica permite explorar gimnasios, planes y clases; las personas pueden crear una
cuenta e inscribirse a un plan, mientras los dueños administran su gimnasio desde un panel privado.

## Funcionalidades

- Registro del gimnasio (onboarding SaaS) y planes iniciales.
- Roles: `admin` (todo), `staff` (socios, check-in y clases) y `member` (portal de su membresía).
- Sitio público con información de gimnasios, planes y próximas clases.
- Perfil público editable del gimnasio con descripción, dirección, contacto y horarios.
- Inscripción de personas a un gimnasio y plan, con acceso a un portal privado de membresía.
- Socios: alta con consentimiento, edición, renovación y eliminación (derecho de supresión).
- Control de acceso: el check-in bloquea membresías vencidas y evita duplicados diarios.
- Clases: programación, reservas con cupos atómicos y cancelación.
- Panel con socios activos, vencidos, asistencias (check-ins) de los últimos 7 días y vencimientos próximos.
- Registro de auditoría de acciones relevantes.

## Ejecutar localmente

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python seed.py          # opcional: crea un gimnasio de demostración
python app.py           # http://localhost:5000
```

Demo (solo local): `demo@gymflow.cl` / `Demo12345678`

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Las pruebas cubren funcionalidad (altas, inscripción de miembros, check-in, renovaciones, cupos) y seguridad
(aislamiento entre gimnasios, roles, CSRF, inyección SQL, XSS, bloqueo por intentos, hashing,
cabeceras y auditoría).


## Seguridad: mapa OWASP Top 10 (2021)

| Riesgo | Medida en el prototipo |
|---|---|
| A01 Control de acceso roto | Todas las consultas filtran por `gym_id`; roles `admin`/`staff`; respuesta 404 ante recursos de otro gimnasio. |
| A02 Fallas criptográficas | Contraseñas con hash scrypt; `SECRET_KEY` desde variable de entorno; cookies `HttpOnly`, `SameSite` y `Secure`; HTTPS/HSTS en producción. |
| A03 Inyección | Consultas parametrizadas; validación y normalización de entradas; Jinja2 escapa la salida (anti XSS). |
| A04 Diseño inseguro | Aislamiento multi-tenant por diseño, cupos atómicos, consentimiento explícito de datos. |
| A05 Configuración incorrecta | CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`; errores genéricos sin trazas. |
| A06 Componentes vulnerables | Dependencias mínimas y versiones fijadas en `requirements.txt`. |
| A07 Fallas de autenticación | Política de contraseñas, bloqueo tras 5 intentos, mensajes genéricos, sesión de 30 min y rotación al ingresar. |
| A08 Integridad de software y datos | Token CSRF en todos los formularios POST; sin deserialización insegura. |
| A09 Registro y monitoreo | Tabla `audit_log` con usuario, acción, IP real del cliente (`TRUST_PROXY`) y fecha; visible para el administrador. |
| A10 SSRF | La aplicación no realiza solicitudes a URLs entregadas por el usuario. |

## Normativa y ética

- **Ley 21.459 (delitos informáticos, Chile):** el diseño previene acceso ilícito, interceptación y
  alteración de datos mediante autenticación, control de acceso, cifrado en tránsito y auditoría.
- **Protección de datos personales (Ley 19.628 y Ley 21.719):** consentimiento registrado,
  minimización de datos y derecho de supresión (eliminación de socios).

## Estructura

```
app.py            aplicación Flask (rutas, seguridad, base de datos)
templates/        vistas HTML (Jinja2)
static/style.css  estilos
static/chatbot.js interacción y actualización periódica del chatbot
chatbot_updates/faqs.json preguntas y respuestas públicas editables
tests/            pruebas automáticas
seed.py           datos de demostración
Procfile, render.yaml, requirements.txt   despliegue
```

Los administradores pueden editar, agregar y eliminar preguntas desde **Chatbot**.
El catálogo está en `chatbot_updates/faqs.json`; el endpoint público solo entrega
sus identificadores, preguntas y respuestas, nunca datos de socios o usuarios.
El chat consulta cambios cada 3 segundos mientras está abierto. El catálogo es
global y compartido por todos los gimnasios: no agregues información privada.
Al crear o eliminar un plan, la respuesta pública de planes se actualiza con los
planes del gimnasio donde se hizo el cambio y queda visible para todos.
En un hosting con almacenamiento efímero, los cambios del archivo se pierden al
reiniciar o desplegar; configura `CHATBOT_FAQ_FILE` para apuntarlo a almacenamiento
persistente.

Los valores iniciales de horario, inscripción, entrenamiento personal y dirección
son ejemplos; reemplázalos antes de publicar el sitio.
