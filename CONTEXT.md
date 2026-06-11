# Ouroboros IDS — Contexto del Proyecto

## Descripción General

Ouroboros es un Sistema de Detección de Intrusos (IDS) de red, desarrollado en Python, orientado a redes locales institucionales. Monitorea tráfico en tiempo real usando Scapy, detecta dispositivos no autorizados (whitelist dinámica), identifica conexiones a IPs peligrosas (blacklist), registra consultas DNS, y notifica al administrador por correo electrónico con análisis forense automatizado.

Incluye un dashboard web (Flask) con autenticación JWT, gestión de usuarios y administración completa del sistema.

---

## Stack Tecnológico

| Componente | Tecnología |
|---|---|
| Captura de paquetes | Scapy |
| Base de datos | SQLite (WAL mode) |
| Dashboard web | Flask + PyJWT + Werkzeug |
| Correo | smtplib (SMTP/TLS) |
| Threat Intelligence | AbuseIPDB API, ip-api.com, python-whois |
| Detección de red | netifaces, ARP scan activo |
| Configuración | python-dotenv (.env) |
| Instalación | pyproject.toml (setuptools) |

---

## Estructura de Archivos

```
ouroboros-ids/
├── ouroboros.py          # Punto de entrada principal
├── cli.py                # CLI de administración (sin sudo)
├── seed_demo.py          # Generador de datos de prueba
├── pyproject.toml        # Configuración del paquete
├── .env                  # Variables de entorno (no versionado)
├── .env.example          # Plantilla de variables de entorno
│
├── config/
│   └── settings.py       # Configuración central, carga .env
│
├── core/
│   ├── sniffer.py        # Motor de captura de paquetes (Scapy)
│   ├── blacklist.py      # Gestión de lista negra
│   ├── db_writer.py      # Capa de acceso a SQLite
│   └── feed_updater.py   # Descarga y parseo de feeds remotos
│
├── services/
│   ├── worker.py         # Motor de procesamiento de alertas (hilo)
│   ├── mailer.py         # Envío de correos HTML
│   ├── abuse_api.py      # Consultas a AbuseIPDB, ip-api, WHOIS
│   └── logger.py         # Bitácora en archivo de texto
│
├── dashboard/
│   └── dashboard.py      # Aplicación Flask (dashboard web)
│
└── data/
    ├── ouroboros.db      # Base de datos SQLite
    ├── blacklist.txt     # Lista negra local de IPs
    └── .reload_blacklist # Archivo-señal para recarga en caliente
```

---

## Arranque del Sistema

### Comando principal (requiere sudo)
```bash
sudo ouroboros
sudo ouroboros --interface eth0
```

### Secuencia de arranque (`ouroboros.py`)
1. Si el primer argumento es un subcomando CLI (`status`, `devices`, etc.), despacha a `cli.py` sin requerir sudo.
2. Valida privilegios de root (`os.geteuid()`).
3. Valida variables de entorno requeridas (`config/settings.py::validate()`).
4. Detecta automáticamente la interfaz de red activa (excluye loopback).
5. Instancia `OuroborosSniffer` → inicializa BD → carga blacklist → ARP scan activo.
6. Arranca hilo **worker** (procesamiento de alertas cada 5 s).
7. Arranca hilo **dashboard** (Flask en `0.0.0.0:5000`).
8. Bloquea en `sniffer.iniciar()` (captura pasiva hasta Ctrl+C).

---

## Módulos

### `config/settings.py`
Carga variables de entorno desde `.env` usando `python-dotenv`.

**Variables expuestas:**
- `SMTP_EMAIL`, `SMTP_PASSWORD`, `SMTP_HOST`, `SMTP_PORT` — credenciales SMTP
- `ADMIN_EMAIL` — destinatario de alertas
- `ABUSEIPDB_KEY` — API key de AbuseIPDB
- `DB_PATH` — ruta a la base de datos SQLite
- `BASE_DIR` — directorio raíz del proyecto

**Funciones:**
- `validate()` — lanza `EnvironmentError` si faltan variables requeridas
- `get_smtp_credentials()` — recarga `.env` en caliente y retorna credenciales SMTP actuales

---

### `core/sniffer.py` — `OuroborosSniffer`

Motor principal del IDS. Clase que encapsula todo el estado del sistema.

**Inicialización (`__init__`):**
- Llama a `init_db()` para crear tablas
- Carga blacklist en memoria (`self.ips_peligrosas`)
- Inicializa diccionarios de cooldown por MAC y por par (MAC, IP peligrosa)
- Mantiene cola `alertas_pendientes` para el worker

**Métodos principales:**

| Método | Descripción |
|---|---|
| `arp_scan()` | ARP broadcast a toda la subred, registra dispositivos, autoriza gateway y máquina local |
| `procesar_paquete(paquete)` | Callback de Scapy; procesa capas ARP, DNS e IP |
| `_en_cooldown(mac)` | Evita spam de alertas whitelist (1 alerta/60 s por MAC) |
| `_en_cooldown_bl(mac, ip)` | Evita spam de alertas blacklist (1 alerta/60 s por par) |
| `_vigilar_recarga()` | Hilo daemon; detecta `.reload_blacklist` y recarga blacklist en caliente |
| `iniciar()` | Arranca hilo de recarga y llama a `sniff()` (bloqueante) |

**Lógica de `procesar_paquete`:**
- **ARP**: registra dispositivo; si es nuevo, encola alerta `DISPOSITIVO_NUEVO`
- **DNS**: registra dominio visitado en `bitacora_dns`
- **IP**: verifica si el origen está autorizado (whitelist); verifica si el destino es peligroso (blacklist); encola alertas correspondientes con cooldown

**Funciones auxiliares del módulo:**
- `obtener_rango_red(interfaz)` → rango CIDR (ej: `192.168.1.0/24`)
- `obtener_ip_mac_propias(interfaz)` → IP y MAC de la máquina local
- `obtener_gateway()` → IP del router (soporta netifaces y netifaces2)

---

### `core/db_writer.py`

Capa de acceso a SQLite. Todas las funciones abren y cierran conexión en cada llamada.

**Tablas que crea `init_db()`:**

| Tabla | Descripción |
|---|---|
| `dispositivos_conocidos` | Registro de cada MAC vista en la red (ip, mac, timestamps, autorizado) |
| `alertas_whitelist` | Alertas de dispositivos no autorizados (procesada = correo enviado) |
| `bitacora_dns` | Registro de dominios consultados por IP |
| `alertas_blacklist` | Conexiones a IPs peligrosas (procesada = correo enviado) |
| `feed_sources` | Fuentes de feeds de threat intelligence (nombre, url, activo) |
| `analisis_forense` | Inteligencia por IP peligrosa única (score, tipo, país, ISP, correo abuso) |
| `usuarios` | Cuentas del dashboard (hash PBKDF2, rol, cambiar_pwd) |

**Feeds por defecto registrados en `init_db()`:**
- Feodo Tracker (botnets/C2)
- Emerging Threats (IPs comprometidas)
- Tor Exit Nodes
- CINS Score (bad guys)

**Funciones clave:**

| Función | Descripción |
|---|---|
| `registrar_dispositivo(ip, mac)` | INSERT o UPDATE; retorna True si es nuevo |
| `es_autorizado(ip, mac)` | Busca por MAC; retorna bool |
| `autorizar_dispositivo(mac)` | SET autorizado=1 por MAC |
| `autorizar_por_ip(ip)` | SET autorizado=1 por IP (para gateway) |
| `registrar_y_autorizar(ip, mac)` | Registra y autoriza en una sola operación |
| `registrar_alerta_whitelist(ip, mac, detalle)` | INSERT en alertas_whitelist |
| `registrar_dns(ip_origen, dominio)` | INSERT en bitacora_dns |
| `registrar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa)` | INSERT en alertas_blacklist |
| `registrar_analisis_forense(...)` | INSERT OR REPLACE en analisis_forense (una fila por IP) |
| `actualizar_ultimo_update_feed(feed_id)` | Marca timestamp de descarga exitosa |

---

### `core/blacklist.py`

Interfaz pública de la blacklist.

- `cargar_blacklist()` → delega a `feed_updater.cargar_blacklist_completa()`
- `es_peligrosa(ip_destino, ips_peligrosas)` → lookup en set en memoria
- `agregar_ip(ip, comentario)` → escribe en `blacklist.txt`
- `quitar_ip(ip)` → reescribe `blacklist.txt` sin la IP

---

### `core/feed_updater.py`

Descarga y unificación de fuentes de IPs peligrosas.

**Funciones:**

| Función | Descripción |
|---|---|
| `cargar_blacklist_completa()` | Función pública principal; combina feeds remotos + lista local; nunca lanza excepción |
| `_cargar_feeds_remotos()` | Lee `feed_sources WHERE activo=1`, hace GET a cada URL, parsea IPs válidas |
| `_cargar_blacklist_local()` | Lee `blacklist.txt` línea a línea, ignora `#` y líneas vacías |
| `_parsear_feed(texto)` | Extrae IPs individuales válidas de texto plano (ignora CIDR, hostnames, comentarios) |

---

### `services/worker.py`

Motor de procesamiento de alertas. Corre en hilo daemon separado, polling cada 5 s.

**Función `procesar_alertas()`:**
1. Abre conexión en modo WAL (`PRAGMA journal_mode=WAL`)
2. `_procesar_whitelist()`: lee alertas no procesadas → envía correo de advertencia → registra en bitácora → marca `procesada=1`
3. `_procesar_blacklist()`: lee alertas no procesadas → envía correo de emergencia → llama a `analizar_ip()` → persiste forense → envía reporte forense → marca `procesada=1`

Maneja `sqlite3.OperationalError` silenciosamente (BD aún no inicializada).

---

### `services/abuse_api.py`

Módulo de Threat Intelligence y análisis forense de IPs.

**Fuentes consultadas:**

| Función | API | Datos obtenidos |
|---|---|---|
| `consultar_abuseipdb(ip)` | AbuseIPDB v2 | score de abuso (0-100), tipo de riesgo, total de reportes |
| `consultar_geoip(ip)` | ip-api.com (gratuita) | país, ISP, ASN |
| `consultar_whois(ip)` | python-whois | correo de abuso del proveedor |

**Función principal `analizar_ip(ip)`:**
- Llama a las tres fuentes en secuencia
- Si todas fallan, retorna `None`
- Normaliza los diccionarios con valores por defecto si alguna fuente falla
- Retorna diccionario unificado con todos los campos forenses

---

### `services/mailer.py`

Envío de correos HTML estilizados al administrador.

**Funciones:**

| Función | Asunto | Cuándo se envía |
|---|---|---|
| `enviar_alerta_whitelist(ip, mac, detalle)` | `[Ouroboros] Alerta — Dispositivo no autorizado` | Dispositivo no autorizado detectado |
| `enviar_alerta_blacklist(ip_origen, mac_origen, ip_peligrosa)` | `[Ouroboros] 🚨 EMERGENCIA — Conexión a IP peligrosa` | Conexión a IP peligrosa detectada |
| `enviar_reporte_forense(...)` | `[Ouroboros] Reporte Forense — <ip>` | Después del análisis forense exitoso |

`_conectar_smtp()` recarga credenciales desde `.env` en cada llamada (detecta cambios sin reiniciar).
`_generar_html_base()` genera el template HTML responsivo reutilizado por los tres tipos de correo.

---

### `services/logger.py`

Registro de eventos en archivo de texto (`data/ids_bitacora.log`).

Formato de línea:
```
[YYYY-MM-DD HH:MM:SS] | EVENTO: <TIPO> | ORIGEN: <ip> | DESTINO: <dest> | DETALLE: <texto>
```

---

### `dashboard/dashboard.py` — Aplicación Flask

Dashboard web de administración. Funciona aunque el sniffer no esté corriendo (solo lee SQLite).

**Autenticación y autorización:**
- Login con usuario/contraseña validados contra tabla `usuarios` (hash PBKDF2 con Werkzeug)
- JWT firmado (HS256) con claims: `sub` (usuario), `rol`, `pwd` (contraseña temporal), `exp` (30 min)
- Cookie `HttpOnly + SameSite=Lax`
- `JWT_SECRET` generado automáticamente y persistido en `.env` si no existe
- Dos roles: `admin` (acceso total) y `operador` (lectura + operaciones básicas)
- Contraseña temporal fuerza cambio en primer login

**Decoradores de acceso:**
- `@requiere_token` — exige JWT válido; redirige a `/cambiar-password` si `pwd=1`
- `@requiere_admin` — además exige `rol=admin`

**Rutas:**

| Ruta | Método | Descripción |
|---|---|---|
| `/login` | GET/POST | Inicio de sesión |
| `/logout` | GET | Cierra sesión (borra cookie) |
| `/cambiar-password` | GET/POST | Cambio de contraseña |
| `/` | GET | Resumen general (contadores + top DNS + últimas alertas) |
| `/dispositivos` | GET | Lista de dispositivos + autorización/revocación por MAC |
| `/autorizar/<mac>` | POST | Autoriza un dispositivo |
| `/desautorizar/<mac>` | POST | Revoca autorización |
| `/alta` | POST | Alta manual por MAC (registro + autorización directa) |
| `/alertas` | GET | Alertas de dispositivos no autorizados |
| `/dns` | GET | Bitácora DNS con filtro por IP |
| `/blacklist` | GET | Lista local + feeds remotos + detecciones forenses |
| `/blacklist/agregar` | POST | Agrega IP a `blacklist.txt` |
| `/blacklist/quitar` | POST | Elimina IP de `blacklist.txt` |
| `/feeds/toggle/<id>` | POST | Activa/desactiva un feed |
| `/feeds/agregar` | POST | Registra nuevo feed |
| `/feeds/actualizar` | POST | Fuerza recarga de feeds en el sniffer |
| `/usuarios` | GET | Gestión de cuentas (solo admin) |
| `/usuarios/agregar` | POST | Crea cuenta nueva (solo admin) |
| `/usuarios/eliminar/<id>` | POST | Elimina cuenta (solo admin, no puede eliminar la propia ni el último admin) |
| `/config` | GET | Vista de configuración del correo admin |
| `/config/admin` | POST | Actualiza `ADMIN_EMAIL` en `.env` |

**Mecanismo de recarga en caliente:**
El dashboard escribe el archivo `data/.reload_blacklist` (señal). El hilo `_vigilar_recarga()` del sniffer lo detecta cada 5 s, recarga la blacklist en memoria y elimina el archivo.

---

### `cli.py` — CLI de Administración

Interfaz de línea de comandos sin necesidad de sudo. Accede directamente a SQLite y `blacklist.txt`.

**Comandos:**

```
ouroboros devices list
ouroboros devices authorize <mac>
ouroboros devices block <mac>
ouroboros devices clear

ouroboros blacklist list
ouroboros blacklist add <ip>
ouroboros blacklist remove <ip>

ouroboros feeds list
ouroboros feeds add <nombre> <url>
ouroboros feeds enable <id>
ouroboros feeds disable <id>
ouroboros feeds remove <id>

ouroboros status
ouroboros dns <ip>
ouroboros help
```

Los comandos que modifican archivos o BD verifican permisos de escritura (`os.access`) antes de proceder. Los comandos `blacklist add/remove` y `feeds enable/disable/add` crean el archivo-señal de recarga para que el sniffer aplique los cambios en ~5 s.

---

## Flujo de Detección Completo

```
Paquete en la red
        │
        ▼
procesar_paquete() [Scapy callback]
        │
        ├─► ARP → registrar_dispositivo()
        │         si nuevo → alerta DISPOSITIVO_NUEVO en cola
        │
        ├─► DNS → registrar_dns(ip_origen, dominio)
        │
        └─► IP
              ├─► ¿ip_origen autorizado? NO + cooldown libre
              │     → registrar_alerta_whitelist()
              │     → encolar WHITELIST
              │
              └─► ¿ip_destino en blacklist? SÍ + cooldown libre
                    → registrar_alerta_blacklist()
                    → encolar BLACKLIST

Worker (cada 5 s)
        │
        ├─► alertas_whitelist WHERE procesada=0
        │     → enviar_alerta_whitelist()
        │     → registrar_evento() [archivo log]
        │     → procesada=1
        │
        └─► alertas_blacklist WHERE procesada=0
              → enviar_alerta_blacklist()
              → analizar_ip() [AbuseIPDB + GeoIP + WHOIS]
              → registrar_analisis_forense()
              → enviar_reporte_forense()
              → procesada=1
```

---

## Variables de Entorno Requeridas (`.env`)

```env
SMTP_EMAIL=correo@gmail.com
SMTP_PASSWORD=app_password
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
ADMIN_EMAIL=admin@dominio.com
ABUSEIPDB_KEY=tu_api_key
DB_PATH=data/ouroboros.db

# Generado automáticamente por el dashboard:
JWT_SECRET=...

# Generado automáticamente por el dashboard:
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=...
```

---

## Instalación

```bash
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows

pip install -e .

cp .env.example .env
# Editar .env con credenciales reales

sudo ouroboros                 # Arranca el IDS completo
ouroboros status               # Sin sudo — solo consulta
```

---

## Dependencias (pyproject.toml)

```
Flask>=3.1
PyJWT>=2.10
Werkzeug>=3.1
netifaces2
python-dotenv>=1.2
requests>=2.34
scapy>=2.7
python-whois>=0.9
```

---

## Notas de Diseño

- **WAL mode**: el worker y el sniffer acceden a la misma BD simultáneamente sin bloqueos gracias a `PRAGMA journal_mode=WAL`.
- **Cooldown en memoria**: los diccionarios `_cooldowns` y `_cooldowns_bl` evitan inundar la BD y el correo con miles de alertas por segundo del mismo dispositivo/IP.
- **INSERT OR REPLACE en `analisis_forense`**: una IP peligrosa que dispare múltiples alertas produce un solo registro de inteligencia siempre actualizado.
- **Recarga en caliente**: el sniffer nunca necesita reiniciarse para aplicar cambios en la blacklist o los feeds — el mecanismo de archivo-señal garantiza coherencia sin locks distribuidos.
- **JWT sin base de datos de sesiones**: la expiración de 30 min y la firma HMAC-SHA256 eliminan la necesidad de almacenar sesiones del lado del servidor.
- **Contraseña temporal**: el campo `cambiar_pwd=1` en la tabla `usuarios` fuerza el cambio antes de que el usuario pueda acceder a cualquier vista, con el claim `pwd` replicado en el JWT para evitar consultas adicionales a la BD por request.
