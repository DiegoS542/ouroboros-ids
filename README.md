# Ouroboros IDS

Sistema de detección de intrusos (IDS) para redes locales. Monitorea tráfico en tiempo real, detecta dispositivos no autorizados y conexiones a IPs peligrosas, y notifica al administrador por correo.

---

## Instalación

### 1. Prerequisitos del sistema

```bash
# Arch Linux
sudo pacman -S libpcap git python

# Ubuntu / Debian
sudo apt install libpcap-dev git python3 python3-venv

# Fedora
sudo dnf install libpcap-devel git python3
```

### 2. Clonar e instalar

```bash
git clone https://github.com/DiegoS542/ouroboros-ids.git
cd ouroboros-ids
python -m venv venv
source venv/bin/activate
pip install -e .
cp .env.example .env
# Editar .env con las credenciales reales
```

### 3. Registrar el comando `ouroboros` en el sistema

Permite ejecutar `ouroboros` desde cualquier directorio sin activar el venv manualmente:

```bash
sudo ln -sf "$(pwd)/venv/bin/ouroboros" /usr/local/bin/ouroboros
```

Solo se ejecuta una vez por instalación.

---

## Uso

### Arrancar el IDS

```bash
sudo ouroboros                        # interfaz detectada automáticamente
sudo ouroboros --interface eth0       # especificar interfaz manualmente
```

Al primer arranque se genera una contraseña aleatoria para el dashboard. Cámbiala antes de usar el sistema.

### Dashboard web

Disponible en `http://localhost:5000` mientras el IDS esté corriendo.

---

## Datos de prueba

Para revisar el dashboard sin necesidad de tráfico real de red:

```bash
# Primera vez ejecutando el IDS
python seed_demo.py

# Dspués de ejevutar el IDS
sudo python seed_demo.py
```

Inserta dispositivos, alertas whitelist, conexiones a IPs peligrosas con análisis forense completo y bitácora DNS. Después abre `http://localhost:5000` y revisa cada sección.

---

## CLI de administración

### Consulta — no requiere sudo

```bash
ouroboros status                      # resumen general del sistema
ouroboros devices list                # dispositivos detectados en la red
ouroboros blacklist list              # IPs en la lista negra local
ouroboros feeds list                  # feeds de IPs peligrosas registrados
ouroboros dns <ip>                    # últimas consultas DNS de una IP
ouroboros help                        # referencia de todos los comandos
```

### Administración — requiere sudo

```bash
# Dispositivos
sudo ouroboros devices authorize <mac>
sudo ouroboros devices block <mac>
sudo ouroboros devices clear

# Lista negra local
sudo ouroboros blacklist add <ip>
sudo ouroboros blacklist remove <ip>

# Feeds
sudo ouroboros feeds add <nombre> <url>
sudo ouroboros feeds enable <id>
sudo ouroboros feeds disable <id>
sudo ouroboros feeds remove <id>
```
