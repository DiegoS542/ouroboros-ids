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
git clone https://github.com/usuario/ouroboros-ids.git
cd ouroboros-ids
python -m venv venv
source venv/bin/activate
pip install -e .
cp .env.example .env
# Llenar .env con credenciales reales
```

### 3. Registrar el comando `ouroboros` en el sistema

Este paso hace que `ouroboros` funcione desde cualquier directorio sin activar el venv:

```bash
sudo ln -sf "$(pwd)/venv/bin/ouroboros" /usr/local/bin/ouroboros
```

Solo se ejecuta una vez por instalación.

### 4. Uso

```bash
# Arrancar el IDS (requiere sudo para raw sockets)
sudo ouroboros

# Administración (no requiere sudo)
ouroboros status
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
ouroboros dns <ip>
```
