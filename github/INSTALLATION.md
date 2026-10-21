# Installation Guide: R3X-BugBounty

This guide details installation across **Kali Linux**, **Arch Linux**, **Ubuntu**, and **Debian**.

## Quick Automated Install

Run the interactive installer script:

```bash
git clone https://github.com/r3xdec/r3x-bugbounty.git
cd r3x-bugbounty
chmod +x install.sh
./install.sh
```

The script will:
1. Detect your Linux distribution.
2. Check for required security tools (`nmap`, `whatweb`, `nuclei`, `httpx`, `subfinder`, `katana`, `amass`, `sslyze`, `dnsx`).
3. Display missing dependencies and request confirmation before proceeding.
4. Download official release binaries for missing tools.
5. Setup the Python 3 virtual environment (`.venv`).
6. Verify and audit all installed components.

---

## Manual Installation

### 1. System Packages

#### Kali Linux / Debian / Ubuntu:
```bash
sudo apt update
sudo apt install -y git curl python3 python3-venv python3-pip nmap whatweb
```

#### Arch Linux:
```bash
sudo pacman -Sy --noconfirm git curl python nmap
```

### 2. Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### 3. Verification
```bash
r3x doctor
```
