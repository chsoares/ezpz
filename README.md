# ezpz

Scripts to automate repetitive enumeration processes in penetration testing. Mainly uses NetExec and Impacket.

## Features

- `netscan`: Host discovery and port scanning
- `webscan`: Web application enumeration and directory fuzzing
- `adscan`: Active Directory enumeration
- `enumdomain`: Detailed domain enumeration
- `enumuser`: User and permission enumeration
- `enumshares`: SMB share enumeration
- `enumsql`: SQL database enumeration
- `checkvulns`: Common vulnerability checks

## Installation

```bash
# Install system dependencies
sudo apt install -y zsh fping nmap whatweb ffuf

# Install Python dependencies
pipx install -r requirements.txt

# Add to .zshrc
echo "source /path/to/ezpz.sh" >> ~/.zshrc

# Reload shell
source ~/.zshrc
```

## Requirements

- zsh
- Python 3.8+
