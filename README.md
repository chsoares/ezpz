# ezpz

A Fish Shell-based collection of penetration testing enumeration scripts, refactored from the original Zsh version. Automates repetitive enumeration processes using NetExec and Impacket.

## Features

- `netscan`: Host discovery and port scanning
- `webscan`: Web application enumeration with whatweb and ffuf
- `adscan`: Active Directory enumeration using NetExec
- `checkvulns`: Common vulnerability checks
- `enumnull`: NULL session enumeration
- `enumdomain`: Detailed domain enumeration
- `enumuser`: User and permission enumeration  
- `enumshares`: SMB share enumeration
- `enumsqli`: SQL Server enumeration
- `testcreds`: Credential validation against targets
- `loot`: Information extraction from compromised Windows hosts
- `secretsparse`: Parse secretsdump.py output for credentials

## Installation

### Prerequisites

- Fish Shell 3.0+
- Python 3.8+

### Setup

1. **Install system dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt install -y fping nmap whatweb ffuf
   pipx install netexec impacket-scripts
   pipx install bloodyAD
   
   # Arch Linux
   yay -S fping nmap whatweb ffuf impacket pre2k-git
   pipx install git+https://github.com/Pennyw0rth/NetExec
   pipx install bloodyAD
   ```

2. **Set EZPZ_HOME environment variable:**
   ```fish
   set -gx EZPZ_HOME /path/to/ezpz
   ```

3. **Add functions to Fish path:**
   ```fish
   set -gx fish_function_path "$EZPZ_HOME/functions" $fish_function_path
   ```

4. **Make settings persistent (optional):**
   Add the above lines to your `~/.config/fish/config.fish` file.

## Usage

After installation, you can use ezpz commands directly from your Fish shell:

```fish
# Basic host discovery and port scanning
ezpz netscan 192.168.1.0/24

# Web application enumeration
ezpz webscan http://target.com

# Active Directory enumeration
ezpz adscan 192.168.1.10

# Test credentials against targets
ezpz testcreds -u administrator -p password123 192.168.1.10

# Extract information from compromised hosts
ezpz loot -u administrator -p password123 192.168.1.10

# Parse secretsdump.py output
ezpz secretsparse /path/to/secretsdump_output.txt
```

Use `ezpz --help` or `ezpz <command> --help` for detailed usage information.

## Requirements

- Fish Shell 3.0+
- Python 3.8+
- nmap, fping (network scanning)
- whatweb, ffuf (web enumeration)
- NetExec (Windows/AD enumeration)
- Impacket tools

## Security Context

This is a defensive security toolkit designed for authorized penetration testing and security assessments. All functions are intended for legitimate security testing purposes within properly scoped engagements.
