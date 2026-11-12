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
- `certspray`: Per-credential ADCS ESC enumeration
- `credspray`: Kerberos password spraying via kerbrute
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

## credspray

Thin wrapper around `kerbrute passwordspray`. Its job is to reuse whatever you
already have — a user list, a password list, or a `user:pass` file — without
retelling you how Kerberos works.

```fish
# One password against a user list
ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \
    -u users.txt -p 'Winter2024'

# Password list against a user list
ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \
    -u users.txt -p passwords.txt

# Hail mary from creds.txt: every password against every user
ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local -f creds.txt
```

`-u` and `-p` accept a literal value, a one-per-line file, or a `user:pass`
file. When every meaningful line of the file carries a colon it is treated as a
creds file: `-u` keeps the username side, `-p` keeps the password side.

`-f` is the hail mary: it splits a `user:pass` file into usernames and unique
passwords and sprays all of them against each other. Lines starting with `#` are
ignored, `DOMAIN\user` / `user@domain` are normalized to the bare username, and
NT hashes (32 hex chars) are skipped — use `testcreds -H` for pass-the-hash.

Accounts that never authenticate are dropped: `krbtgt`, machine accounts ending
in `$`, and the built-in placeholders (`Guest`, `DefaultAccount`,
`DefaultUser`, `WDAGUtilityAccount`). A disabled account comes back as
`KRB_ERR_CLIENT_REVOKED`, which `--safe` reads as a lockout, so leaving `krbtgt`
in the list would abort every spray.

Output is one command template plus a line per password, so the run is
reproducible.

Lockout protection is on by default: kerbrute always runs with `--safe`, so the
spray stops on the first locked account and names it. Before spraying, the
domain password policy is read with `nxc --pass-pol` (null session first, then a
known credential) and the password list is trimmed to one attempt below the
lockout threshold — the attempt that reaches the threshold is the one that
locks the account.

- `--force` sprays the whole list, ignoring the policy guard.
- `--unsafe` drops `--safe`, so kerbrute keeps spraying after a lockout.

Throttling stays with kerbrute (`--delay`, `--threads`).

## Requirements

- Fish Shell 3.0+
- Python 3.8+
- nmap, fping (network scanning)
- whatweb, ffuf (web enumeration)
- NetExec (Windows/AD enumeration)
- Impacket tools

## Security Context

This is a defensive security toolkit designed for authorized penetration testing and security assessments. All functions are intended for legitimate security testing purposes within properly scoped engagements.
