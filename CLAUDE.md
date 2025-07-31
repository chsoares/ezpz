# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Installation and Setup

The ezpz toolkit is a Fish Shell-based collection of penetration testing enumeration scripts, refactored from the original Zsh version. To set up the environment:

1. **Set EZPZ_HOME environment variable:**
   ```fish
   set -gx EZPZ_HOME /path/to/ezpz
   ```

2. **Add functions to Fish path:**
   ```fish
   set -gx fish_function_path "$EZPZ_HOME/functions" $fish_function_path
   ```

3. **Install system dependencies:**
   ```bash
   sudo apt install -y zsh fping nmap whatweb ffuf
   pipx install netexec impacket-scripts
   ```

## Architecture Overview

### Core Components

- **Main Dispatcher (`functions/ezpz.fish`)**: The primary entry point that routes commands to specific functions
- **Color System (`functions/_ezpz_colors.fish`)**: Centralized color output functions for consistent terminal formatting
- **Individual Function Modules**: Each penetration testing command is implemented as a separate Fish function

### Function Structure

All functions follow the naming convention `_ezpz_<command>.fish` and implement the pattern:
- Argument parsing using Fish's `argparse` 
- Authentication handling (for commands that require credentials)
- Prerequisite tool validation
- Logging to `~/.ezpz/` or `$boxpwd/ezpz/` directory
- Consistent color output using the centralized color functions

### Authentication Pattern

Functions that require authentication (loot, checkvulns, enumdomain, testcreds, enumuser, enumshares, enumsqli) handle their own credential parsing rather than using a centralized `get_auth` function. Each implements support for:
- Username/password authentication (`-u user -p password`)
- Pass-the-hash authentication (`-u user -H hash`)  
- Kerberos authentication (`-k`)
- Domain specification (`-d domain`)

## Available Commands

- `netscan` - Host discovery and port scanning
- `webscan` - Web application enumeration with whatweb and ffuf
- `adscan` - Active Directory enumeration using NetExec
- `checkvulns` - Common vulnerability checks
- `enumnull` - NULL session enumeration
- `enumdomain` - Detailed domain enumeration
- `enumuser` - User and permission enumeration  
- `enumshares` - SMB share enumeration
- `enumsqli` - SQL Server enumeration
- `testcreds` - Credential validation against targets
- `loot` - Information extraction from compromised Windows hosts
- `secretsparse` - Parse secretsdump.py output for credentials

## Development Guidelines

### Color Output Standards

Use the centralized color functions from `_ezpz_colors.fish`:
- `ezpz_header` - Yellow bold for section headers `[+]`
- `ezpz_info` - Cyan for informational messages `[*]`
- `ezpz_cmd` - Blue for command display `[>]`
- `ezpz_error` - Red bold for errors `[!]`
- `ezpz_warn` - Red for warnings `[-]`
- `ezpz_success` - Magenta bold for success `[✓]`
- `ezpz_question` - Cyan for user prompts `[?]`
- `ezpz_title` - Magenta bold for titles `[~]`

### Adding New Functions

1. Create `functions/_ezpz_<command>.fish`
2. Include `source $EZPZ_HOME/functions/_ezpz_colors.fish` at the top
3. Implement help with `--help` flag support
4. Add to the commands list in `functions/ezpz.fish:27`
5. Follow the authentication pattern if credentials are needed

### Tool Dependencies

The codebase assumes these tools are available in `$PATH`:
- `nmap`, `fping` for network scanning
- `whatweb`, `ffuf` for web enumeration  
- `nxc` (NetExec) for Windows/AD enumeration
- Impacket tools (`secretsdump.py`, `GetNPUsers.py`, etc.)
- Standard utilities: `grep`, `awk`, `sed`, `mktemp`

## File Structure Reference

```
ezpz/
├── functions/           # Fish functions (auto-loaded)
│   ├── ezpz.fish       # Main dispatcher
│   ├── _ezpz_colors.fish # Color output functions
│   └── _ezpz_*.fish    # Individual command implementations
├── old/
│   └── ezpz.sh         # Original Zsh version (reference)
├── utils/
│   ├── loot.sh         # Legacy utility script
│   └── weblist_ezpz.txt # Wordlist for web fuzzing
├── README.md           # Installation and usage instructions
└── instructions.md     # Detailed refactoring documentation (Portuguese)
```

## Security Context

This is a defensive security toolkit designed for authorized penetration testing and security assessments. All functions are intended for legitimate security testing purposes within properly scoped engagements.