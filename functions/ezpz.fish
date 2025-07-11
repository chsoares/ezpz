function ezpz
    set -l commands netscan webscan secretsparse loot checkvulns adscan testcreds enumdomain enumuser enumshares enumsql

    if test (count $argv) -eq 0
        ezpz_show_menu
        return 0
    end

    set -l subcmd $argv[1]
    set -e argv[1]

    # Get EZPZ_HOME
    if not set -q EZPZ_HOME
        ezpz_error "EZPZ_HOME environment variable not set. Please set it to the ezpz installation directory."
        return 1
    end

    if contains -- $subcmd $commands
        set -l func_name ezpz_$subcmd
        if functions -q $func_name
            $func_name $argv
            return $status
        else
            ezpz_error "Function '$func_name' not found."
            return 127
        end
    else
        ezpz_error "Unknown command: $subcmd"
        ezpz_show_menu
        return 1
    end
end

function ezpz_show_menu
    echo ''
    echo '                |    '(set_color magenta --bold)'  __|   __|    \     \ | '(set_color normal)
    echo ' \ \  \ /  -_)   _ \ '(set_color magenta --bold)'\__ \  (      _ \   .  | '(set_color normal)
    echo '  \_/\_/ \___| _.__/ '(set_color magenta --bold)'____/ \___| _/  _\ _|\_|  '(set_color normal)
    echo ''
    echo (set_color cyan --bold)"ezpz CTF Scripts - v0.fish 🍣"(set_color normal)
    echo ""
    echo (set_color magenta)"Available commands:"(set_color normal)
    echo "  netscan     - Network discovery and port scanning"
    echo "  webscan     - Web enumeration with whatweb and ffuf"
    echo "  adscan      - Active Directory enumeration"
    echo "  checkvulns  - Vulnerability assessment"
    echo "  enumdomain  - Domain enumeration"
    echo "  enumuser    - User enumeration"
    echo "  enumshares  - Share enumeration"
    echo "  enumsql     - SQL Server enumeration"
    echo "  testcreds   - Test credentials against targets"
    echo "  loot        - Extract information from Windows hosts"
    echo "  secretsparse - Parse secretsdump.py output"
    echo ""
    echo (set_color blue)"Usage: ezpz <command> [options]"(set_color normal)
    echo "For help on a specific command: ezpz <command> --help"
end

function ezpz_error
    echo (set_color red --bold)"[!] "$argv(set_color normal)
end 