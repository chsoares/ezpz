function ezpz
    set -l commands netscan webscan secretsparse loot checkvulns adscan startresponder testcreds enumdomain enumuser enumshares enumsql

    if test (count $argv) -eq 0
        ezpz_show_menu
        return 0
    end

    set -l subcmd $argv[1]
    set -e argv[1]

    if contains -- $subcmd $commands
        set -l func_name ezpz_$subcmd
        if functions -q $func_name
            $func_name $argv
            return $status
        else
            ezpz_error "Função '$func_name' não encontrada."
            return 127
        end
    else
        ezpz_error "Comando desconhecido: $subcmd"
        ezpz_show_menu
        return 1
    end
end

function ezpz_show_menu
    echo ''
    echo '                |    '(set_color magenta --bold)'  __|   __|    \     \ | '(set_color normal)
    echo ' \ \  \ /  -_)   _ \ '(set_color blue)'\__ \  (      _ \   .  | '(set_color normal)
    echo '  \_/\_/ \___| _.__/ '(set_color cyan)'____/ \___| _/  _\ _|\_|  '(set_color normal)
    echo ''
    echo (set_color cyan --bold)"eZpZ Hacking Scripts - Fish Shell Version"(set_color normal)
    echo ""
    echo (set_color magenta)"Comandos disponíveis:"(set_color normal)
    echo "  netscan     - Network discovery and port scanning"
    echo "  webscan     - Web enumeration with whatweb and ffuf"
    echo "  secretsparse - Parse secretsdump.py output"
    echo "  loot        - Extract information from Windows hosts"
    echo "  checkvulns  - Vulnerability assessment"
    echo "  adscan      - Active Directory enumeration"
    echo "  startresponder - Start Responder for LLMNR/NBT-NS"
    echo "  testcreds   - Test credentials against targets"
    echo "  enumdomain  - Domain enumeration"
    echo "  enumuser    - User enumeration"
    echo "  enumshares  - Share enumeration"
    echo "  enumsql     - SQL Server enumeration"
    echo ""
    echo (set_color blue)"Uso: ezpz <comando> [opções]"(set_color normal)
    echo "Para ajuda de um comando específico: ezpz <comando> --help"
end

function ezpz_error
    echo (set_color red --bold)"[!] "$argv(set_color normal)
end 