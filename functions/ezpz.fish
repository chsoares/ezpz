function ezpz_get_log_path
    set -l subcmd $argv[1]
    set -l timestamp (date +"%Y%m%d_%H%M%S")
    
    # Determinar diretório base
    if set -q boxpwd
        set log_dir "$boxpwd/ezpz"
    else
        set log_dir "$HOME/.ezpz"
    end
    
    # Criar diretório se não existir
    mkdir -p "$log_dir" 2>/dev/null
    
    echo "$log_dir/$timestamp"_"$subcmd.log"
end

function ezpz
    # Get EZPZ_HOME
    if not set -q EZPZ_HOME
        ezpz_error "EZPZ_HOME environment variable not set. Please set it to the ezpz installation directory."
        return 1
    end

    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    set -l commands netscan webscan secretsparse loot checkvulns adscan testcreds enumnull enumdomain enumuser enumshares enumsqli

    if test (count $argv) -eq 0
        ezpz_show_menu
        return 0
    end

    set -l subcmd $argv[1]
    set -e argv[1]

    if contains -- $subcmd $commands
        set -l func_name _ezpz_$subcmd
        if functions -q $func_name
            set -l log_path (ezpz_get_log_path $subcmd)
            set -l temp_log (mktemp)
            $func_name $argv | tee $temp_log
            set -l exit_status $status
            
            if test $exit_status -eq 0
                mv $temp_log $log_path
                ezpz_info "Log saved to: $log_path"
            else
                rm -f $temp_log
            end
            
            return $exit_status
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
    echo '       __  /' (set_color magenta --bold)'      __  / '(set_color normal)
    echo '   -_)    / ' (set_color magenta --bold)'  _ \    /  '(set_color normal)
    echo ' \___| ____|' (set_color magenta --bold)' .__/ ____| '(set_color normal)
    echo '            ' (set_color magenta --bold)'_|          '(set_color normal)
    echo ''
    ezpz_title "ezpz CTF Scripts - v0.fish 🍣"
    echo ""
    echo "Available commands:"
    echo "  netscan      - Network discovery and port scanning"
    echo "  webscan      - Web enumeration with whatweb and ffuf"
    echo "  adscan       - Active Directory enumeration"
    echo "  checkvulns   - Vulnerability assessment"
    echo "  enumnull     - Initial enumeration via NULL sessions"
    echo "  enumdomain   - Domain enumeration"
    echo "  enumuser     - User enumeration"
    echo "  enumshares   - Share enumeration"
    echo "  enumsqli     - SQL Server enumeration"
    echo "  testcreds    - Test credentials against targets"
    echo "  loot         - Extract information from Windows hosts"
    echo "  secretsparse - Parse secretsdump.py output"
    echo ""
    ezpz_info "Usage: ezpz <command> [options]"
    echo "For help on a specific command: ezpz <command> --help"
end