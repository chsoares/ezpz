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
    # Resolve EZPZ_HOME from the function file when it is not exported.
    # This makes the dispatcher usable even if the user forgot to export it.
    if not set -q EZPZ_HOME; or not test -d "$EZPZ_HOME"
        set -l self (functions --details ezpz 2>/dev/null)
        if test -n "$self"; and test -f "$self"
            set self (path resolve $self)
            set -gx EZPZ_HOME (path dirname (path dirname $self))
        end
    end

    if not set -q EZPZ_HOME; or not test -d "$EZPZ_HOME"
        echo "EZPZ_HOME is not set and could not be resolved from the ezpz function file." >&2
        echo "Set it with: set -gx EZPZ_HOME /path/to/ezpz" >&2
        return 1
    end

    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    set -l commands netscan webscan secretsparse getloot checkvulns adscan testcreds certspray path enumnull enumdomain enumuser enumshares enumsqli credspray getflag getshell selfrelay

    if test (count $argv) -eq 0
        ezpz_show_menu
        return 1
    end

    set -l subcmd $argv[1]
    set -e argv[1]

    # Help is not a run: do not create a log for `ezpz <cmd> -h`.
    set -l wants_help 0
    if contains -- -h $argv; or contains -- --help $argv
        set wants_help 1
    end

    if contains -- $subcmd $commands
        set -l func_name _ezpz_$subcmd
        if functions -q $func_name
            if test $wants_help -eq 1
                $func_name $argv
                return $status
            end

            set -l log_path (ezpz_get_log_path $subcmd)
            set -l temp_log (mktemp)
            $func_name $argv | tee $temp_log
            # $status is tee's status; the function's status is pipestatus[1].
            set -l exit_status $pipestatus[1]
            
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
    ezpz_banner
    echo ""
    ezpz_info "Available commands"

    # Single source of truth for the menu: <category>|<command>|<description>.
    # Every command the dispatcher accepts must have a row here, otherwise it
    # silently disappears from the help.
    set -l sections \
        "Recon|netscan|Network discovery and port scanning" \
        "Recon|webscan|Web enumeration with whatweb and ffuf" \
        "Recon|adscan|Active Directory discovery" \
        "Enumeration|enumnull|Unauthenticated enumeration via NULL sessions" \
        "Enumeration|enumdomain|Domain enumeration" \
        "Enumeration|enumuser|User and permission enumeration" \
        "Enumeration|enumshares|SMB share enumeration" \
        "Enumeration|enumsqli|SQL injection enumeration with sqlmap" \
        "Enumeration|checkvulns|SMB and AD vulnerability checks" \
        "Access|testcreds|Test credentials against targets" \
        "Access|credspray|Kerberos password spraying via kerbrute" \
        "Access|certspray|Spray credentials against ADCS" \
        "Access|selfrelay|NTLM self-relay attack chain" \
        "Access|path|One-hop AD attack paths from BloodHound" \
        "Post-Exploit|getloot|Extract information from Windows hosts" \
        "Post-Exploit|getflag|Read flags from compromised hosts" \
        "Post-Exploit|getshell|Get reverse shell from compromised hosts" \
        "Post-Exploit|secretsparse|Parse secretsdump.py output"

    set -l current_category
    for entry in $sections
        set -l fields (string split -m 2 -- '|' $entry)
        if test "$fields[1]" != "$current_category"
            set current_category $fields[1]
            echo ""
            # Two leading spaces put the category symbol on the same column as
            # the first character of the command lines below it.
            echo -n "  "
            ezpz_cmd $current_category
        end
        printf '  %-14s %s\n' $fields[2] $fields[3]
    end

    echo ""
    ezpz_info "Usage: ezpz <command> [options]"
    echo "For help on a specific command: ezpz <command> --help"
end