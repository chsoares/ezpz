function _ezpz_certspray
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner certspray

    set usage "
Usage: ezpz certspray -t <target> [-d <domain>] [-f <credentials>]

Runs Certipy's ADCS find for every credential in the file and reports the
ESC findings that apply to each user.

  -t, --target    DC IP or hostname (required)
  -d, --domain    Default domain for entries without DOMAIN\\user or user@domain
  -f, --file      Credentials file (default: creds.txt)
  -h, --help      Show this help message

Credential lines are user:password, DOMAIN\\user:password, user@domain:password,
or a 32-character NTLM hash in place of the password.
"

    argparse 't/target=' 'f/file=' 'd/domain=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    if not set -q _flag_target
        ezpz_error "Missing required argument: -t/--target"
        echo $usage
        return 1
    end

    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    set -l target $_flag_target
    set -l creds_file creds.txt
    if set -q _flag_file
        set creds_file $_flag_file
    end

    if not test -f "$creds_file"
        ezpz_error "Credentials file not found: $creds_file"
        return 1
    end

    set -l default_domain ""
    if set -q _flag_domain
        set default_domain $_flag_domain
    else
        set -l resolved (ezpz_resolve_dc $target)
        set default_domain (printf '%s\n' $resolved | awk -F'\t' 'NF >= 3 { print $3; exit }')
        if test -z "$default_domain"
            set -l labels (string split '.' -- $target)
            if test (count $labels) -gt 2
                set default_domain (string join '.' $labels[2..-1])
            end
        end
    end

    set -l c_users
    set -l c_domains
    set -l c_secrets
    set -l c_types
    set -l c_labels

    while read -l line
        set line (string trim -- $line)
        test -z "$line"; and continue
        string match -q '#*' -- $line; and continue

        set -l parts (string split -m1 ':' -- $line)
        set -l raw_user $parts[1]
        set -l secret ""
        if test (count $parts) -gt 1
            set secret $parts[2]
        end

        set -l user $raw_user
        set -l domain ""
        if string match -rq '\\\\' -- $raw_user
            set domain (string split '\\' -- $raw_user)[1]
            set user (string split '\\' -- $raw_user)[2]
        else if string match -q '*@*' -- $raw_user
            set domain (string split '@' -- $raw_user)[2]
            set user (string split '@' -- $raw_user)[1]
        else if test -n "$default_domain"
            set domain $default_domain
        end

        if test -z "$user"; or test -z "$domain"
            ezpz_warn "Skipping credential without a domain: $raw_user"
            continue
        end

        if string match -q 'local*' -- $domain
            ezpz_warn "Skipping local credential for ADCS: $raw_user"
            continue
        end

        set -l kind password
        if string match -qr '^[a-fA-F0-9]{32}$' -- $secret
            set kind hash
        end

        set -a c_users $user
        set -a c_domains $domain
        set -a c_secrets $secret
        set -a c_types $kind
        set -a c_labels "$user@$domain"
    end < $creds_file

    set -l total (count $c_users)
    if test $total -eq 0
        ezpz_error "No usable credentials found in $creds_file"
        return 1
    end

    ezpz_header "Trying $total credentials against ADCS"
    ezpz_cmd "nxc ldap $target -u <USER> -d <DOMAIN> (-p <PASS> | -H <HASH>) -M certipy-find"

    set -l summary_tmp (mktemp)
    trap 'rm -f "$summary_tmp"' EXIT TERM INT

    for i in (seq $total)
        set -l user $c_users[$i]
        set -l domain $c_domains[$i]
        set -l secret $c_secrets[$i]
        set -l kind $c_types[$i]
        set -l label $c_labels[$i]
        set -l tmp (mktemp)

        if test "$kind" = hash
            ezpz_spin_capture $tmp timeout 120 nxc ldap $target -u $user -d $domain -H $secret -M certipy-find
        else
            ezpz_spin_capture $tmp timeout 120 nxc ldap $target -u $user -d $domain -p $secret -M certipy-find
        end
        set -l rc $status

        if test $rc -eq 124
            ezpz_warn "$label: timeout"
            rm -f $tmp
            continue
        end

        if grep -aqE '\[-\].*(STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED|STATUS_ACCOUNT_LOCKED_OUT|STATUS_PASSWORD_EXPIRED)' $tmp
            ezpz_warn "$label: authentication failed"
            rm -f $tmp
            continue
        end

        set -l findings (__ezpz_adcs_parse < $tmp | grep -a '^ESC|' | sed 's/^ESC|//')

        rm -f $tmp

        if test -n "$findings"
            ezpz_info "$label"
            for finding in $findings
                set -l parts (string split '|' -- $finding)
                set -l esc $parts[1]
                set -l scope $parts[2]
                set -l object $parts[3]
                set -l desc $parts[4]
                printf '%-6s %s: %s — %s\n' "$esc" "$scope" "$object" "$desc"
                printf '%s|%s\n' "$esc" "$label" >> $summary_tmp
            end
        end
    end

    ezpz_header "Summary"
    if test -s $summary_tmp
        sort -u $summary_tmp | awk -F'|' '
        {
            users[$1] = users[$1] ? users[$1] ", " $2 : $2
            count[$1]++
        }
        END {
            for (esc in users) {
                if (count[esc] > 3) {
                    print esc "|(multiple users)"
                } else {
                    print esc "|" users[esc]
                }
            }
        }' | sort -V | while read -l entry
            set -l parts (string split '|' -- $entry)
            printf '%-6s %s\n' "$parts[1]" "$parts[2]"
        end
    else
        ezpz_info "No ESC findings."
    end

    rm -f $summary_tmp
    ezpz_success "Done."
end
