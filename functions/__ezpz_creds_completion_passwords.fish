function __ezpz_creds_completion_passwords
    set -l current_user (__ezpz_creds_completion_user)
    test -n "$current_user"; or return
    set -l filter (__ezpz_creds_completion_domain)

    for entry in (__ezpz_creds_completion_entries)
        set -l fields (string split \t -- $entry)
        set -l user $fields[1]
        set -l domain $fields[2]
        set -l secret $fields[3]
        test "$user" = "$current_user"; or continue
        __ezpz_creds_completion_matches $domain $filter; or continue
        string match -qr '^[a-fA-F0-9]{32}$' -- $secret; and continue
        printf '%s\t%s\n' "$secret" (__ezpz_creds_completion_description $domain)
    end
end
