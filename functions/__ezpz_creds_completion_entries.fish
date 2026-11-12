function __ezpz_creds_completion_entries
    test -f creds.txt; or return
    while read -l line
        set line (string trim -- $line)
        test -z "$line"; and continue
        string match -q '#*' -- $line; and continue

        set -l parts (string split -m1 ':' -- $line)
        test (count $parts) -ge 1; or continue
        set -l identity $parts[1]
        set -l secret ""
        if test (count $parts) -gt 1
            set secret $parts[2]
        end

        set -l user $identity
        set -l domain ""
        if string match -q '*@*' -- $identity
            set user (string split -m1 '@' -- $identity)[1]
            set domain (string split -m1 '@' -- $identity)[2]
        else if string match -rq '\\\\' -- $identity
            set domain (string split -m1 '\\' -- $identity)[1]
            set user (string split -m1 '\\' -- $identity)[2]
        end

        test -n "$user"; or continue
        printf '%s\t%s\t%s\n' "$user" "$domain" "$secret"
    end < creds.txt
end
