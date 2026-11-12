# Shared target completion helper: IP descriptions come from /etc/hosts.

function __ezpz_completion_ip_description --argument-names ip
    set -l names (awk -v ip="$ip" '
        /^[[:space:]]*#/ { next }
        $1 == ip {
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^#/) break
                print $i
            }
        }
    ' /etc/hosts 2>/dev/null)

    if test (count $names) -eq 0
        echo unknown
        return
    end

    set -l best $names[1]
    for name in $names
        if test (string length -- $name) -lt (string length -- $best)
            set best $name
        end
    end
    echo $best
end

function __ezpz_completion_targets
    set -l include_files 0
    if contains -- --files $argv
        set include_files 1
    end

    set -l ip_files (find . -maxdepth 1 -name "*_ips.txt" -type f 2>/dev/null)

    if test $include_files -eq 1
        for file in $ip_files
            printf '%s\t%s\n' (basename -- "$file") "IP list"
        end
    end

    for file in $ip_files
        while read -l line
            set line (string trim -- $line)
            string match -qr '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -- $line; or continue
            printf '%s\t%s\n' "$line" (__ezpz_completion_ip_description $line)
        end < "$file"
    end
end
