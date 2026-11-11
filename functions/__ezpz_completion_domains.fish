# Completion helper: list real AD domains from adscan output, preferring the
# domain of the -t/--target already present on the command line.
function __ezpz_completion_domains
    set -l domains

    # Primary source: one domain per line from adscan.
    for file in (find . -maxdepth 1 -name "*_domains.txt" -type f 2>/dev/null)
        for line in (cat $file 2>/dev/null | string trim)
            test -n "$line"; or continue
            string match -q '#*' -- $line; and continue
            set -a domains $line
        end
    end

    # Fallback for workspaces created before *_domains.txt existed.
    if test (count $domains) -eq 0
        for file in (find . -maxdepth 1 -name "*_krb5conf.txt" -type f 2>/dev/null)
            for line in (sed -n 's/^[[:space:]]*default_domain[[:space:]]*=[[:space:]]*//p' $file)
                test -n "$line"; and set -a domains $line
            end
        end
    end

    test (count $domains) -gt 0; or return
    set domains (printf '%s\n' $domains | sort -u)

    # Extract -t/--target from the current command line.
    set -l target
    set -l want_target 0
    for token in (commandline -opc)
        if test $want_target -eq 1
            set target $token
            break
        end
        if test "$token" = "-t"; or test "$token" = "--target"
            set want_target 1
        else if string match -q -- '--target=*' $token
            set target (string replace -- '--target=' '' $token)
            break
        end
    end

    set -l preferred
    # A target that is itself a domain wins immediately.
    if test -n "$target"; and contains -- $target $domains
        set preferred $target
    end

    # Otherwise resolve an IP/hostname through adscan's hosts file and pick
    # the longest domain suffix (north.sevenkingdoms.local over sevenkingdoms.local).
    if test -n "$target"; and not test -f "$target"; and test -z "$preferred"
        set -l fqdn
        for file in (find . -maxdepth 1 -name "*_etchosts.txt" -type f 2>/dev/null)
            set -l candidate (awk -v t="$target" '
                BEGIN { t = tolower(t); best = ""; max = 0 }
                /^[ \t]*#/ { next }
                {
                    hit = 0
                    for (i = 1; i <= NF; i++) {
                        if (tolower($i) == t) { hit = 1; break }
                    }
                    if (!hit) next
                    for (i = 1; i <= NF; i++) {
                        if ($i ~ /\./ && length($i) > max) {
                            max = length($i)
                            best = $i
                        }
                    }
                }
                END { print best }
            ' $file)
            if test -n "$candidate"
                set fqdn $candidate
                break
            end
        end

        if test -n "$fqdn"
            for d in $domains
                if test "$fqdn" = "$d"; or string match -q "*.$d" -- $fqdn
                    if test -z "$preferred"; or test (string length $d) -gt (string length $preferred)
                        set preferred $d
                    end
                end
            end
        end
    end

    if test -n "$preferred"
        echo $preferred
    end
    for d in $domains
        test "$d" = "$preferred"; and continue
        echo $d
    end
end
