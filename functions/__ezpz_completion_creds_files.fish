# Complete .txt files with a generic entry count. Filename conventions are
# not reliable, so do not try to guess users/passwords/hashes here.
function __ezpz_completion_creds_files
    for file in (find . -maxdepth 1 -name "*.txt" -type f 2>/dev/null | sort)
        set -l count (awk 'NF && $0 !~ /^[[:space:]]*#/ { n++ } END { print n + 0 }' "$file")
        set -l desc "$count entry"
        if test "$count" -ne 1
            set desc "$count entries"
        end
        printf '%s\t%s\n' (basename -- "$file") "$desc"
    end
end
