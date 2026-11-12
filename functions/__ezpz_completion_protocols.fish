# Complete comma-separated testcreds protocols, keeping the existing prefix.
function __ezpz_completion_protocols
    set -l token (commandline -ct)
    set -l prefix ""
    set -l selected

    if string match -q '*,*' -- $token
        set prefix (string replace -r ',[^,]*$' ',' -- $token)
        set -l parts (string split ',' -- $token)
        set -e parts[-1]
        set selected $parts
    end

    for entry in \
        'smb|SMB (445)' \
        'winrm|WinRM (5985/5986)' \
        'mssql|MSSQL (1433)' \
        'rdp|RDP (3389)' \
        'ssh|SSH (22)' \
        'ftp|FTP (21)'
        set -l fields (string split -m1 '|' -- $entry)
        set -l protocol $fields[1]
        contains -- $protocol $selected; and continue
        printf '%s%s\t%s\n' "$prefix" "$protocol" "$fields[2]"
    end
end
