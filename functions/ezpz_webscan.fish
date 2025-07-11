function ezpz_webscan
    # Color helper functions
    function ezpz_header
        echo (set_color yellow --bold)"[+] "$argv(set_color normal)
    end
    function ezpz_info_star
        echo (set_color cyan)"[*] "$argv(set_color normal)
    end
    function ezpz_cmd_display
        echo (set_color blue)"[>] "$argv(set_color normal)
    end
    function ezpz_error
        echo (set_color red --bold)"[!] "$argv(set_color normal)
    end
    function ezpz_warning
        echo (set_color blue --bold)"[*] "$argv(set_color normal)
    end

    # Usage message
    set usage "
Usage: ezpz webscan <url> [-w/--wordlist <wordlist>]
  <url> must be a full URL including http:// or https://.

  -w, --wordlist   Specify a custom wordlist for fuzzing.
                   Default: utils/weblist_ezpz.txt
"

    # ASCII art banner
    echo ''
    echo '                |    '(set_color magenta --bold)'  __|   __|    \     \ | '(set_color normal)
    echo ' \ \  \ /  -_)   _ \ '(set_color magenta --bold)'\__ \  (      _ \   .  | '(set_color normal)
    echo '  \_/\_/ \___| _.__/ '(set_color magenta --bold)'____/ \___| _/  _\ _|\_|  '(set_color normal)
    echo ''

    # Variables
    set url ""
    set wordlist "$EZPZ_HOME/utils/weblist_ezpz.txt"

    # Argument parsing
    argparse 'w/wordlist' 'h/help' -- $argv
    or return 1

    if set -q _flag_help
        echo $usage
        return 0
    end

    if set -q _flag_wordlist
        if test -f "$_flag_wordlist"
            set wordlist "$_flag_wordlist"
        else
            ezpz_error "Wordlist not found: $_flag_wordlist"
            return 1
        end
    end

    # Check for exactly one positional argument
    if test (count $argv) -ne 1
        ezpz_error "Missing URL parameter."
        echo $usage
        return 1
    end

    set url $argv[1]

    # URL validation
    if test -z "$url" || not echo "$url" | grep -qE '^https?://'
        ezpz_error "Invalid or missing URL. Please include 'http://' or 'https://'."
        echo $usage
        return 1
    end

    # Prerequisites check
    for tool in whatweb ffuf
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Check if default wordlist exists
    if not test -f "$wordlist"
        ezpz_error "Default wordlist not found: $wordlist"
        return 1
    end

    # Extract host information
    set host (echo "$url" | sed 's|https*://||' | cut -d'/' -f1)
    set is_ip 0
    if echo "$host" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
        set is_ip 1
    end

    # Extract domain and TLD for subdomain/vhost fuzzing
    set domain ""
    set tld ""
    if test $is_ip -eq 0
        set domain (echo "$host" | cut -d '.' -f 1)
        set tld (echo "$host" | cut -d '.' -f 2-)
    end

    # Test connectivity
    ezpz_info_star "Testing connectivity to $url"
    if not curl -s --connect-timeout 10 "$url" >/dev/null 2>&1
        ezpz_warning "Host might not be accessible. Continuing anyway..."
    end

    # Set trap for Ctrl+C
    trap "echo ''" INT

    # Enumeration - WhatWeb
    ezpz_header "Running WhatWeb on $url"
    ezpz_cmd_display "whatweb -a3 -v \"$url\""
    echo ""
    whatweb -a3 -v "$url"
    echo ""

    # Directory fuzzing
    ezpz_header "Fuzzing for directories"
    ezpz_cmd_display "ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -c -t 250 -ic -ac -v"
    echo ""
    ffuf -u "$url/FUZZ" -w "$wordlist" -c -t 250 -ic -ac -v 2>/dev/null |
        grep -vE "FUZZ:|-->"
    echo ""

    # Subdomain fuzzing (only for domains, not IPs)
    if test $is_ip -eq 0
        ezpz_header "Fuzzing for subdomains"
        ezpz_cmd_display "ffuf -u \"$url\" -w \"$wordlist\" -H \"Host: FUZZ.$domain.$tld\" -c -t 250 -ic -ac -v"
        echo ""
        ffuf -u "$url" -w "$wordlist" -H "Host: FUZZ.$domain.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
            grep -vE "URL|-->"
        ezpz_info_star "Remember to add any discovered subdomain to /etc/hosts :)"
        echo ""

        # Vhost fuzzing
        ezpz_header "Fuzzing for vhosts"
        ezpz_cmd_display "ffuf -u \"$url\" -w \"$wordlist\" -H \"Host: FUZZ.$tld\" -c -t 250 -ic -ac -v"
        echo ""
        ffuf -u "$url" -w "$wordlist" -H "Host: FUZZ.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
            grep -vE "URL|-->"
        echo ""
    else
        ezpz_warning "Target is an IP. Skipping subdomain and vhost fuzzing."
        echo ""
    end

    # Recursive fuzzing with extensions
    ezpz_header "Fuzzing recursively for common file extensions (this might take long!)"
    ezpz_cmd_display "ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v"
    echo ""
    ffuf -u "$url/FUZZ" -w "$wordlist" -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v 2>/dev/null |
        grep -vE "FUZZ:|-->"
    echo ""

    # Finalization
    trap - INT
    ezpz_warning "Done."
end 