function _ezpz_webscan
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # Usage message
    set usage "
Usage: ezpz webscan <url> [-w/--wordlist <wordlist>] [-e/--extensions <extensions>]
  <url> must be a full URL including http:// or https://.

  -w, --wordlist   Specify a custom wordlist for fuzzing.
                   Default: utils/weblist_ezpz.txt
  -e, --extensions Specify extensions for recursive fuzzing (comma-separated).
                   Default: .php,.aspx,.txt,.html
                   Note: .txt is always included automatically.
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
    set extensions ".php,.aspx,.txt,.html"

    # Argument parsing
    argparse 'w/wordlist=' 'e/extensions=' 'h/help' -- $argv
    or return 1

    if set -q _flag_help
        echo $usage
        return 1
    end

    if set -q _flag_wordlist
        if test -f "$_flag_wordlist"
            set wordlist "$_flag_wordlist"
        else
            ezpz_error "Wordlist not found: $_flag_wordlist"
            return 1
        end
    end

    if set -q _flag_extensions
        # Always ensure .txt is included
        if not echo "$_flag_extensions" | grep -q "\.txt"
            set extensions "$_flag_extensions,.txt"
        else
            set extensions "$_flag_extensions"
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
    set has_subdomain 0
    if test $is_ip -eq 0
        set parts (echo "$host" | tr '.' '\n' | wc -l)
        if test $parts -gt 2
            # More than 2 parts means we likely have a subdomain (e.g., dev.htb.local)
            set has_subdomain 1
            set domain (echo "$host" | cut -d '.' -f 1)
            set tld (echo "$host" | cut -d '.' -f 2-)
        else
            # Only 2 parts, standard domain.tld format
            set domain (echo "$host" | cut -d '.' -f 1)
            set tld (echo "$host" | cut -d '.' -f 2-)
        end
    end

    # Test connectivity
    ezpz_info "Testing connectivity to $url"
    if not curl -s --connect-timeout 10 "$url" >/dev/null 2>&1
        ezpz_warn "Host might not be accessible. Continuing anyway..."
    end

    # Set trap for Ctrl+C

    # Enumeration - WhatWeb
    ezpz_header "Running WhatWeb on $url"
    ezpz_cmd "whatweb -a3 -v \"$url\""
    echo ""
    whatweb -a3 -v "$url"
    echo ""

    # Directory fuzzing
    ezpz_header "Fuzzing for directories"
    ezpz_cmd "ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -c -t 250 -ic -ac -v"
    echo ""
    ffuf -u "$url/FUZZ" -w "$wordlist" -c -t 250 -ic -ac -v 2>/dev/null |
        grep -vE "FUZZ:|-->"
    echo ""

    # Subdomain fuzzing (only for domains, not IPs)
    if test $is_ip -eq 0
        ezpz_header "Fuzzing for subdomains"
        ezpz_cmd "ffuf -u \"$url\" -w \"$wordlist\" -H \"Host: FUZZ.$domain.$tld\" -c -t 250 -ic -ac -v"
        echo ""
        ffuf -u "$url" -w "$wordlist" -H "Host: FUZZ.$domain.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
            grep -vE "URL|-->"
        ezpz_info "Remember to add any discovered subdomain to /etc/hosts :)"
        echo ""

        # Vhost fuzzing (skip if URL already has a subdomain)
        if test $has_subdomain -eq 0
            ezpz_header "Fuzzing for vhosts"
            ezpz_cmd "ffuf -u \"$url\" -w \"$wordlist\" -H \"Host: FUZZ.$tld\" -c -t 250 -ic -ac -v"
            echo ""
            ffuf -u "$url" -w "$wordlist" -H "Host: FUZZ.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
                grep -vE "URL|-->"
            echo ""
        else
            ezpz_info "URL already contains a subdomain ($host). Skipping vhost fuzzing."
            echo ""
        end
    else
        ezpz_warn "Target is an IP. Skipping subdomain and vhost fuzzing."
        echo ""
    end

    # Recursive fuzzing with extensions
    ezpz_header "Fuzzing recursively for file extensions (this might take long!)"
    ezpz_cmd "ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -recursion -recursion-depth 1 -e $extensions -c -t 250 -ic -ac -v"
    echo ""
    ffuf -u "$url/FUZZ" -w "$wordlist" -recursion -recursion-depth 1 -e $extensions -c -t 250 -ic -ac -v 2>/dev/null |
        grep -vE "FUZZ:|-->"
    echo ""

    # Finalization
    ezpz_success "Done."
end 