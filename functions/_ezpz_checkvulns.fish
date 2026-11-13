# Run one nxc vulnerability module with a spinner and a concise result.
function __ezpz_checkvulns_module --argument-names label proto module target
    set -l auth $argv[5..-1]

    ezpz_header $label
    ezpz_cmd "nxc $proto $target $auth -M $module"

    set -l tmp (mktemp)
    ezpz_spin_capture $tmp timeout $timeout_secs nxc $proto $target $auth -M $module
    set -l rc $status
    set -l lines (grep -avE '\[\*\]|\[\+\]|\[-\]|\[!\]' $tmp \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | grep -aiE 'vulnerable|next step|enabled|found|unable to detect|webdav|petitpotam|printerbug|dfscoerce|mseven|coerce|nopac|remove.?mic|smbghost' \
        | grep -avE 'Traceback|File "|^[[:space:]]*[│╭╰]|KDC_ERR|KerberosError|Name or service|Errno|Exception|module:' \
        | sort -u)

    if test $rc -eq 124
        ezpz_warn "Timeout reached while testing $label on $target"
    else if grep -aqE 'KDC_ERR|KerberosError' $tmp
        echo "No result / Kerberos realm or authentication error"
    else if grep -aqE 'Name or service not known|Errno -2' $tmp
        echo "No result / DNS resolution error"
    else if test -n "$lines"
        printf '%s\n' $lines
    else
        echo "No result / not vulnerable"
    end
    rm -f $tmp
end

# BadSuccessor keeps all of its signal on tagged lines: the OS gate is a [-]
# line ("attack not possible"), the hit count is [+], and the only untagged
# line is the trustee SID. The generic filter drops the verdict and keeps the
# SID, which reads like a finding when there is none. So: gate first, and only
# show OU/ACL detail when a Server 2025 DC actually makes the attack possible.
function __ezpz_checkvulns_badsuccessor --argument-names target
    set -l auth $argv[2..-1]

    ezpz_header "BadSuccessor"
    ezpz_cmd "nxc ldap $target $auth -M badsuccessor"

    set -l tmp (mktemp)
    ezpz_spin_capture $tmp timeout $timeout_secs nxc ldap $target $auth -M badsuccessor
    set -l rc $status

    set -l out (sed -E 's/\x1b\[[0-9;]*m//g' $tmp \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | sed -E 's/^\[[^]]*\][[:space:]]*//' \
        | grep -avE '^[[:space:]]*$')

    if test $rc -eq 124
        ezpz_warn "Timeout reached while testing BadSuccessor on $target"
    else if grep -aqE 'KDC_ERR|KerberosError' $tmp
        echo "No result / Kerberos realm or authentication error"
    else if test -z "$out"
        # nxc ldap exits silently with status 0 against a non-DC target, so
        # an empty capture is "wrong host", not "not vulnerable".
        echo "Skipped / target is not a domain controller"
    else if string match -qr 'Found domain controller with operating system Windows Server 2025' -- $out
        echo "VULNERABLE / dMSA abuse possible (Server 2025 DC)"
        printf '%s\n' (printf '%s\n' $out | grep -aiE '^Found domain controller with operating system Windows Server 2025' | sort -u)
        set -l acl (printf '%s\n' $out | grep -aiE ', OU=' | sort -u)
        if test -n "$acl"
            echo "Principals with rights on OUs (candidates to create a dMSA):"
            printf '  %s\n' $acl
        end
    else if string match -qr 'attack not possible' -- $out
        echo "No result / no Server 2025 DC (attack not possible)"
    else
        printf '%s\n' $out | sort -u
    end
    rm -f $tmp
end

function _ezpz_checkvulns
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner checkvulns

    # Usage message
    set usage "
Usage: ezpz checkvulns -t <target> [-d <domain>] -u <user> [-p <password> | -H <hash>] [-k]

  <target>    A single host or a file with one host per line.

  -t, --target    Target IP, hostname, or file containing targets.
  -d, --domain    Domain for authentication (optional).
  -u, --user      Username for authentication.
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
  -h, --help      Show this help message
"
    # Check if nxc is installed
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Parse arguments
    argparse 't/target=' 'u/user=' 'p/password=' 'H/hash=' 'k/kerb' 'd/domain=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    # Check required arguments
    if not set -q _flag_target
        ezpz_error "Missing required argument: -t/--target"
        echo $usage
        return 1
    end

    # Build authentication arguments
    set auth_args
    
    # Only add authentication if user is provided
    if set -q _flag_user
        set -l bare_user $_flag_user
        if string match -q '*\\*' $bare_user
            set bare_user (string split '\\' $bare_user)[2]
        end
        if string match -q '*@*' $bare_user
            set bare_user (string split '@' $bare_user)[1]
        end

        if set -q _flag_kerb
            set -a auth_args -u "$bare_user"
            if set -q _flag_domain
                set -a auth_args -d "$_flag_domain"
            end
        else if set -q _flag_domain
            set -a auth_args -u "$_flag_domain\\$_flag_user"
        else
            set -a auth_args -u "$_flag_user"
        end

        if set -q _flag_password
            set -a auth_args -p "$_flag_password"
        else if set -q _flag_hash
            set -a auth_args -H "$_flag_hash"
        end

        if set -q _flag_kerb
            set -a auth_args -k
            if set -q KRB5CCNAME
                set -a auth_args --use-kcache
                ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
            end
        end

        if set -q _flag_kerb; and not ezpz_kerberos_has_tgt
            ezpz_warn "Kerberos ccache has no TGT; SMB checks may work, but LDAP checks (e.g. badsuccessor) will fail."
        end
    end

    # Time synchronization for Kerberos
    if set -q _flag_kerb -a set -q _flag_target
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo systemctl stop systemd-timesyncd
            sudo ntpdate -u $_flag_target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Set timeout for vulnerability checks
    set -x timeout_secs 180

    function _check_single_target
        set target $argv[1]
        set auth_string $argv[2..-1]

        ezpz_title "Checking for vulnerabilities on $target"

        # Connectivity/auth preflight.
        set smb_test_output (timeout $timeout_secs nxc smb $target $auth_string 2>/dev/null)
        if test (count $auth_string) -eq 0
            if test -z "$smb_test_output"
                ezpz_warn "SMB connection failed for $target (no response). Skipping."
                return
            end
        else
            if test -z "$smb_test_output"
                ezpz_warn "SMB connection failed for $target (no response). Skipping."
                return
            else if not string match -qr '\[\+\]' -- $smb_test_output
                ezpz_warn "SMB authentication failed for $target. Skipping."
                return
            end
        end

        # Passive OS/UBR CVE inventory. This is a lead generator, not a
        # replacement for the active checks below: enum_cve maps the build to
        # known CVEs while each module actually tests exploitability.
        ezpz_header "OS/UBR CVE inventory (passive)"
        ezpz_cmd "nxc smb $target $auth_string -M enum_cve"
        set -l cve_tmp (mktemp)
        ezpz_spin_capture $cve_tmp timeout $timeout_secs nxc smb $target $auth_string -M enum_cve
        set -l cve_rc $status
        set -l cve_lines (grep -aoE 'CVE-[0-9]{4}-[0-9]+.*' $cve_tmp | sed -E 's/[[:space:]]+$//' | sort -u)
        if test $cve_rc -eq 124
            ezpz_warn "Timeout reached while testing CVE inventory on $target"
        else if test -n "$cve_lines"
            printf '%s\n' $cve_lines
        else
            echo "No matching CVEs found."
        end
        rm -f $cve_tmp

        # Spooler enum is intentionally not here: coerce_plus below reports
        # "VULNERABLE, PrinterBug" whenever MS-RPRN actually accepts a
        # coercion, which is the actionable half. "Spooler service enabled" is
        # a coercion-source property, not a host vulnerability -- run
        # `-M spooler` in the recon/coercion phase if the endpoint list (or
        # the nxc DB spooler flag) is needed.
        __ezpz_checkvulns_module "WebDAV Detection" smb webdav $target $auth_string
        __ezpz_checkvulns_module "EternalBlue (MS17-010)" smb ms17-010 $target $auth_string
        __ezpz_checkvulns_module "Zerologon (CVE-2020-1472)" smb zerologon $target $auth_string
        __ezpz_checkvulns_module "PrintNightmare (CVE-2021-34527)" smb printnightmare $target $auth_string

        if test (count $auth_string) -eq 0
            ezpz_header "NoPac (CVE-2021-42278)"
            echo "NoPac requires valid credentials to test. Skipping."
        else
            __ezpz_checkvulns_module "NoPac (CVE-2021-42278)" smb nopac $target $auth_string
        end

        __ezpz_checkvulns_module "Coerce Attacks (PetitPotam, etc.)" smb coerce_plus $target $auth_string
        __ezpz_checkvulns_module "Remove MIC (CVE-2019-1040)" smb remove-mic $target $auth_string
        __ezpz_checkvulns_module "SMBGhost (CVE-2020-0796)" smb smbghost $target $auth_string
        __ezpz_checkvulns_badsuccessor $target $auth_string

        # Host defense posture, at the end after the active vulnerability
        # checks: useful context for whether exploitation would be blocked.
        __ezpz_checkvulns_module "Endpoint protection (AV/EDR)" smb enum_av $target $auth_string
    end

    # Process target(s)
    if test -f "$_flag_target"
        set -l seen
        while read -l target
            set target (string trim -- $target)
            test -z "$target"; and continue
            string match -q '#*' -- $target; and continue
            contains -- $target $seen; and continue
            set -a seen $target
            _check_single_target $target $auth_args
            echo ""
        end < $_flag_target
    else
        _check_single_target $_flag_target $auth_args
    end

    echo
    ezpz_success "Done."
end 