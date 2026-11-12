# special symbols

function ezpz_header
    if set -q __ezpz_header_seen; and test "$__ezpz_header_seen" -eq 1
        echo
    end
    set -g __ezpz_header_seen 1
    echo (set_color yellow --bold)"  "$argv(set_color normal)
end
function ezpz_info
    echo (set_color cyan)"  "$argv(set_color normal)
end
function __ezpz_cmd_quote_arg --argument-names value
    if test -z "$value"
        echo "''"
        return
    end
    if string match -q "'*'" -- $value
        echo $value
        return
    end
    if string match -q '<*' -- $value
        echo $value
        return
    end

    set -l escaped (string replace -a -- "'" "'\\''" $value)
    echo "'$escaped'"
end

function ezpz_cmd
    set -l parts $argv
    set -l from_list 0
    if test (count $parts) -gt 1
        set from_list 1
    else
        set parts (string split -n ' ' -- $parts[1])
    end

    set -l out
    set -l quote_next 0
    set -l auth_flags -u --user --username -p --password --pass -H --hash -hashes --hashes

    for arg in $parts
        if test $quote_next -eq 1
            if test $from_list -eq 0; and string match -q -- '-*' $arg
                set -a out "''"
                set quote_next 0
            else
                set -a out (__ezpz_cmd_quote_arg $arg)
                set quote_next 0
                continue
            end
        end

        set -a out $arg
        if contains -- $arg $auth_flags
            set quote_next 1
        end
    end

    if test $quote_next -eq 1
        set -a out "''"
    end

    echo (set_color blue)"  "(string join -- ' ' $out)(set_color normal)
end
function ezpz_error
    echo (set_color red --bold)"  "$argv(set_color normal)
end
function ezpz_warn
    echo (set_color magenta --bold)"  "$argv(set_color normal)
end
function ezpz_success
    echo (set_color magenta --bold)" "$argv(set_color normal)
end
function ezpz_question
    echo (set_color cyan)"  "$argv(set_color normal)
end
function ezpz_title
    if set -q __ezpz_header_seen; and test "$__ezpz_header_seen" -eq 1
        echo
    end
    set -g __ezpz_header_seen 1
    echo (set_color magenta --bold)"  "$argv(set_color normal)
end


function ezpz_banner
    set -g __ezpz_header_seen 0
    set -l label " ezpz"
    if test (count $argv) -gt 0
        set label "$label $argv"
    end
    set label "$label v0.fish"

    # The dispatcher pipes output through tee, so gum sees a non-TTY and
    # otherwise drops all color. Keep the banner colorful like ctf.fish.
    env CLICOLOR_FORCE=1 gum style --foreground 5 --border-foreground 6 --border rounded --padding "0 4" "$label"
end
function ezpz_input
    gum input --prompt "❯  " --placeholder "$argv" --prompt.foreground 5 --cursor.foreground 6
end
function ezpz_choose_one
    gum choose --limit=1 --cursor.foreground 5 --selected.foreground 6 --cursor "❯ " --header "" $argv
end
function ezpz_choose_many
    gum choose --no-limit --cursor.foreground 5 --selected.foreground 6 --cursor "❯ " --header "" $argv
end

function ezpz_confirm --argument-names prompt
    if test -z "$prompt"
        set prompt "Select option"
    end
    gum confirm "$prompt" --default=false --prompt.foreground 240 --selected.background 5 --selected.foreground 255
end

function ezpz_spin
    set -l verbs "running" "executing" "processing" "computing" "pwning" "exploiting" "hacking" "cracking" "scanning" "enumerating" "fuzzing" "bruteforcing" "rooting" "escalating" "pivoting" "tunneling" "injecting" "dumping" "decrypting" "reverse-engineering" "brewing" "cooking" "dancing" "vibing" "contemplating" "procrastinating" "caffeinating" "debugging life" "yolo-ing" "memeing" "overthinking" "quantum-leaping" "time-traveling" "teleporting" "summoning chaos" "manifesting packets" "channeling energy" "consulting the void" "awakening the machine"
    set -l random_verb $verbs[(math (random) % (count $verbs) + 1)]
    gum spin --spinner minidot --title " $random_verb..." --spinner.foreground 6 --title.foreground 5 --show-output -- $argv
end

# Run a command behind a spinner and capture stdout+stderr in a file. Useful
# when the caller needs to parse the output or show errors afterwards without
# mixing command lines with the spinner.
function ezpz_spin_capture --argument-names outfile
    set -l verbs "running" "executing" "processing" "computing" "pwning" "exploiting" "hacking" "cracking" "scanning" "enumerating" "fuzzing" "bruteforcing" "rooting" "escalating" "pivoting" "tunneling" "injecting" "dumping" "decrypting" "reverse-engineering" "brewing" "cooking" "dancing" "vibing" "contemplating" "procrastinating" "caffeinating" "debugging life" "yolo-ing" "memeing" "overthinking" "quantum-leaping" "time-traveling" "teleporting" "summoning chaos" "manifesting packets" "channeling energy" "consulting the void" "awakening the machine"
    set -l random_verb $verbs[(math (random) % (count $verbs) + 1)]
    gum spin --spinner minidot --title " $random_verb..." --spinner.foreground 6 --title.foreground 5 -- \
        fish --no-config -c 'set out $argv[1]; set -e argv[1]; $argv > $out 2>&1' -- $outfile $argv[2..-1]
end

# Resolve a target IP/hostname to the DC record advertised by a previous
# `ezpz adscan` run. Searches *_etchosts.txt in the current directory first,
# then /etc/hosts. Prints "IP<TAB>FQDN<TAB>DOMAIN" for every match.
function ezpz_resolve_dc --argument-names target
    set -l sources
    set -a sources (find . -maxdepth 1 -name "*_etchosts.txt" -type f 2>/dev/null)
    test -r /etc/hosts; and set -a sources /etc/hosts
    test (count $sources) -gt 0; or return

    awk -v target="$target" '
        BEGIN { t = tolower(target) }
        /^[[:space:]]*#/ { next }
        NF < 2 { next }
        {
            hit = (tolower($1) == t)
            if (!hit) {
                for (i = 2; i <= NF; i++) {
                    if (tolower($i) == t) { hit = 1; break }
                }
            }
            if (hit && $2 ~ /\./) {
                n = split($2, labels, ".")
                domain = labels[2]
                for (j = 3; j <= n; j++) domain = domain "." labels[j]
                print $1 "\t" $2 "\t" domain
            }
        }
    ' $sources 2>/dev/null | sort -u
end

function ezpz_dc_ip --argument-names target
    set -l lookup (ezpz_resolve_dc $target)
    printf '%s\n' $lookup | awk -F'\t' 'NF >= 1 && $1 != "" { print $1; exit }'
end

function ezpz_dc_fqdn --argument-names target
    set -l lookup (ezpz_resolve_dc $target)
    printf '%s\n' $lookup | awk -F'\t' 'NF >= 2 && $2 ~ /\./ { print $2; exit }'
end

function ezpz_kerberos_has_tgt
    klist 2>/dev/null | string match -qr 'krbtgt/'
end

function ezpz_kerberos_principal
    klist 2>/dev/null | awk -F': ' '/Default principal:/ { print $2; exit }'
end

# Warn/abort when the current ccache cannot support the requested protocol.
function ezpz_kerberos_check --argument-names protocol
    if not command -v klist >/dev/null 2>&1
        ezpz_warn "klist not found; cannot inspect the Kerberos ccache."
        return 0
    end

    set -l principal (ezpz_kerberos_principal)
    if test -z "$principal"
        ezpz_error "No Kerberos ccache found. Run getTGT.py/kinit or remove -k."
        return 1
    end

    ezpz_info "Kerberos principal: $principal"
    if not ezpz_kerberos_has_tgt
        ezpz_warn "Kerberos ccache has no TGT (only service tickets)."
        if test "$protocol" = winrm; or test "$protocol" = ldap
            ezpz_error "Kerberos $protocol requires a TGT. Get one with getTGT.py/kinit or use -x smb."
            return 1
        end
    end
    return 0
end




## no special symbols

# function ezpz_header
#     echo (set_color yellow --bold)"[+] "$argv(set_color normal)
# end
# function ezpz_info
#     echo (set_color cyan)"[*] "$argv(set_color normal)
# end
# function ezpz_cmd
#     echo (set_color blue)"[>] "$argv(set_color normal)
# end
# function ezpz_error
#     echo (set_color red --bold)"[!] "$argv(set_color normal)
# end
# function ezpz_warn
#     echo (set_color red)"[-] "$argv(set_color normal)
# end
# function ezpz_success
#     echo (set_color magenta --bold)"[✓] "$argv(set_color normal)
# end
# function ezpz_question
#     echo (set_color cyan)"[?] "$argv(set_color normal)
# end
# function ezpz_title
#     echo (set_color magenta --bold)"[~] "$argv(set_color normal)
# end
