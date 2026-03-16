# Gum UI Migration — Remaining Work

## Context

Branch `gum` partially migrated ezpz from plain `echo`/`read` UI to `gum` interactive elements. Work stopped months ago. Three files are fully/partially migrated (`netscan`, `adscan`, `enumshares`), but the rest still use old patterns. This plan covers all remaining changes.

**Established conventions:**
- Colors: ANSI `5` (magenta) primary, `6` (cyan) secondary, `240` (gray) muted
- Spinners: `ezpz_spin` wraps blocking commands with `--show-output`
- Inputs: `ezpz_input "placeholder"`, `ezpz_choose_one`, `ezpz_choose_many`, `ezpz_confirm`
- Piped commands: spin base command → temp file → post-process file

---

## Priority 1: Replace Old `read` Patterns (broken UX)

### 1a. `functions/_ezpz_enumsqli.fish` — 3x `bash -c 'read'` → `ezpz_input`

**Line 94-99** — database selection:
```fish
# BEFORE
ezpz_question "Select database (all/current/name) [current]: "
set db_choice (bash -c 'read -r input; echo "$input"')

# AFTER
ezpz_question "Select database (all/current/name) [current]: "
set db_choice (ezpz_input "current")
```

**Line 136-141** — table selection:
```fish
# BEFORE
ezpz_question "Select tables (all/names): [all] "
set table_choice (bash -c 'read -r input; echo "$input"')

# AFTER
ezpz_question "Select tables (all/names): [all] "
set table_choice (ezpz_input "all")
```

**Line 166-171** — column selection:
```fish
# BEFORE
ezpz_question "Select columns (all/names): [all] "
set column_choice (bash -c 'read -r input; echo "$input"')

# AFTER
ezpz_question "Select columns (all/names): [all] "
set column_choice (ezpz_input "all")
```

Note: `ezpz_input` shows the placeholder as the default hint. The existing empty-check + default assignment logic stays as-is.

### 1b. `functions/_ezpz_selfrelay.fish` — `while/read` loop → `ezpz_confirm`

**Lines 125-138:**
```fish
# BEFORE
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

# AFTER
ezpz_question "Proceed with coercion attack?"
if not ezpz_confirm
    ezpz_warn "Attack cancelled by user"
    return 0
end
```

---

## Priority 2: Add `ezpz_spin` to Long-Running Commands

General pattern for piped commands:
```fish
# Spin the base command to a temp file, then post-process
set _tmp (mktemp)
ezpz_spin <command> > $_tmp
cat $_tmp | grep ... | cut ... | tee $output
rm -f $_tmp
```

### 2a. `functions/_ezpz_webscan.fish`
- Wrap `whatweb` calls with `ezpz_spin whatweb -a3 -v "$url"`
- **Do NOT wrap `ffuf`** — it has its own interactive TUI progress

### 2b. `functions/_ezpz_checkvulns.fish`
- 9 nxc module checks inside `_check_single_target` (spooler, webdav, ms17-010, zerologon, printnightmare, nopac, coerce, remove-mic, smbghost, badsuccessor)
- Each follows: `timeout N nxc ... -M module | grep | cut`
- Wrap each with spinner → temp file → grep/cut the temp file
- Declare `set _chk_tmp (mktemp)` once at top, reuse, `rm -f` at end
- Leave the initial `set smb_test_output (timeout ... nxc ...)` unchanged (quick connectivity probe in command substitution)

### 2c. `functions/_ezpz_enumnull.fish`
- RID brute (`nxc smb --rid-brute`): spinner → temp file → grep/cut/tee
- Groups (`timeout 60 nxc ldap --groups`): spinner → temp file
- Password policy (`timeout 60 nxc smb --pass-pol`): spinner → temp file
- Shares (`timeout 60 nxc smb --shares`): spinner → temp file
- Timeroast (`nxc smb -M timeroast`): spinner → temp file
- pre2k: spinner → temp file
- Leave `GetNPUsers.py` command substitution unchanged

### 2d. `functions/_ezpz_enumdomain.fish` (largest file, ~12 calls)
- RID brute, users fallback, groups, admin-count, user descriptions: spinner → temp file
- `GetNPUsers.py` / `GetUserSPNs.py` with `-outputfile`: `ezpz_spin` wraps the call directly (hash files written by impacket, stdout shown via `--show-output`)
- Timeroast, pre2k, kerbrute, ADCS, DC list, MAQ: spinner → temp file
- `nxc ldap --bloodhound`: spinner → temp file → grep temp file for zip path
- GPP (2 nxc calls), bloodyAD DNS dump: spinner → temp file
- Leave `findDelegation.py` command substitution unchanged

### 2e. `functions/_ezpz_enumshares.fish` (already has gum prompts, missing spinners)
- `nxc smb --shares` (line ~137): spinner → temp file → grep/cut to `$shares_tmp`
- `nxc smb --spider` (line ~264): spinner → temp file → grep/cut/tee
- `nxc smb -M slinky` (line ~231): spinner → temp file → grep
- **Do NOT wrap `manspider`** — has its own live progress output

### 2f. `functions/_ezpz_getloot.fish`
- `secretsdump.py`: `ezpz_spin secretsdump.py $args > /dev/null` (output already discarded)
- nxc WinRM/SMB data collection calls (~6): spinner → temp file → tail/cut/grep

### 2g. `functions/_ezpz_credspray.fish`
- `kerbrute passwordspray` inside loop: spinner → temp file → grep per iteration

### 2h. `functions/_ezpz_testcreds.fish`
- `timeout 60s nxc $protocol` calls in loop (2 per iteration: normal + local-auth): spinner → temp file → grep/awk/string replace

---

## Priority 3: Interactive Menu (optional)

### 3a. `functions/ezpz.fish` — `ezpz_show_menu`
- Replace static `echo` command list with `gum choose`-based interactive picker
- On selection: print `ezpz <choice> --help` hint (commands need args, can't auto-launch)

---

## Files Modified (in implementation order)

1. `functions/_ezpz_selfrelay.fish` — smallest change
2. `functions/_ezpz_enumsqli.fish` — 3 input replacements
3. `functions/_ezpz_webscan.fish` — whatweb spinner only
4. `functions/_ezpz_enumshares.fish` — add spinners to existing gum file
5. `functions/_ezpz_credspray.fish` — single loop spinner
6. `functions/_ezpz_getloot.fish` — secretsdump + nxc spinners
7. `functions/_ezpz_testcreds.fish` — protocol loop spinners
8. `functions/_ezpz_checkvulns.fish` — 9 module check spinners
9. `functions/_ezpz_enumnull.fish` — multiple spinners
10. `functions/_ezpz_enumdomain.fish` — largest, ~12 spinners
11. `functions/ezpz.fish` — interactive menu (optional)

## Edge Cases

| Scenario | Decision |
|---|---|
| `ffuf` / `manspider` | No spinner — own TUI progress |
| Command substitution `set x (cmd)` | No spinner — must capture stdout |
| `secretsdump.py > /dev/null` | Simple `ezpz_spin ... > /dev/null` |
| `timeout N cmd` | `ezpz_spin timeout N cmd` works fine |

## Verification

- Test each modified function against a lab target (or `--help` for syntax)
- Verify spinners show and output is preserved after spinner exits
- Verify `ezpz_input` returns user text and falls back to default on empty
- Verify `ezpz_confirm` yes/no works in selfrelay
- Verify piped post-processing still produces correct filtered output
