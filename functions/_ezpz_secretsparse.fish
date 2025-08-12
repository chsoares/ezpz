function _ezpz_secretsparse
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII art banner
    echo ''
    echo '                                |  '(set_color magenta --bold)'   __|   __|    \     \ | '(set_color normal)
    echo '   -_)  -_)  _ \   -_)   _ \   _|'(set_color magenta --bold)' \__ \  (      _ \   .  | '(set_color normal)
    echo ' \___| \___| .__/ \___| .__/ \__|'(set_color magenta --bold)' ____/ \___| _/  _\ _|\_| '(set_color normal)
    echo '           _|         _|          '
    echo ''

    # Usage message
    set usage "
Usage: ezpz secretsparse <base_filename>
  Parses secretsdump.py output files (.sam, .secrets, .ntds) for user:hash (NTLM)
  and consolidates them into a single, deduplicated .parsed file.

  <base_filename>  The base name of the secretsdump.py output files (e.g., '172.16.1.200-secrets').
                   Files like <base_filename>.sam, <base_filename>.secrets, <base_filename>.ntds
                   are expected in the current directory or ./secretsdump/.
"
    # Argument parsing
    argparse 'h/help' -- $argv
    or begin
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 1
    end

    # Check if base filename was provided
    if test (count $argv) -eq 0
        ezpz_error "Missing base filename parameter."
        echo $usage
        return 1
    end

    # Determine base directory
    set base_dir "."
    if set -q boxpwd
        set base_dir $boxpwd
    end

    set base_filename $argv[1]
    set secretsdump_dir "$base_dir/secretsdump"
    set base_path_secretsdump "$secretsdump_dir/$base_filename"  # Path where secretsdump saves originals
    set output_parsed_file "$base_dir/$base_filename.parsed"     # Final parsed output file in base directory
    set tmp_collection_file (mktemp)                            # Temporary file to collect hashes

    # Create secretsdump directory if it doesn't exist
    if not test -d "$secretsdump_dir"
        mkdir -p "$secretsdump_dir"
        if test $status -ne 0
            ezpz_error "Failed to create directory: $secretsdump_dir"
            return 1
        end
    end

    # Trap to ensure temporary collection file is removed on exit
    trap "rm -f '$tmp_collection_file'" EXIT TERM INT

    ezpz_header "Starting secrets parsing for '$base_filename'..."

    set hashes_found_for_this_run 0

    # --- Process .sam file ---
    if test -f "$base_path_secretsdump.sam"
        ezpz_info "Parsing SAM hashes from $base_path_secretsdump.sam..."
        # Print to screen and redirect to temporary collection file
        cat "$base_path_secretsdump.sam" | awk -F: '{print $1":"$4}' | tee /dev/tty >> "$tmp_collection_file"
        set hashes_found_for_this_run 1
    else
        ezpz_warn "SAM file not found: $base_path_secretsdump.sam"
    end

    # --- Process .secrets file ---
    if test -f "$base_path_secretsdump.secrets"
        ezpz_info "Parsing LSA secrets from $base_path_secretsdump.secrets..."
        # Grep for lines that look like user:id:lm:nt (common secretsdump output)
        # Then awk for user:nt_hash. Print to screen and redirect to temp file.
        cat "$base_path_secretsdump.secrets" | grep -oP '^\w+:\d+:[0-9a-f]{32}:[0-9a-f]{32}' | awk -F: '{print $1":"$4}' | tee /dev/tty >> "$tmp_collection_file"
        set hashes_found_for_this_run 1
    else
        ezpz_warn "SECRETS file not found: $base_path_secretsdump.secrets"
    end

    # --- Process .ntds file ---
    if test -f "$base_path_secretsdump.ntds"
        ezpz_info "Parsing NTDS hashes from $base_path_secretsdump.ntds..."
        # Print to screen and redirect to temporary file
        cat "$base_path_secretsdump.ntds" | awk -F: '{print $1":"$4}' | tee /dev/tty >> "$tmp_collection_file"
        set hashes_found_for_this_run 1
    else
        ezpz_warn "NTDS file not found: $base_path_secretsdump.ntds"
    end

    # --- Final Consolidation ---
    if test $hashes_found_for_this_run -eq 1 -a -s "$tmp_collection_file"
        ezpz_info "Consolidating and deduplicating hashes for '$base_filename'..."
        sort -u "$tmp_collection_file" >> "$output_parsed_file"
        ezpz_cmd "Parsed hashes for '$base_filename' saved to '$output_parsed_file'."
    else
        ezpz_warn "No hashes found or extracted for '$base_filename'."
    end

    # --- Update all-secrets.parsed ---
    ezpz_info "Updating global 'all-secrets.parsed' with all unique hashes..."
    set all_parsed_hashes_file_root "$base_dir/all-secrets.parsed"
    # Find all existing <target>-secrets.parsed files in the base directory
    # Concatenate them, sort -u, and save to all-secrets.parsed
    find "$base_dir" -maxdepth 1 -type f -name "*-secrets.parsed" -print0 | xargs -0 cat 2>/dev/null | sort -u > "$all_parsed_hashes_file_root"
    ezpz_cmd "All unique parsed hashes consolidated and saved to '$all_parsed_hashes_file_root'."

    # Finalization
    ezpz_success "Done."
end 