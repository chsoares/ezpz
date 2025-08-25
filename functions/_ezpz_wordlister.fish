function _ezpz_wordlister --description "Generate mutated wordlists for CTF"
    # Source color functions
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    # Check for help flag
    if contains -- --help $argv; or contains -- -h $argv
        ezpz_info "EZPZ Wordlist Generator"
        echo
        echo "Usage: ezpz wordlister [options] [wordlist_file]"
        echo
        echo "Generate mutated wordlists for CTF with various transformations:"
        echo "  • Capitalization (lower, Title, UPPER)"
        echo "  • Word reversal (password → drowssap)"
        echo "  • Leetspeak (o→0, a→@, e→3, s→\$, i→1)"
        echo "  • Word combinations (user + user, user + default words)"
        echo "  • Numeric suffixes (1-4 digits, years 1980-2030)"
        echo "  • Symbol suffixes (!@#\$%&*-+=)"
        echo
        echo "Options:"
        echo "  -o, --output FILE    Output file (default: input_mutated.txt)"
        echo "  --min LENGTH         Minimum password length (default: 1)"
        echo "  --upper NUM          Minimum uppercase characters (default: 0)"
        echo "  --lower NUM          Minimum lowercase characters (default: 0)"
        echo "  --num NUM            Minimum numbers (default: 0)"
        echo "  --special NUM        Minimum special characters (default: 0)"
        echo "  -F, --fast           Fast mode: -F skips default words, -FF also skips reversal and leetspeak"
        echo "  -h, --help           Show this help"
        echo
        echo "Examples:"
        echo "  ezpz wordlister wordlist.txt"
        echo "  ezpz wordlister -F --min 8 wordlist.txt"
        echo "  ezpz wordlister -FF --min 12 wordlist.txt"
        echo "  ezpz wordlister --min 12 --upper 1 --num 2 wordlist.txt"
        echo "  ezpz wordlister --output custom.txt wordlist.txt"
        return 0
    end
    
    # Check if EZPZ_HOME is set
    if not set -q EZPZ_HOME
        ezpz_error "EZPZ_HOME not set. Please set it to the ezpz directory."
        return 1
    end
    
    # Check if wordlister.py exists
    set wordlister_path "$EZPZ_HOME/utils/wordlister.py"
    if not test -f $wordlister_path
        ezpz_error "wordlister.py not found at $wordlister_path"
        return 1
    end
    
    # Check if Python is available
    if not command -q python3
        ezpz_error "python3 not found. Please install Python 3."
        return 1
    end
    
    # Display starting message
    ezpz_header "Starting wordlist generation..."
    
    # Call the Python script with all arguments
    python3 $wordlister_path $argv
    set python_status $status
    
    # Check if the command was successful
    if test $python_status -eq 0
        ezpz_success "Wordlist generation completed successfully!"
    else
        ezpz_error "Wordlist generation failed!"
        return 1
    end
end