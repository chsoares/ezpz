#!/usr/bin/env fish

#  ezpz Installation Script
# This script sets up the ezpz penetration testing toolkit environment for Fish shell

set -l script_dir (dirname (realpath (status --current-filename)))

# Source color functions
source "$script_dir/functions/_ezpz_colors.fish"

# Check for required dependencies
if not command -v gum >/dev/null 2>&1; or not command -v ntpdate >/dev/null 2>&1
    if command -v pacman >/dev/null 2>&1
        ezpz_header "Installing required dependencies (gum, ntp)..."
        sudo pacman -S --needed gum ntp
        if test $status -eq 0
            ezpz_success "Dependencies installed successfully"
            ezpz_header "Please run the installation script again"
            exit 0
        else
            ezpz_error "Failed to install dependencies"
            exit 1
        end
    else
        ezpz_warn "This installation script is designed for Arch Linux. For other distributions, please install the 'gum' and 'ntp' packages manually before running this script."
        exit 1
    end
end

ezpz_banner

# Set EZPZ_HOME to current directory
ezpz_header "Setting EZPZ_HOME environment variable..."
set -Ux EZPZ_HOME "$script_dir"
ezpz_success "EZPZ_HOME set to: $EZPZ_HOME"

# Add functions directory to fish_function_path
ezpz_header "Adding functions to Fish function path..."
if not contains "$EZPZ_HOME/functions" $fish_function_path
    set -U fish_function_path "$EZPZ_HOME/functions" $fish_function_path
    ezpz_success "Functions directory added to fish_function_path"
else
    ezpz_success "Functions directory already in fish_function_path"
end

# Add completions directory to fish_complete_path
ezpz_header "Adding completions to Fish completion path..."
if not contains "$EZPZ_HOME/completions" $fish_complete_path
    set -U fish_complete_path "$EZPZ_HOME/completions" $fish_complete_path
    ezpz_success "Completions directory added to fish_complete_path"
else
    ezpz_success "Completions directory already in fish_complete_path"
end

echo ""
ezpz_header "Creating ezpz log directories..."

# Create ~/.ezpz directory for logs
if not test -d "$HOME/.ezpz"
    mkdir -p "$HOME/.ezpz"
    ezpz_success "Created log directory: ~/.ezpz"
else
    ezpz_success "Log directory already exists: ~/.ezpz"
end

echo ""
ezpz_title " ezpz installation completed!"
echo 
echo "Please restart your Fish shell or run:"
ezpz_cmd "exec fish"
echo
echo "Then you can use the 'ezpz' command to get started."
echo "You can also run 'tools.fish' to install the required penetration testing tools."
echo
echo "For help:"
ezpz_cmd "ezpz --help"