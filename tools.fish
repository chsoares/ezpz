#!/usr/bin/env fish

# EZPZ Tools Installation Script
# This script installs penetration testing tools required by ezpz toolkit

set -l script_dir (dirname (realpath (status --current-filename)))

# Source color functions
source "$script_dir/functions/_ezpz_colors.fish"
sudo -v > /dev/null

ezpz_banner
ezpz_title "ezpz curated penetration testing packages"

# Function to install yay packages
function install_yay_packages
    set -l packages $argv
    
    if test (count $packages) -gt 0
        ezpz_header "Installing yay packages..."
        for package in $packages
            _ezpz_spin yay -S --needed --noconfirm $package
            if test $status -eq 0
                ezpz_success "$package"
            else
                ezpz_error "Failed to install $package"
            end
        end
    end
end

# Function to install pipx packages
function install_pipx_packages
    set -l packages $argv
    
    if test (count $packages) -gt 0
        ezpz_header "Installing pipx packages..."
        _ezpz_spin pipx ensurepath
        for package in $packages
            _ezpz_spin pipx install $package
            if test $status -eq 0
                ezpz_success "$package"
            else
                ezpz_error "Failed to install $package"
            end
        end
    end
end

# Core ezpz dependencies
install_yay_packages \
    ntp \
    impacket \
    kerbrute-bin \
    pre2k-git \
    nmap \
    fping \
    whatweb \
    ffuf \
    sqlmap \
    responder \
    python-pipx \
    python-krb5

install_pipx_packages \
    bloodyad \
    "git+https://github.com/Pennyw0rth/NetExec"

# Function to install git repositories to /opt
function install_git_repos
    ezpz_header "Installing git repositories..."
    sudo -v >/dev/null
    
    # Create /opt if it doesn't exist
    if not test -d /opt
        sudo mkdir -p /opt
    end
    
    # Change to /opt directory
    cd /opt
    
    # Install krbrelayx (used by some ezpz functions)
    if not test -d /opt/krbrelayx
        _ezpz_spin sudo git clone https://github.com/dirkjanm/krbrelayx.git
        if test $status -eq 0
            sudo chown -R $USER:$USER /opt/krbrelayx
            sudo chmod +x /opt/krbrelayx/*.py
            fish_add_path /opt/krbrelayx/
            ezpz_success "krbrelayx"
        else
            ezpz_error "Failed to install krbrelayx"
        end
    else
        ezpz_success "krbrelayx (already exists)"
    end
end
    
install_git_repos

echo ""
ezpz_title " ezpz tools installation completed!"
echo ""
echo "All required tools have been installed."
echo "You may need to restart your shell for some tools to be available in PATH."