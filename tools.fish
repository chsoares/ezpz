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
            ezpz_spin yay -S --needed --noconfirm $package
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
        ezpz_spin pipx ensurepath
        for package in $packages
            ezpz_spin pipx install $package
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

# Function to install git repositories in the user's local data directory.
# No sudo and no /opt: dependencies stay in a dedicated venv and wrappers are
# exposed through ~/.local/bin, matching the pipx-managed tools.
function install_git_repos
    ezpz_header "Installing git repositories..."

    set -l data_dir "$HOME/.local/share"
    set -l bin_dir "$HOME/.local/bin"
    set -l repo "$data_dir/krbrelayx"
    set -l venv "$repo/.venv"

    mkdir -p $data_dir $bin_dir

    if not test -d "$repo/.git"
        ezpz_spin git clone https://github.com/dirkjanm/krbrelayx.git $repo
        if test $status -ne 0
            ezpz_error "Failed to clone krbrelayx"
            return 1
        end
        ezpz_success "krbrelayx"
    else
        ezpz_success "krbrelayx (already exists)"
    end

    if not test -x "$venv/bin/python"
        ezpz_spin python3 -m venv --system-site-packages $venv
        if test $status -ne 0
            ezpz_error "Failed to create krbrelayx venv"
            return 1
        end
    end

    ezpz_spin "$venv/bin/pip" install --quiet --disable-pip-version-check ldap3-ad-auth
    if test $status -ne 0
        ezpz_error "Failed to install ldap3-ad-auth"
        return 1
    end

    for script in dnstool.py krbrelayx.py addspn.py printerbug.py
        set -l wrapper "$bin_dir/$script"
        printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$venv/bin/python" "$repo/$script" > $wrapper
        chmod +x $wrapper
    end
    ezpz_success "krbrelayx wrappers in $bin_dir"
end
    
install_git_repos

echo ""
ezpz_title " ezpz tools installation completed!"
echo ""
echo "All required tools have been installed."
echo "You may need to restart your shell for some tools to be available in PATH."