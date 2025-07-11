#!/usr/bin/env fish

# Script temporário para testar as funções ezpz
# Execute: source test_ezpz.fish

# Carrega as funções
source functions/ezpz.fish
source functions/ezpz_netscan.fish
source functions/ezpz_webscan.fish

echo (set_color green)"eZpZ functions loaded successfully!"(set_color normal)
echo "You can now test:"
echo "  ezpz"
echo "  ezpz netscan --help"
echo "  ezpz netscan 127.0.0.1"
echo "  ezpz netscan -F 192.168.1.0/24" 