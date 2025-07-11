# Set EZPZ_HOME to the installation directory
# This should be sourced by Fish shell during startup
set -gx EZPZ_HOME (realpath (dirname (status filename))"/../../") 