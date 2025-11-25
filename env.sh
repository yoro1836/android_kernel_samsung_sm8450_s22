#!/bin/bash

export BLACK='\033[0;30m'
export RED='\033[1;31m'
export UNBOLD_GREEN='\033[0;32m'
export MINT_GREEN='\033[1;92m'
export YELLOW='\033[0;\033m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export BLK='\033[30m'
export GRAY='\033[90m'
export WHITE='\033[0;37m'
export BOLD_WHITE='\033[1;37m'
export LIGHT_YELLOW='\033[1;93m'
export BOLD='\033[1m'
export UNDERLINE='\033[4m'
export RESET='\033[0m'


info() {
    echo -e "${BOLD}${MINT_GREEN}${1}${RESET} ${BOLD}${2}${RESET}"
}

warn() {
    echo -e "${BOLD}${RED}${1}${RESET} ${BOLD}${2}${RESET}" 
}
