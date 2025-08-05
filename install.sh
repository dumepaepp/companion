#!/bin/bash
#
# Improved Installation Script for the Pentesting Assistant
#
# Features:
# - Pre-flight check and confirmation
# - Unattended mode (-y flag)
# - Robust root/sudo handling
# - Comprehensive logging to a file
# - OS detection for major Linux families
#

# --- Setup and Initialization ---
set -e # Exit immediately if a command exits with a non-zero status.

# Color codes for better output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

LOG_FILE="pentest-app-install.log"
VENV_DIR="venv"

# --- Logging Functions ---
# Redirect all stdout/stderr to a log file and the console
exec > >(tee -a "$LOG_FILE") 2>&1

log_info() {
    echo -e "${GREEN}[INFO]    $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[WARN]    $1${NC}"
}

log_error() {
    echo -e "${RED}[ERROR]   $1${NC}"
    exit 1
}

# --- Pre-flight Checks ---
log_info "Starting the installation script for the Pentesting Assistant."
echo "-----------------------------------------------------------------"
log_info "This script will perform the following actions:"
echo "  1. Detect your OS and install system dependencies (nmap, john, metasploit)."
echo "  2. Create a Python virtual environment in './${VENV_DIR}'."
echo "  3. Install required Python packages from requirements.txt."
echo "  4. Use 'sudo' for system-wide installations, so you may be prompted for your password."
echo "-----------------------------------------------------------------"

# Unattended mode check
if [[ "$1" != "-y" && "$1" != "--yes" ]]; then
    read -p "Do you want to continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Installation cancelled by user."
    fi
fi

# --- 1. Sudo and Root Handling ---
SUDO_CMD=""
if [ "$(id -u)" -ne 0 ]; then
    log_info "Script is not run as root. Using 'sudo'."
    if ! command -v sudo >/dev/null 2>&1; then
        log_error "'sudo' command not found. Please run this script as root or install sudo."
    fi
    SUDO_CMD="sudo"
else
    log_info "Script is run as root. 'sudo' is not required."
fi

# --- 2. System Dependency Check & Installation ---
log_info "Checking for and installing system dependencies..."

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect package manager
if command_exists apt-get; then
    UPDATE_CMD="$SUDO_CMD apt-get update"
    INSTALL_CMD="$SUDO_CMD apt-get install -y"
elif command_exists yum; then
    UPDATE_CMD="$SUDO_CMD yum check-update"
    INSTALL_CMD="$SUDO_CMD yum install -y"
elif command_exists pacman; then
    UPDATE_CMD="$SUDO_CMD pacman -Syu"
    INSTALL_CMD="$SUDO_CMD pacman -S --noconfirm"
else
    log_error "Could not detect a supported package manager (apt, yum, pacman). Please install dependencies manually."
fi

# List of required packages
PACKAGES="python3 python3-pip python3-venv nmap john"

# Install dependencies
log_info "Updating package lists..."
$UPDATE_CMD

log_info "Installing packages: $PACKAGES"
$INSTALL_CMD $PACKAGES

# Special installation for Metasploit Framework
if ! command_exists msfconsole; then
    log_info "Installing Metasploit Framework... This might take a while."
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    $SUDO_CMD ./msfinstall
    if [ $? -ne 0 ]; then
        log_error "Metasploit installation failed. Please install it manually from the Rapid7 website."
    fi
    log_info "Cleaning up Metasploit installer..."
    rm msfinstall
else
    log_info "Metasploit Framework is already installed."
fi


# --- 3. Python Virtual Environment Setup ---
if [ ! -d "$VENV_DIR" ]; then
    log_info "Creating Python virtual environment in './${VENV_DIR}'..."
    python3 -m venv $VENV_DIR
    if [ $? -ne 0 ]; then
        log_error "Failed to create Python virtual environment."
    fi
else
    log_info "Virtual environment already exists."
fi

# --- 4. Activate Virtual Environment & Install Python Packages ---
log_info "Activating virtual environment and installing Python packages..."
source ${VENV_DIR}/bin/activate

pip install --upgrade pip
if [ $? -ne 0 ]; then
    log_warn "Failed to upgrade pip. Continuing with existing version."
fi

pip install -r requirements.txt
if [ $? -ne 0 ]; then
    deactivate
    log_error "Failed to install Python packages. Check requirements.txt and your internet connection."
fi

log_info "Python packages installed successfully."
deactivate # Deactivate after installation

# --- 5. Final Instructions ---
echo
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}      Installation Complete! 🎉                     ${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo
echo -e "${YELLOW}Before you run the application, you MUST:${NC}"
echo
echo -e "  1. Activate the virtual environment:"
echo -e "     ${GREEN}source ${VENV_DIR}/bin/activate${NC}"
echo
echo -e "  2. Set the required environment variables:"
echo -e "     ${GREEN}export SECRET_KEY='a-very-strong-and-random-secret-key'${NC}"
echo -e "     ${GREEN}export MSF_RPC_PASSWORD='your-metasploit-rpc-password'${NC}"
echo
echo -e "  3. Start the Metasploit RPC server in a separate terminal:"
echo -e "     ${GREEN}msfrpcd -P your-metasploit-rpc-password -S${NC}  (Note: -S disables SSL)"
echo
echo -e "  4. Run the application:"
echo -e "     ${GREEN}python3 main.py${NC}"
echo
echo -e "A full log of this installation has been saved to: ${GREEN}${LOG_FILE}${NC}"
echo

