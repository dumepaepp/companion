#!/bin/bash
#
# Advanced Installation Script for the Pentesting Assistant
#
# Features:
# - Pre-flight check and user confirmation
# - Unattended mode (-y flag)
# - Robust root/sudo handling
# - NVIDIA GPU and CUDA check for fine-tuning
# - Interactive .env file generation for secrets
# - Comprehensive logging and dependency verification
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
ENV_FILE=".env"

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

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Pre-flight Checks ---
log_info "Starting the installation script for the Pentesting Assistant."
echo "-----------------------------------------------------------------"
log_info "This script will perform the following actions:"
echo "  1. Detect your OS and install system dependencies (nmap, john, metasploit)."
echo "  2. Check for an NVIDIA GPU and CUDA for fine-tuning capabilities."
echo "  3. Create a Python virtual environment in './${VENV_DIR}'."
echo "  4. Install required Python packages from requirements.txt."
echo "  5. Help you create a '.env' file for your secret keys."
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
    log_info "Script is not run as root. Using 'sudo' for system-wide changes."
    if ! command_exists sudo; then
        log_error "'sudo' command not found. Please run this script as root or install sudo."
    fi
    SUDO_CMD="sudo"
else
    log_info "Script is run as root. 'sudo' is not required."
fi

# --- 2. GPU/CUDA Check for Fine-Tuning ---
log_info "Checking for GPU and CUDA for fine-tuning..."
if command_exists nvidia-smi && nvidia-smi > /dev/null; then
    log_info "NVIDIA GPU detected. Fine-tuning should be possible."
else
    log_warn "No NVIDIA GPU detected. The application will run in CPU mode."
    log_warn "Fine-tuning will be extremely slow or impossible without a compatible GPU."
fi

# --- 3. System Dependency Installation ---
log_info "Installing system dependencies..."

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
    log_error "Could not detect a supported package manager (apt, yum, pacman)."
fi

# Install core tools
PACKAGES="python3 python3-pip python3-venv nmap john"
log_info "Updating package lists and installing: $PACKAGES"
$UPDATE_CMD
$INSTALL_CMD $PACKAGES

# Verify installation
for pkg in $PACKAGES; do
    if ! command_exists $(echo $pkg | sed 's/python3-pip/pip3/' | sed 's/python3-venv/python3/'); then
         log_warn "Verification failed for $pkg. Please install it manually."
    fi
done

# Install Metasploit
if ! command_exists msfconsole; then
    log_info "Installing Metasploit Framework... This might take a while."
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    $SUDO_CMD ./msfinstall
    rm msfinstall
    if ! command_exists msfconsole; then
        log_error "Metasploit installation failed. Please install it manually."
    fi
else
    log_info "Metasploit Framework is already installed."
fi

# --- 4. Python Environment Setup ---
if [ ! -d "$VENV_DIR" ]; then
    log_info "Creating Python virtual environment in './${VENV_DIR}'..."
    python3 -m venv $VENV_DIR
else
    log_info "Virtual environment already exists."
fi

log_info "Activating virtual environment and installing Python packages..."
source ${VENV_DIR}/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
log_info "Python packages installed successfully."

# --- 5. Environment Configuration ---
log_info "Configuring environment..."
if [ -f "$ENV_FILE" ]; then
    log_info ".env file already exists. Skipping creation."
else
    log_info "Creating .env file for environment variables."
    read -p "Enter your desired SECRET_KEY (leave blank for a random key): " secret_key
    if [ -z "$secret_key" ]; then
        secret_key=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
        log_info "Generated a random SECRET_KEY."
    fi
    echo "SECRET_KEY='$secret_key'" > $ENV_FILE

    read -p "Enter your MSF_RPC_PASSWORD: " msf_password
    echo "MSF_RPC_PASSWORD='$msf_password'" >> $ENV_FILE
    log_info "Saved configuration to $ENV_FILE"
fi


# --- 6. Final Instructions ---
echo
echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}      Installation Complete! 🎉                     ${NC}"
echo -e "${GREEN}=====================================================${NC}"
echo
echo -e "${YELLOW}Before you run the application, you MUST:${NC}"
echo
echo -e "  1. Start the Metasploit RPC server in a separate terminal."
echo -e "     (Use the password you just set in the .env file)"
echo -e "     ${GREEN}msfrpcd -P your-metasploit-rpc-password -S${NC}"
echo
echo -e "  2. Activate the virtual environment and load your .env file:"
echo -e "     ${GREEN}source ${VENV_DIR}/bin/activate${NC}"
echo -e "     ${GREEN}export \$(cat .env | xargs)${NC}"
echo
echo -e "  3. Run the application:"
echo -e "     ${GREEN}python3 main.py${NC}"
echo
echo -e "A full log of this installation has been saved to: ${GREEN}${LOG_FILE}${NC}"
echo
