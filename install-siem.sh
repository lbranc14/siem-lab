#!/bin/bash

#############################################
# SIEM Lab - Automated Installation Script
# For SIEM Server (Ubuntu 24.04)
#############################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

print_header() {
    echo ""
    echo "======================================"
    echo "$1"
    echo "======================================"
    echo ""
}

# Check if running on Ubuntu
check_os() {
    if [ ! -f /etc/os-release ]; then
        print_error "Cannot determine OS. Exiting."
        exit 1
    fi
    
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        print_error "This script is designed for Ubuntu. Detected: $ID"
        exit 1
    fi
    
    print_success "Running on Ubuntu $VERSION"
}

# Check minimum requirements
check_requirements() {
    print_header "Checking System Requirements"
    
    # Check RAM
    total_ram=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$total_ram" -lt 4 ]; then
        print_error "Insufficient RAM: ${total_ram}GB (minimum 4GB required)"
        exit 1
    fi
    print_success "RAM: ${total_ram}GB"
    
    # Check disk space
    available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 30 ]; then
        print_error "Insufficient disk space: ${available_space}GB (minimum 30GB required)"
        exit 1
    fi
    print_success "Available disk space: ${available_space}GB"
}

# Update system
update_system() {
    print_header "Updating System"
    sudo apt update
    sudo apt upgrade -y
    print_success "System updated"
}

# Install Docker
install_docker() {
    print_header "Installing Docker"
    
    if command -v docker &> /dev/null; then
        print_info "Docker already installed: $(docker --version)"
        return
    fi
    
    # Install prerequisites
    sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
    
    # Add Docker GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    sudo apt update
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Add current user to docker group
    sudo usermod -aG docker $USER
    
    print_success "Docker installed: $(docker --version)"
}

# Configure Docker logging
configure_docker_logging() {
    print_header "Configuring Docker Log Rotation"
    
    sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
EOF
    
    sudo systemctl restart docker
    print_success "Docker logging configured"
}

# Deploy Wazuh
deploy_wazuh() {
    print_header "Deploying Wazuh SIEM Stack"
    
    # Create directory
    mkdir -p ~/wazuh-docker
    cd ~/wazuh-docker
    
    # Clone repository
    if [ ! -d "wazuh-docker" ]; then
        print_info "Cloning Wazuh repository..."
        git clone https://github.com/wazuh/wazuh-docker.git -b v4.10.0
    else
        print_info "Wazuh repository already exists"
    fi
    
    cd wazuh-docker/single-node
    
    # Generate certificates
    print_info "Generating SSL certificates..."
    docker compose -f generate-indexer-certs.yml run --rm generator
    
    # Start services
    print_info "Starting Wazuh services (this may take 3-5 minutes)..."
    docker compose up -d
    
    # Wait for services
    print_info "Waiting for services to initialize..."
    sleep 180
    
    # Check status
    docker compose ps
    
    print_success "Wazuh deployed successfully"
}

# Display credentials
display_credentials() {
    print_header "Installation Complete!"
    
    echo ""
    echo "🎉 SIEM Server is ready!"
    echo ""
    echo "📊 Wazuh Dashboard:"
    echo "   URL: https://192.168.56.101"
    echo "   Username: admin"
    echo "   Password: SecretPassword"
    echo ""
    echo "⚠️  Note: You may see an SSL warning (self-signed certificate)"
    echo "    Click 'Advanced' and accept the risk to proceed"
    echo ""
    echo "📝 Next Steps:"
    echo "   1. Install Wazuh agents on target systems"
    echo "   2. Configure File Integrity Monitoring"
    echo "   3. Set up Suricata IDS"
    echo "   4. Run attack scenarios"
    echo ""
    echo "📖 Documentation: See README.md and INSTALL.md"
    echo ""
}

# Main installation flow
main() {
    print_header "SIEM Lab - Automated Installation"
    print_info "This script will install Docker and deploy Wazuh SIEM"
    echo ""
    
    # Ask for confirmation
    read -p "Do you want to continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Installation cancelled"
        exit 1
    fi
    
    check_os
    check_requirements
    update_system
    install_docker
    configure_docker_logging
    deploy_wazuh
    display_credentials
    
    print_success "Installation completed successfully!"
    print_info "You may need to log out and back in for Docker group membership to take effect"
}

# Run main function
main
