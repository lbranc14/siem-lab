# 📥 Installation Guide

Complete step-by-step installation guide for the Enterprise SIEM Lab.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Virtual Machine Setup](#virtual-machine-setup)
3. [SIEM Server Installation](#siem-server-installation)
4. [Target System Setup](#target-system-setup)
5. [Attacker System Setup](#attacker-system-setup)
6. [Verification](#verification)
7. [Next Steps](#next-steps)

---

## Prerequisites

### Hardware

- **RAM**: 8 GB minimum, 16 GB recommended
- **Storage**: 60 GB free space minimum
- **CPU**: Quad-core processor (Intel VT-x/AMD-V enabled)

### Software

Download and install:
- [VirtualBox 7.0+](https://www.virtualbox.org/wiki/Downloads)
- [Ubuntu 24.04 LTS ISO](https://ubuntu.com/download/desktop)
- [Kali Linux 2024.4 ISO](https://www.kali.org/get-kali/)

---

## Virtual Machine Setup

### Step 1: Create Host-Only Network

1. Open VirtualBox
2. Go to **File** → **Host Network Manager**
3. Click **Create**
4. Configure:
   - IPv4 Address: `192.168.56.1`
   - IPv4 Network Mask: `255.255.255.0`
   - DHCP Server: **Disabled**
5. Click **Apply**

### Step 2: Create SIEM Server VM

1. **New VM**:
   - Name: `siem-server`
   - Type: Linux
   - Version: Ubuntu (64-bit)
   - RAM: 4096 MB
   - Create virtual hard disk: 50 GB (VDI, Dynamically allocated)

2. **Settings** → **Network**:
   - Adapter 1: Host-only Adapter (`vboxnet0`)

3. **Install Ubuntu 24.04**:
   - Mount ISO
   - Start VM
   - Follow installation wizard
   - Username: `siem`
   - Hostname: `siem-server`

4. **Configure Static IP**:
   ```bash
   sudo nano /etc/netplan/01-netcfg.yaml
   ```
   
   ```yaml
   network:
     version: 2
     ethernets:
       enp0s3:
         addresses:
           - 192.168.56.101/24
         dhcp4: no
   ```
   
   ```bash
   sudo netplan apply
   ip a  # Verify IP
   ```

### Step 3: Create Target VM

1. **New VM**:
   - Name: `ubuntu-target`
   - Type: Linux
   - Version: Ubuntu (64-bit)
   - RAM: 2048 MB
   - Disk: 20 GB (VDI, Dynamically allocated)

2. **Settings** → **Network**:
   - Adapter 1: Host-only Adapter (`vboxnet0`)

3. **Install Ubuntu 24.04**:
   - Mount ISO
   - Start VM
   - Username: `target`
   - Hostname: `ubuntu-target`

4. **Configure Static IP** (`192.168.56.102`):
   ```bash
   sudo nano /etc/netplan/01-netcfg.yaml
   ```
   
   ```yaml
   network:
     version: 2
     ethernets:
       enp0s3:
         addresses:
           - 192.168.56.102/24
         dhcp4: no
   ```
   
   ```bash
   sudo netplan apply
   ```

### Step 4: Create Kali Attacker VM

1. **New VM**:
   - Name: `kali-attacker`
   - Type: Linux
   - Version: Debian (64-bit)
   - RAM: 2048 MB
   - Disk: 30 GB (VDI, Dynamically allocated)

2. **Settings** → **Network**:
   - Adapter 1: Host-only Adapter (`vboxnet0`)

3. **Install Kali Linux 2024.4**:
   - Mount ISO
   - Start VM
   - Username: `kali`
   - Hostname: `kali-attacker`

4. **Configure Static IP** (`192.168.56.103`):
   ```bash
   sudo nano /etc/network/interfaces
   ```
   
   ```
   auto eth0
   iface eth0 inet static
       address 192.168.56.103
       netmask 255.255.255.0
   ```
   
   ```bash
   sudo systemctl restart networking
   ```

### Step 5: Verify Network Connectivity

From each VM:
```bash
# Test connectivity
ping -c 3 192.168.56.101  # SIEM
ping -c 3 192.168.56.102  # Target
ping -c 3 192.168.56.103  # Kali
```

All pings should succeed.

---

## SIEM Server Installation

### Step 1: Update System

```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### Step 2: Install Docker

```bash
# Install prerequisites
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
```

### Step 3: Configure Docker Logging

```bash
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
```

### Step 4: Deploy Wazuh Stack

```bash
# Create project directory
mkdir -p ~/wazuh-docker
cd ~/wazuh-docker

# Clone Wazuh repository
git clone https://github.com/wazuh/wazuh-docker.git -b v4.10.0
cd wazuh-docker/single-node

# Generate SSL certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Start Wazuh stack
docker compose up -d

# Wait for services to start (3-5 minutes)
echo "Waiting for Wazuh to start..."
sleep 180

# Verify services
docker compose ps
```

Expected output:
```
NAME                           STATUS
single-node-wazuh.dashboard-1  Up
single-node-wazuh.indexer-1    Up
single-node-wazuh.manager-1    Up
```

### Step 5: Access Dashboard

Open browser: `https://192.168.56.101`

- **Username**: `admin`
- **Password**: `SecretPassword`

Accept the self-signed SSL warning.

---

## Target System Setup

### Step 1: Install Wazuh Agent

```bash
# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install agent
sudo apt update
sudo apt install -y wazuh-agent
```

### Step 2: Configure Agent

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Find and modify:
```xml
<client>
  <server>
    <address>192.168.56.101</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

### Step 3: Enable File Integrity Monitoring

In the same file, configure `<syscheck>`:
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>

  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/passwd</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/shadow</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/sudoers</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/root/.ssh</directories>
</syscheck>
```

### Step 4: Enable Active Response

Add before `</ossec_config>`:
```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

### Step 5: Start Agent

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

Verify connection:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

Look for: `INFO: Connected to the server`

### Step 6: Install Suricata IDS

```bash
# Install Suricata
sudo apt update
sudo apt install -y suricata

# Check network interface
ip a | grep "192.168.56"
# Note the interface name (e.g., enp0s3)

# Configure Suricata
sudo nano /etc/suricata/suricata.yaml
```

Modify:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: enp0s3  # Your interface
    cluster-id: 99
    cluster-type: cluster_flow
```

```bash
# Update rules
sudo apt install -y suricata-update
sudo suricata-update

# Start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

### Step 7: Install Log Shipper

```bash
# Install Python requests
pip3 install requests --break-system-packages

# Create script
sudo nano /usr/local/bin/log-shipper.py
```

Paste the log-shipper.py code from the main README.

```bash
# Make executable
sudo chmod +x /usr/local/bin/log-shipper.py

# Create systemd service
sudo nano /etc/systemd/system/log-shipper.service
```

```ini
[Unit]
Description=Log Shipper to OpenSearch
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/log-shipper.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable log-shipper
sudo systemctl start log-shipper

# Verify
sudo systemctl status log-shipper
sudo journalctl -u log-shipper -f
```

---

## Attacker System Setup

### Step 1: Install Wazuh Agent (Optional)

Same procedure as Target System, but:
- Configure manager IP: `192.168.56.101`
- Agent name will be `kali-attacker`

### Step 2: Install Attack Tools

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install tools (most are pre-installed on Kali)
sudo apt install -y nmap hydra john metasploit-framework
```

---

## Verification

### Step 1: Check Agent Status

In Wazuh Dashboard:
- Go to **Agents** section
- You should see:
  - Agent 001: `ubuntu-target` (Active)
  - Agent 002: `kali-attacker` (Active, if installed)

### Step 2: Test Log Collection

On Target:
```bash
logger "TEST: SIEM Lab log test"
```

In Wazuh Dashboard:
- **Threat Hunting** → **Events**
- Search for: `"TEST: SIEM Lab"`
- Should appear within 1-2 minutes

### Step 3: Test FIM

On Target:
```bash
sudo useradd testuser
```

In Wazuh Dashboard:
- **Threat Hunting** → **Events**
- Filter: `rule.groups: "syscheck"`
- Should show `/etc/passwd` modification

### Step 4: Test Suricata

From Kali:
```bash
curl http://testmynids.org/uid/index.html
```

On SIEM:
```bash
curl "http://localhost:9200/suricata-alerts-*/_search?size=1&pretty"
```

Should return Suricata alerts.

### Step 5: Test Active Response

From Kali:
```bash
for i in {1..10}; do
  ssh fakeuser@192.168.56.102
  sleep 2
done
```

On Target:
```bash
sudo iptables -L INPUT -n | grep 192.168.56.103
```

Should show DROP rule after 5-6 attempts.

---

## Next Steps

1. **Configure Dashboards**: Import pre-built dashboards from `/dashboards`
2. **Run Attack Scenarios**: Follow scenarios in main README
3. **Customize Rules**: Add custom detection rules
4. **Enable Threat Intelligence**: Configure AbuseIPDB integration
5. **Document Your Setup**: Take screenshots, note configurations

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/yourname/siem-lab/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourname/siem-lab/discussions)

---

**Installation Complete! 🎉**

Your SIEM lab is now ready for attack simulation and defense testing.
