# 🔧 Troubleshooting Guide

Common issues and solutions encountered when deploying the SIEM Lab.

---

## Table of Contents

- [VM Issues](#vm-issues)
- [Docker Issues](#docker-issues)
- [Wazuh Issues](#wazuh-issues)
- [Network Issues](#network-issues)
- [Suricata Issues](#suricata-issues)
- [Active Response Issues](#active-response-issues)
- [Dashboard Issues](#dashboard-issues)

---

## VM Issues

### Issue 1: VM Fails to Boot - Black Screen

**Symptom**: VM shows black screen on startup, cannot access system.

**Cause**: Disk space saturation (100% full), typically caused by Docker logs.

**Solution**:

1. **Boot in Recovery Mode**:
   - Restart VM
   - Press and hold **Shift** during boot
   - Select **Advanced options** → **Recovery mode**
   - Select **root** (Drop to root shell prompt)

2. **Mount filesystem as read-write**:
   ```bash
   mount -o remount,rw /
   ```

3. **Check disk usage**:
   ```bash
   df -h
   ```

4. **Clean Docker logs**:
   ```bash
   rm -rf /var/lib/docker/containers/*/*-json.log
   ```

5. **Clean journald logs**:
   ```bash
   journalctl --vacuum-time=1d
   ```

6. **Reboot**:
   ```bash
   reboot
   ```

7. **Configure log rotation permanently** (see [Docker Log Saturation](#issue-2-docker-log-saturation))

---

### Issue 2: VirtualBox "VERR_UNRESOLVED_ERROR"

**Symptom**: 
```
Unresolved (unknown) host platform error. (VERR_UNRESOLVED_ERROR)
Result Code: E_FAIL (0x80004005)
Component: ConsoleWrap
Interface: IConsole
```

**Causes**: 
- Corrupted VM state
- Network adapter conflict
- Multiple VMs trying to use same Host-Only adapter
- 3D acceleration conflicts

**Solutions**:

**Solution A: Discard corrupted state**
```powershell
# PowerShell (Windows)
cd "C:\Program Files\Oracle\VirtualBox"
.\VBoxManage.exe discardstate "vm-name"
.\VBoxManage.exe startvm "vm-name" --type gui
```

**Solution B: Reset network configuration**
```powershell
# Stop VM
.\VBoxManage.exe controlvm "vm-name" poweroff

# Reset all network adapters
.\VBoxManage.exe modifyvm "vm-name" --nic1 none
.\VBoxManage.exe modifyvm "vm-name" --nic2 none
.\VBoxManage.exe modifyvm "vm-name" --nic3 none
.\VBoxManage.exe modifyvm "vm-name" --nic4 none

# Reconfigure Host-Only adapter
.\VBoxManage.exe modifyvm "vm-name" --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter"

# Start VM
.\VBoxManage.exe startvm "vm-name" --type gui
```

**Solution C: Disable problematic features**
```powershell
.\VBoxManage.exe modifyvm "vm-name" --accelerate3d off
.\VBoxManage.exe modifyvm "vm-name" --accelerate2dvideo off
.\VBoxManage.exe modifyvm "vm-name" --cpus 2
```

**Solution D: Start VMs in correct order**
```powershell
# Start SIEM first, wait 60 seconds, then start Target
.\VBoxManage.exe startvm "siem-server" --type gui
Start-Sleep -Seconds 60
.\VBoxManage.exe startvm "ubuntu-target" --type gui
```

---

### Issue 3: VirtualBox "Failed to acquire VirtualBox COM object"

**Symptom**: VirtualBox fails to start with error about corrupted `VirtualBox.xml`.

**Cause**: Corrupted VirtualBox configuration file.

**Solution**:

```powershell
# Close VirtualBox completely
taskkill /F /IM VirtualBox.exe
taskkill /F /IM VBoxSVC.exe

# Backup and delete corrupted config
cd C:\Users\<username>\.VirtualBox
copy VirtualBox.xml VirtualBox.xml.backup
del VirtualBox.xml

# Restart VirtualBox (creates new config)
# Then re-import VMs: Machine → Add → select .vbox files
```

---

## Docker Issues

### Issue 4: Docker Log Saturation

**Symptom**: Disk fills up rapidly (30+ GB of logs), system becomes unresponsive.

**Cause**: Docker containers generate unlimited logs without rotation by default.

**Solution**:

1. **Configure log rotation**:
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
   ```

2. **Restart Docker**:
   ```bash
   sudo systemctl restart docker
   ```

3. **Clean existing logs**:
   ```bash
   docker system prune -af --volumes
   ```

4. **Set up automated cleanup** (weekly cron job):
   ```bash
   (crontab -l 2>/dev/null; echo "0 3 * * 0 docker system prune -af --volumes") | crontab -
   ```

**Result**: Limits Docker logs to 150 MB per container (3 files × 50 MB).

---

### Issue 5: Docker Containers Reset Configuration

**Symptom**: Configuration changes in `ossec.conf` are lost after container restart.

**Cause**: Docker containers reset to image state on restart unless volumes are mounted.

**Solution**:

**Option A: Edit directly in running container**
```bash
# Enter container
docker exec -it single-node-wazuh.manager-1 bash

# Install text editor
dnf install -y nano

# Edit configuration
nano /var/ossec/etc/ossec.conf

# Restart Wazuh service (NOT container)
/var/ossec/bin/wazuh-control restart

# Exit container
exit
```

**Option B: Mount configuration as volume**

Edit `docker-compose.yml`:
```yaml
services:
  wazuh.manager:
    volumes:
      - ./config/ossec.conf:/var/ossec/etc/ossec.conf:ro
```

---

## Wazuh Issues

### Issue 6: Wazuh Agent Not Connecting

**Symptom**: Agent status shows "Never connected" or "Disconnected" in Dashboard.

**Diagnosis**:

```bash
# On Agent
sudo systemctl status wazuh-agent
sudo tail -50 /var/ossec/logs/ossec.log

# On Manager
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

**Common Causes & Solutions**:

**A. Wrong Manager IP in agent config**

```bash
# On Agent
sudo nano /var/ossec/etc/ossec.conf
```

Verify:
```xml
<client>
  <server>
    <address>192.168.56.101</address>  <!-- Correct Manager IP -->
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

```bash
sudo systemctl restart wazuh-agent
```

**B. Network connectivity issues**

```bash
# Test connectivity
ping -c 3 192.168.56.101
nc -zv 192.168.56.101 1514
telnet 192.168.56.101 1514
```

If no connectivity, check:
- VirtualBox Host-Only network configuration
- Static IP configuration (`/etc/netplan/01-netcfg.yaml`)
- Firewall rules

**C. Agent not started**

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

---

### Issue 7: Active Response Not Blocking IPs

**Symptom**: Brute-force attacks detected but attacker IP not blocked.

**Diagnosis**:

```bash
# On Target (Agent)
sudo tail -f /var/ossec/logs/active-responses.log
sudo iptables -L INPUT -n -v
```

**Common Causes & Solutions**:

**A. Active Response not configured on Manager**

```bash
# On SIEM Server (inside Wazuh Manager container)
docker exec -it single-node-wazuh.manager-1 bash
nano /var/ossec/etc/ossec.conf
```

Add before `</ossec_config>`:
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5712,5720</rules_id>
  <timeout>600</timeout>
</active-response>
```

```bash
/var/ossec/bin/wazuh-control restart
exit
```

**B. Active Response disabled on Agent**

```bash
# On Target
sudo nano /var/ossec/etc/ossec.conf
```

Ensure:
```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

```bash
sudo systemctl restart wazuh-agent
```

**C. Rules not triggering**

Check if brute-force rule is firing:
```bash
# On Manager
docker exec single-node-wazuh.manager-1 tail -100 /var/ossec/logs/alerts/alerts.log | grep -i "brute\|authentication"
```

---

### Issue 8: FIM Not Detecting File Changes

**Symptom**: File modifications not generating alerts.

**Diagnosis**:

```bash
# On Agent
sudo tail -f /var/ossec/logs/ossec.log | grep -i syscheck
```

**Common Causes & Solutions**:

**A. FIM disabled**

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Check:
```xml
<syscheck>
  <disabled>no</disabled>  <!-- Must be "no" -->
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>
</syscheck>
```

**B. Files not monitored**

Verify directories are configured:
```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/etc/passwd</directories>
<directories realtime="yes" check_all="yes" report_changes="yes">/etc/shadow</directories>
```

**C. Need to wait for scan**

FIM scans every 5 minutes by default. Force immediate scan:
```bash
sudo systemctl restart wazuh-agent
```

**D. Changes happened before FIM enabled**

FIM only detects changes AFTER it's enabled. Make a NEW change:
```bash
sudo useradd testuser-$(date +%s)
```

---

### Issue 9: Vulnerability Detection Not Working

**Symptom**: No vulnerabilities detected in Dashboard.

**Cause**: Vulnerability Detection module not available in Docker single-node deployment (Wazuh 4.10.0).

**Explanation**: 
The `vulnerability-scanner` binary is not included in the lightweight Docker single-node container. This module requires the full installation or multi-node deployment.

**Workaround**: 
Focus on other detection capabilities (FIM, Active Response, Suricata, Threat Intelligence). Vulnerability scanning is a "nice-to-have" but not essential for demonstrating SIEM capabilities.

**Alternative**: 
For a production environment, deploy Wazuh using the distributed architecture or install directly on the host OS instead of Docker.

---

## Network Issues

### Issue 10: Static IP Not Persisting

**Symptom**: VM loses its static IP after reboot, gets DHCP address or no IP.

**Solution**:

```bash
# Check netplan config
sudo nano /etc/netplan/01-netcfg.yaml
```

Correct configuration:
```yaml
network:
  version: 2
  ethernets:
    enp0s3:  # Your interface name (check with: ip a)
      addresses:
        - 192.168.56.102/24
      dhcp4: no
```

Apply:
```bash
sudo netplan apply
```

Verify:
```bash
ip a | grep 192.168.56
```

Make it permanent:
```bash
sudo chmod 600 /etc/netplan/01-netcfg.yaml
```

---

### Issue 11: VMs Cannot Communicate

**Symptom**: `ping 192.168.56.101` fails between VMs.

**Diagnosis**:

```bash
# Check IP configuration
ip a

# Check route
ip route

# Check if interface is up
ip link show
```

**Common Causes & Solutions**:

**A. Wrong network adapter in VirtualBox**

- VirtualBox → VM → Settings → Network
- Adapter 1: **Host-only Adapter**
- Name: **VirtualBox Host-Only Ethernet Adapter**

**B. Host-Only network not configured**

VirtualBox → File → Host Network Manager:
- Create new adapter if none exists
- IPv4 Address: `192.168.56.1`
- IPv4 Network Mask: `255.255.255.0`
- DHCP Server: **Disabled**

**C. Firewall blocking**

```bash
# Temporarily disable firewall for testing
sudo ufw disable

# If it works, add proper rules
sudo ufw allow from 192.168.56.0/24
sudo ufw enable
```

---

## Suricata Issues

### Issue 12: Suricata Not Generating Alerts

**Symptom**: No alerts in `/var/log/suricata/eve.json` or OpenSearch.

**Diagnosis**:

```bash
sudo systemctl status suricata
sudo tail -f /var/log/suricata/suricata.log
sudo tail -f /var/log/suricata/eve.json
```

**Common Causes & Solutions**:

**A. Wrong network interface configured**

```bash
# Check your interface name
ip a

sudo nano /etc/suricata/suricata.yaml
```

Update:
```yaml
af-packet:
  - interface: enp0s3  # Must match your actual interface
    cluster-id: 99
    cluster-type: cluster_flow
```

```bash
sudo systemctl restart suricata
```

**B. Rules not updated**

```bash
sudo suricata-update
sudo systemctl restart suricata
```

**C. Not enough test traffic**

Generate known malicious traffic:
```bash
# From attacker VM
curl http://testmynids.org/uid/index.html
sudo nmap -sS -p 22,80,443 192.168.56.102
```

**D. HOME_NET misconfigured**

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"  # Your lab subnet
    EXTERNAL_NET: "!$HOME_NET"
```

---

### Issue 13: Suricata Service Fails to Start

**Symptom**: `sudo systemctl start suricata` fails.

**Solution**:

```bash
# Check detailed error
sudo journalctl -u suricata -n 50

# Common issue: config syntax error
sudo suricata -T -c /etc/suricata/suricata.yaml

# Fix permissions
sudo chown -R root:root /var/log/suricata
sudo chmod 755 /var/log/suricata
```

---

## Active Response Issues

### Issue 14: IP Blocked But SSH Still Works

**Symptom**: Active Response logs show IP blocked, but attacker can still connect.

**Diagnosis**:

```bash
# Check iptables rules
sudo iptables -L INPUT -n -v | grep DROP

# Check active response logs
sudo tail -f /var/ossec/logs/active-responses.log
```

**Causes**:

**A. Wrong interface**

Active Response blocks on INPUT chain but traffic comes from different interface.

**B. Timeout expired**

Default timeout is 600 seconds (10 minutes). IP automatically unblocked after timeout.

**C. IP whitelisted**

Check Wazuh configuration for whitelisted IPs.

---

## Dashboard Issues

### Issue 15: Dashboard Shows "No Results Found"

**Symptom**: Wazuh Dashboard displays empty visualizations.

**Common Causes & Solutions**:

**A. Wrong time range**

Change time range (top-right):
- Last 15 minutes → **Last 24 hours** or **Last 7 days**

**B. Index pattern missing**

Management → Index Patterns:
- Create: `wazuh-alerts-*` (Time field: `@timestamp`)
- Create: `target-logs-*` (Time field: `@timestamp`)
- Create: `suricata-alerts-*` (Time field: `@timestamp`)

**C. No data indexed yet**

Wait a few minutes for data to be ingested, or generate test events.

**D. Wrong filters applied**

Clear all filters in Dashboard and try again.

---

### Issue 16: Cannot Import Dashboard JSON

**Symptom**: Error when importing saved objects (dashboards, visualizations).

**Solution**:

1. Management → Saved Objects → **Import**
2. If conflicts occur:
   - Select **Automatically overwrite**
   - Or select **Create new objects with random IDs**
3. Refresh browser (Ctrl+F5)

---

## General Tips

### Enable Debug Logging

**Wazuh Agent**:
```bash
sudo nano /var/ossec/etc/local_internal_options.conf
```
Add:
```
# Debug
agent.debug=2
```

```bash
sudo systemctl restart wazuh-agent
sudo tail -f /var/ossec/logs/ossec.log
```

---

### Check Service Status Script

```bash
#!/bin/bash
echo "=== Wazuh Agent ==="
sudo systemctl status wazuh-agent --no-pager | head -5

echo -e "\n=== Suricata ==="
sudo systemctl status suricata --no-pager | head -5

echo -e "\n=== Log Shipper ==="
sudo systemctl status log-shipper --no-pager | head -5

echo -e "\n=== Network ==="
ip a | grep "inet 192.168.56"

echo -e "\n=== Connectivity ==="
ping -c 2 192.168.56.101
```

---

### Reset Everything (Nuclear Option)

If nothing works and you want to start fresh:

```bash
# On Agent
sudo systemctl stop wazuh-agent
sudo systemctl stop suricata
sudo systemctl stop log-shipper
sudo apt remove --purge wazuh-agent suricata -y
sudo rm -rf /var/ossec
sudo rm -rf /var/log/suricata

# On Manager
docker compose down -v
docker system prune -af --volumes
# Then re-deploy from scratch
```

---

## Getting Help

If you encounter an issue not covered here:

1. **Check logs first**:
   - Wazuh: `/var/ossec/logs/ossec.log`
   - Suricata: `/var/log/suricata/suricata.log`
   - Docker: `docker logs <container-name>`
   - System: `journalctl -xe`

2. **Search Wazuh documentation**: https://documentation.wazuh.com

3. **Wazuh community forums**: https://groups.google.com/g/wazuh

4. **GitHub Issues**: Report bugs or request features

---

## Common Error Messages Reference

| Error Message | Likely Cause | Solution |
|---------------|--------------|----------|
| `VERR_UNRESOLVED_ERROR` | VirtualBox VM corruption | Discard state, reset network config |
| `Connection refused (111)` | Service not running or wrong port | Check service status, verify port |
| `Permission denied` | Insufficient privileges | Use `sudo`, check file permissions |
| `Unable to connect to manager` | Network or firewall issue | Check connectivity, verify Manager IP |
| `Invalid element in configuration` | XML syntax error | Validate `ossec.conf` syntax |
| `Failed to start wazuh-agent.service` | Config error or port conflict | Check logs: `journalctl -u wazuh-agent` |
| `No such file or directory` | Missing dependency or wrong path | Verify file exists, check installation |

---

**Last Updated**: January 2025  
**Version**: 1.0.0

For the latest troubleshooting tips, check the [GitHub Issues](https://github.com/yourusername/siem-lab/issues).
