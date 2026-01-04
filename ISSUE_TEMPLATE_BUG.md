---
name: Bug Report
about: Report a bug to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

A clear and concise description of what the bug is.

## 📋 Steps to Reproduce

1. Go to '...'
2. Click on '...'
3. Run command '...'
4. See error

## ✅ Expected Behavior

A clear description of what you expected to happen.

## ❌ Actual Behavior

A clear description of what actually happened.

## 📸 Screenshots

If applicable, add screenshots to help explain your problem.

## 🖥️ Environment

**SIEM Server:**
- OS: [e.g., Ubuntu 24.04]
- Wazuh Version: [e.g., 4.10.0]
- Docker Version: [e.g., 24.0.5]
- RAM: [e.g., 4GB]
- Storage: [e.g., 50GB]

**Target System:**
- OS: [e.g., Ubuntu 24.04]
- Wazuh Agent Version: [e.g., 4.10.0]

**Attacker System:**
- OS: [e.g., Kali Linux 2024.4]

**Network:**
- Configuration: [e.g., VirtualBox Host-Only]
- IP Range: [e.g., 192.168.56.0/24]

## 📝 Logs

Please provide relevant log outputs:

```
Paste logs here
```

**Wazuh Manager logs:**
```bash
docker logs single-node-wazuh.manager-1 --tail 50
```

**Agent logs:**
```bash
sudo tail -50 /var/ossec/logs/ossec.log
```

**Suricata logs (if applicable):**
```bash
sudo tail -50 /var/log/suricata/suricata.log
```

## 🔍 Additional Context

Add any other context about the problem here.

## ✔️ Checklist

- [ ] I have searched existing issues
- [ ] I have checked the documentation
- [ ] I have provided all requested information
- [ ] I have included relevant logs
