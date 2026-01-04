# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-01

### Added
- Initial release of Enterprise SIEM Lab
- Multi-VM architecture (SIEM Server, Target, Attacker)
- Wazuh 4.10.0 integration with OpenSearch
- File Integrity Monitoring (FIM) on 50+ critical files
- Active Response with automatic IP blocking
- Suricata IDS with 10,000+ Emerging Threats rules
- Custom log-shipper for real-time log forwarding
- Threat Intelligence integration (AbuseIPDB)
- Three professional dashboards:
  - Security Alerts Dashboard
  - Suricata IDS Dashboard
  - File Integrity Monitoring Dashboard
- Five validated attack scenarios:
  - SSH Brute-force (MITRE T1110)
  - Network Scanning (MITRE T1046)
  - File Integrity Compromise
  - Suspicious Sudo Commands
  - Persistence via Crontab
- Complete documentation:
  - README.md with architecture and features
  - INSTALL.md with step-by-step setup
  - CONTRIBUTING.md for contributors
  - LICENSE (MIT)
- Docker log rotation configuration
- Automated cleanup scripts

### Performance
- Mean Time to Detect (MTTD): < 5 minutes
- Mean Time to Respond (MTTR): < 30 seconds
- Detection Rate: 100% on tested scenarios
- False Positive Rate: < 5%

### Known Issues
- Vulnerability Detection (CVE scanning) not functional in Docker single-node deployment
- Manual SSL feed downloads required for offline environments
- Docker log saturation possible without proper configuration (documented solution provided)

## [Unreleased]

### Planned
- Vulnerability Detection module activation
- MISP (Malware Information Sharing Platform) integration
- Email alerting via SMTP
- Webhook notifications (Slack, Discord)
- Extended MITRE ATT&CK technique coverage
- Automated attack simulation with Atomic Red Team
- Machine Learning anomaly detection
- Cloud deployment templates (AWS, Azure, GCP)
- Kubernetes orchestration support

### In Progress
- Enhanced documentation with video tutorials
- Pre-configured dashboard exports
- Attack scenario automation scripts

---

## Version History Summary

- **v1.0.0** (2025-01-01): Initial release with core SIEM functionality
