# 📁 Repository Structure Guide

This document explains the organization of the SIEM Lab repository.

---

## 📂 Directory Structure

```
siem-lab/
├── README.md                    # Main project documentation
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # Contribution guidelines
├── INSTALL.md                   # Detailed installation guide
├── CHANGELOG.md                 # Version history
├── .gitignore                   # Git ignore rules
│
├── scripts/                     # Automation scripts
│   ├── install-siem.sh         # Automated SIEM server setup
│   ├── log-shipper.py          # Log forwarding script
│   ├── install-agent.sh        # Wazuh agent installation
│   └── attack-scenarios/       # Pre-built attack simulations
│       ├── brute-force.sh
│       ├── network-scan.sh
│       └── file-compromise.sh
│
├── configs/                     # Configuration files
│   ├── wazuh/
│   │   ├── ossec.conf.sample   # Wazuh manager config
│   │   └── agent.conf.sample   # Wazuh agent config
│   ├── suricata/
│   │   └── suricata.yaml.sample
│   ├── docker/
│   │   └── daemon.json         # Docker logging config
│   └── netplan/
│       └── network-config.yaml # Static IP configuration
│
├── dashboards/                  # OpenSearch Dashboard exports
│   ├── security-alerts.ndjson
│   ├── suricata-ids.ndjson
│   └── file-integrity.ndjson
│
├── docs/                        # Additional documentation
│   ├── architecture.md         # Detailed architecture
│   ├── troubleshooting.md      # Common issues and fixes
│   ├── attack-scenarios.md     # Detailed attack guides
│   ├── performance.md          # Performance benchmarks
│   ├── images/                 # Screenshots and diagrams
│   │   ├── architecture-diagram.png
│   │   ├── dashboard-security.png
│   │   ├── dashboard-suricata.png
│   │   └── dashboard-fim.png
│   └── videos/                 # Video tutorials (links)
│
├── .github/                     # GitHub-specific files
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   └── question.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/               # CI/CD workflows (future)
│
└── tests/                       # Test scripts (future)
    ├── test-connectivity.sh
    ├── test-fim.sh
    └── test-active-response.sh
```

---

## 📄 File Descriptions

### Root Level Files

| File | Purpose | When to Edit |
|------|---------|--------------|
| `README.md` | Main project overview, features, quick start | When adding major features |
| `LICENSE` | MIT License terms | Rarely (only if changing license) |
| `CONTRIBUTING.md` | How to contribute to the project | When changing contribution process |
| `INSTALL.md` | Step-by-step installation guide | When installation process changes |
| `CHANGELOG.md` | Version history and changes | With each release |
| `.gitignore` | Files to exclude from Git | When adding new file types |

### Scripts Directory (`scripts/`)

Contains all automation and utility scripts:

- **`install-siem.sh`**: Automated installation for SIEM server
- **`log-shipper.py`**: Real-time log forwarding to OpenSearch
- **`install-agent.sh`**: Wazuh agent installation automation
- **Attack scenarios**: Pre-configured attack simulations

**Usage Example:**
```bash
# Install SIEM server
chmod +x scripts/install-siem.sh
./scripts/install-siem.sh

# Run attack scenario
chmod +x scripts/attack-scenarios/brute-force.sh
./scripts/attack-scenarios/brute-force.sh 192.168.56.102
```

### Configs Directory (`configs/`)

Template configuration files for all components:

- Wazuh Manager and Agent configs
- Suricata IDS configuration
- Docker daemon settings
- Network configuration templates

**Note**: These are **templates** with placeholder values. Copy and customize for your environment.

### Dashboards Directory (`dashboards/`)

Pre-built OpenSearch Dashboard exports in NDJSON format.

**Import Instructions:**
1. Wazuh Dashboard → Management → Saved Objects
2. Import → Select .ndjson file
3. Resolve conflicts if any

### Docs Directory (`docs/`)

Extended documentation:

- **`architecture.md`**: Deep dive into system design
- **`troubleshooting.md`**: Common issues and solutions
- **`attack-scenarios.md`**: Detailed attack walkthroughs
- **`performance.md`**: Benchmarks and optimization
- **`images/`**: Screenshots and diagrams for documentation
- **`videos/`**: Links to video tutorials (YouTube, etc.)

### GitHub Directory (`.github/`)

GitHub-specific configuration:

- **Issue templates**: Standardized bug reports and feature requests
- **PR template**: Pull request guidelines
- **Workflows**: CI/CD automation (future)

---

## 🚀 Getting Started with the Repository

### For Users

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/siem-lab.git
   cd siem-lab
   ```

2. **Read the documentation**:
   - Start with `README.md`
   - Follow `INSTALL.md` for setup

3. **Use automation scripts**:
   ```bash
   chmod +x scripts/install-siem.sh
   ./scripts/install-siem.sh
   ```

4. **Import dashboards**:
   - Import files from `dashboards/` into Wazuh Dashboard

### For Contributors

1. **Fork the repository**
2. **Read `CONTRIBUTING.md`**
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature
   ```
4. **Make changes and test**
5. **Submit a Pull Request**

---

## 📝 Documentation Standards

### README.md
- Should be under 500 lines
- Include badges, table of contents
- Quick start section at the top
- Link to detailed docs

### Code Comments
- Explain **why**, not **what**
- Add comments for complex logic
- Include examples where helpful

### Configuration Files
- Add inline comments
- Explain non-obvious settings
- Provide example values

### Scripts
- Include usage instructions at the top
- Add error handling
- Provide meaningful output

---

## 🔄 Update Process

### When Adding New Features

1. Update `CHANGELOG.md`
2. Update relevant documentation (`README.md`, `INSTALL.md`)
3. Add configuration templates to `configs/`
4. Create example scripts if applicable
5. Update version numbers
6. Create release notes

### When Fixing Bugs

1. Document fix in `CHANGELOG.md`
2. Update `docs/troubleshooting.md` if applicable
3. Add test case if possible

---

## 📦 Release Process

1. Update `CHANGELOG.md` with version and changes
2. Tag the release:
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```
3. Create GitHub release with release notes
4. Attach binary files if applicable

---

## 🎯 Best Practices

### File Naming
- Use lowercase with hyphens: `install-siem.sh`
- Descriptive names: `security-alerts-dashboard.ndjson`
- Include version in releases: `siem-lab-v1.0.0.tar.gz`

### Directory Organization
- Keep related files together
- Don't create unnecessary nesting
- Use clear, descriptive directory names

### Documentation
- Keep docs up-to-date with code
- Use relative links between docs
- Include code examples
- Add screenshots where helpful

### Git Commits
- Write clear commit messages
- Use conventional commits format:
  - `feat: Add new feature`
  - `fix: Fix bug in Active Response`
  - `docs: Update installation guide`
  - `refactor: Improve log-shipper performance`

---

## 📞 Support

For questions about repository structure:
- **Issues**: [GitHub Issues](https://github.com/yourusername/siem-lab/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/siem-lab/discussions)

---

**This structure is designed to be:**
- ✅ Easy to navigate
- ✅ Self-documenting
- ✅ Scalable for future additions
- ✅ Contributor-friendly
