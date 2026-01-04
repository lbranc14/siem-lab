# Contributing to Enterprise SIEM Lab

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## 🎯 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When you create a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (OS, Wazuh version, Docker version)
- **Logs** if applicable
- **Screenshots** if helpful

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case** explaining why this enhancement would be useful
- **Possible implementation** if you have ideas

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**:
   - Follow the coding style of the project
   - Add comments for complex logic
   - Update documentation if needed
4. **Test your changes**:
   - Verify functionality in your local lab
   - Check for any breaking changes
5. **Commit with clear messages**:
   ```bash
   git commit -m "Add: Brief description of your changes"
   ```
6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**:
   - Describe your changes clearly
   - Link any related issues
   - Wait for review

## 📋 Coding Standards

### Documentation
- Update README.md for significant changes
- Add inline comments for complex configurations
- Document any new dependencies

### Configuration Files
- Use consistent formatting (YAML, XML, JSON)
- Add comments explaining non-obvious settings
- Test configurations before committing

### Scripts
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add error handling
- Include usage examples

### Commit Messages
```
Type: Brief description (50 chars max)

Detailed explanation of changes (optional)
- Point 1
- Point 2

Closes #issue_number (if applicable)
```

**Types**: `Add`, `Fix`, `Update`, `Remove`, `Refactor`, `Docs`

## 🧪 Testing Guidelines

Before submitting a PR, test:

1. **Installation**: Clean VM setup from scratch
2. **Functionality**: All attack scenarios work
3. **Dashboards**: Visualizations display correctly
4. **Documentation**: Instructions are accurate
5. **Performance**: No significant resource degradation

## 🔒 Security

- **Never commit** API keys, passwords, or sensitive data
- **Use environment variables** or config files for secrets
- Report security vulnerabilities privately (see SECURITY.md)

## 📝 Documentation Changes

- Update relevant .md files
- Check formatting and links
- Verify code blocks are correctly highlighted
- Test commands in documentation

## 🎨 Style Guide

### Markdown
- Use ATX-style headers (`#`, `##`, `###`)
- Wrap code in triple backticks with language identifier
- Use tables for structured data
- Add emoji sparingly for visual markers

### Configuration
- YAML: 2 spaces for indentation
- XML: 2 spaces for indentation
- JSON: 2 spaces for indentation

## 🤝 Code of Conduct

### Our Standards

- **Be respectful** and inclusive
- **Welcome newcomers** and help them learn
- **Accept constructive criticism** gracefully
- **Focus on what's best** for the community

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Unprofessional conduct

## 📞 Getting Help

- **GitHub Issues**: For bugs and enhancements
- **Discussions**: For questions and general discussion
- **Email**: For private concerns

## 🏆 Recognition

Contributors will be acknowledged in:
- README.md Contributors section
- Release notes
- Project documentation

Thank you for contributing! 🎉
