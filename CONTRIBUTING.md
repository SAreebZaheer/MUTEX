# Contributing to MUTEX

Thank you for your interest in contributing to MUTEX (Multi-User Threaded Exchange Xfer)! This document provides guidelines and instructions for contributing to this kernel-level proxy module project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Branch Naming Conventions](#branch-naming-conventions)
- [Documentation](#documentation)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors. We expect everyone to:

- Be respectful and professional
- Accept constructive criticism gracefully
- Focus on what's best for the project
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discrimination, or offensive comments
- Trolling or deliberate disruption
- Publishing others' private information
- Any conduct that could be considered inappropriate in a professional setting

---

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- **Linux kernel headers** (version 5.x or later)
  ```bash
  # Fedora/RHEL
  sudo dnf install kernel-devel kernel-headers

  # Ubuntu/Debian
  sudo apt-get install linux-headers-$(uname -r)

  # Arch Linux
  sudo pacman -S linux-headers
  ```

- **Build tools**
  ```bash
  # Fedora/RHEL
  sudo dnf install gcc make git

  # Ubuntu/Debian
  sudo apt-get install build-essential git

  # Arch Linux
  sudo pacman -S base-devel git
  ```

- **Python 3.8+** (for development tools)
  ```bash
  python3 --version
  ```

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/MUTEX.git
   cd MUTEX
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/SAreebZaheer/MUTEX.git
   ```

4. **Verify remotes**:
   ```bash
   git remote -v
   # origin    https://github.com/YOUR_USERNAME/MUTEX.git (fetch)
   # origin    https://github.com/YOUR_USERNAME/MUTEX.git (push)
   # upstream  https://github.com/SAreebZaheer/MUTEX.git (fetch)
   # upstream  https://github.com/SAreebZaheer/MUTEX.git (push)
   ```

---

## Development Setup

### 1. Set Up Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows
```

### 2. Install Pre-commit Hooks

Pre-commit hooks ensure code quality and enforce conventional commit messages.

```bash
# Install pre-commit
pip install pre-commit

# Install the git hooks
pre-commit install
pre-commit install --hook-type commit-msg

# (Optional) Run against all files to test
pre-commit run --all-files
```

### 3. Verify Installation

```bash
# Test that pre-commit is working
echo "test" > test.txt
git add test.txt
git commit -m "test commit"  # This should FAIL (bad format)
git commit -m "test: verify pre-commit hook"  # This should PASS
git reset HEAD~1  # Undo the test commit
rm test.txt
```

### 4. Install Development Dependencies

```bash
# Install additional Python development tools (optional)
pip install black isort pylint pytest
```

---

## Contribution Workflow

### 1. Sync Your Fork

Always start by syncing your fork with the upstream repository:

```bash
git checkout main
git fetch upstream
git merge upstream/main
git push origin main
```

### 2. Create a Feature Branch

Follow the [branch naming conventions](#branch-naming-conventions):

```bash
# For new features
git checkout -b feature/your-feature-name

# For bug fixes
git checkout -b bugfix/issue-description

# For documentation
git checkout -b docs/what-youre-documenting
```

### 3. Make Your Changes

- Write clean, well-documented code
- Follow the [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html) for C code
- Add comments explaining complex logic
- Update documentation as needed

### 4. Test Your Changes

```bash
# Build the kernel module (if applicable)
make

# Run tests (when test framework is available)
make test

# Manual testing
sudo insmod your_module.ko
# Test functionality
sudo rmmod your_module
dmesg | tail -n 50  # Check kernel logs
```

### 5. Commit Your Changes

Follow [Conventional Commits v1.0.0](docs/COMMIT_CONVENTIONS.md):

```bash
git add .
git commit -m "feat(netfilter): add packet interception hook

Implement NF_INET_PRE_ROUTING hook to intercept incoming packets.
Includes basic packet validation and logging."
```

**Common commit types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

### 6. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 7. Create a Pull Request

1. Go to the [MUTEX repository](https://github.com/SAreebZaheer/MUTEX)
2. Click "New Pull Request"
3. Select your fork and branch
4. Fill out the PR template (see below)
5. Submit the PR

---

## Commit Message Guidelines

This project uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

### Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Examples

```bash
# Simple feature
git commit -m "feat: add SOCKS5 protocol support"

# Bug fix with scope
git commit -m "fix(netfilter): handle NULL pointer in hook"

# Breaking change
git commit -m "feat(api)!: change syscall interface

BREAKING CHANGE: syscall now uses new struct format"

# With issue reference
git commit -m "fix: memory leak in connection tracking

Fixes: #42"
```

**See [docs/COMMIT_CONVENTIONS.md](docs/COMMIT_CONVENTIONS.md) for detailed guidelines.**

---

## Coding Standards

### C Code (Kernel Module)

Follow the **Linux Kernel Coding Style**:

```c
/* Use tabs for indentation (8 spaces) */
int example_function(struct sk_buff *skb)
{
        /* Braces on same line for functions, next line for conditionals */
        if (skb == NULL) {
                pr_err("Invalid skb\n");
                return -EINVAL;
        }

        /* Use kernel logging functions */
        pr_info("Processing packet\n");

        return 0;
}
```

**Key points:**
- Use tabs (8 characters) for indentation
- Maximum line length: 80 characters (100 for exceptions)
- Use `pr_*` functions for logging, not `printk` directly
- Error handling: check returns, use goto for cleanup
- No C++ style comments (`//`), use `/* */`

### Python Code (Utilities)

Follow **PEP 8** with Black formatting:

```python
"""Module docstring."""

def example_function(param: str) -> int:
    """Function docstring.

    Args:
        param: Description of parameter

    Returns:
        Description of return value
    """
    # Your code here
    return 0
```

**Key points:**
- Use Black for formatting (run automatically via pre-commit)
- Use type hints
- Write docstrings for all public functions/classes
- Maximum line length: 88 characters (Black default)

---

## Testing

### Manual Testing

```bash
# Build the module
make clean
make

# Load the module
sudo insmod mutex.ko

# Check that it loaded
lsmod | grep mutex
dmesg | tail -20

# Test functionality
# (Your testing commands here)

# Unload the module
sudo rmmod mutex

# Check for errors
dmesg | tail -20
```

### Automated Testing

Once the test framework is implemented (Branch 22):

```bash
# Run all tests
make test

# Run specific test suite
make test-netfilter
make test-proxy

# Run with coverage
make test-coverage
```

### Writing Tests

- Write tests for new features
- Ensure tests pass before submitting PR
- Include both positive and negative test cases
- Test edge cases and error conditions

---

## Pull Request Process

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Related Issue
Fixes #(issue number)

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
Describe the tests you ran and their results

## Checklist
- [ ] My code follows the project's coding style
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated the documentation accordingly
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Pre-commit hooks pass
```

### Review Process

1. **Automated checks** must pass (pre-commit, CI/CD)
2. **At least one approving review** required
3. **Address review comments** promptly
4. **Maintainer approval** before merging
5. **Squash commits** if requested

### After Your PR is Merged

1. Delete your feature branch (optional but recommended)
   ```bash
   git branch -d feature/your-feature-name
   git push origin --delete feature/your-feature-name
   ```

2. Sync your fork
   ```bash
   git checkout main
   git pull upstream main
   git push origin main
   ```

---

## Branch Naming Conventions

Use descriptive branch names following this pattern:

```
<type>/<short-description>
```

### Types

- `feature/` - New features
- `bugfix/` - Bug fixes
- `hotfix/` - Urgent production fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions/changes
- `chore/` - Maintenance tasks

### Examples

```bash
feature/netfilter-hooks
feature/socks5-protocol
bugfix/memory-leak-connection-tracking
bugfix/null-pointer-hook-handler
docs/api-documentation
docs/update-readme
refactor/optimize-packet-processing
test/add-integration-tests
chore/update-dependencies
```

---

## Documentation

### What to Document

- **Code comments**: Explain complex logic, algorithms, and non-obvious decisions
- **Function/API documentation**: Parameters, return values, side effects
- **Architecture decisions**: Why you chose a particular approach
- **User guides**: How to use new features
- **Troubleshooting**: Common issues and solutions

### Documentation Standards

- Update `README.md` for user-facing changes
- Update `docs/` for detailed documentation
- Include examples and code snippets
- Keep documentation in sync with code

### Example Comment Style

```c
/**
 * hook_incoming_packet - Intercept incoming network packets
 * @skb: Socket buffer containing the packet
 * @state: Netfilter hook state
 *
 * This function is called by netfilter for each incoming packet.
 * It inspects the packet and determines if it should be proxied.
 *
 * Return: NF_ACCEPT to allow packet, NF_DROP to drop it
 */
static unsigned int hook_incoming_packet(struct sk_buff *skb,
                                          const struct nf_hook_state *state)
{
        /* Implementation */
}
```

---

## Community

### Getting Help

- **Issues**: Check existing [issues](https://github.com/SAreebZaheer/MUTEX/issues) or create a new one
- **Discussions**: Use [GitHub Discussions](https://github.com/SAreebZaheer/MUTEX/discussions) for questions
- **Email**: Contact the maintainers (see README.md)

### Reporting Bugs

When reporting bugs, include:

1. **Description**: Clear description of the issue
2. **Steps to reproduce**: Exact steps to reproduce the behavior
3. **Expected behavior**: What you expected to happen
4. **Actual behavior**: What actually happened
5. **Environment**:
   - Kernel version: `uname -r`
   - Distribution: `cat /etc/os-release`
   - Module version: `modinfo mutex.ko`
6. **Logs**: Relevant `dmesg` output or error messages
7. **Additional context**: Any other relevant information

### Suggesting Features

For feature requests:

1. Check if the feature is already planned (see `docs/BRANCH_PLAN.md`)
2. Open an issue with the `enhancement` label
3. Provide:
   - Use case and motivation
   - Proposed implementation (if you have ideas)
   - Potential challenges or concerns
   - Willingness to contribute

---

## Project Structure

```
MUTEX/
├── README.md                   # Project overview
├── CONTRIBUTING.md            # This file
├── .gitignore                 # Git ignore rules
├── .pre-commit-config.yaml    # Pre-commit configuration
├── Makefile                   # Build configuration
├── docs/                      # Documentation
│   ├── BRANCH_PLAN.md        # Development roadmap
│   ├── PDM-sequence.md       # Project scheduling
│   └── COMMIT_CONVENTIONS.md # Commit message guide
├── src/                       # Source code (to be created)
│   ├── module/               # Kernel module code
│   ├── userspace/            # Userspace utilities
│   └── tests/                # Test suite
└── linux/                     # Linux kernel source (reference)
```

---

## Development Workflow Summary

```bash
# 1. Sync your fork
git checkout main
git pull upstream main

# 2. Create feature branch
git checkout -b feature/my-feature

# 3. Make changes and commit
git add .
git commit -m "feat: add my feature"

# 4. Push to your fork
git push origin feature/my-feature

# 5. Create PR on GitHub

# 6. Address review feedback
git add .
git commit -m "fix: address review comments"
git push origin feature/my-feature

# 7. After merge, clean up
git checkout main
git pull upstream main
git branch -d feature/my-feature
```

---

## Quick Reference

### Pre-commit Hook Issues

If pre-commit fails:

```bash
# See what failed
git commit -m "your message"

# Fix the issues, then try again
git add .
git commit -m "feat: properly formatted message"

# Skip pre-commit (NOT RECOMMENDED)
git commit -m "message" --no-verify
```

### Updating Pre-commit Hooks

```bash
# Update to latest versions
pre-commit autoupdate

# Run manually
pre-commit run --all-files
```

### Common Issues

**Issue**: Can't build kernel module  
**Solution**: Ensure kernel headers are installed matching your kernel version

**Issue**: Pre-commit hook rejects commit  
**Solution**: Follow Conventional Commits format (see `docs/COMMIT_CONVENTIONS.md`)

**Issue**: Module won't load  
**Solution**: Check `dmesg` for errors, ensure kernel version compatibility

---

## License

By contributing to MUTEX, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

---

## Thank You!

Your contributions make this project better! We appreciate your time and effort in helping build a kernel-level proxy solution for Linux.

For questions or assistance, don't hesitate to reach out through GitHub issues or discussions.

**Happy coding! 🚀**

---

*Last Updated: December 14, 2025*  
*Project: MUTEX - Multi-User Threaded Exchange Xfer*  
*Team: Syed Areeb Zaheer, Azeem, Hamza Bin Aamir*
