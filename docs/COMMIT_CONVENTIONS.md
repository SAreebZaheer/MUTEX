# Conventional Commits Guide

This project uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) specification for commit messages.

## Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

## Types

The following types are allowed:

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that do not affect the meaning of the code (white-space, formatting, etc)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to CI configuration files and scripts
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

## Examples

### Simple commit
```bash
git commit -m "feat: add netfilter hook registration"
git commit -m "fix: correct packet checksum calculation"
git commit -m "docs: update PDM sequence diagram"
```

### Commit with scope
```bash
git commit -m "feat(syscall): implement proxy enable system call"
git commit -m "fix(netfilter): handle NULL pointer in hook handler"
git commit -m "docs(readme): add installation instructions"
```

### Commit with body
```bash
git commit -m "feat(proxy): add SOCKS5 protocol support

Implement SOCKS5 handshake and authentication in kernel space.
Supports username/password and no-auth methods.
"
```

### Breaking change
```bash
git commit -m "feat(api)!: change syscall parameter structure

BREAKING CHANGE: syscall now requires proxy_config struct instead of individual parameters
"
```

### Commit with footer
```bash
git commit -m "fix(connection): prevent memory leak in connection table

Fixes: #123
Reviewed-by: John Doe
"
```

## Scopes (Suggested)

While scopes are optional, here are suggested scopes for this project:

- **module**: Core kernel module
- **syscall**: System call interface
- **netfilter**: Netfilter hooks
- **proxy**: Proxy functionality
- **socks**: SOCKS protocol
- **http**: HTTP proxy
- **connection**: Connection tracking
- **packet**: Packet manipulation
- **config**: Configuration management
- **test**: Testing infrastructure
- **docs**: Documentation
- **build**: Build system

## Pre-commit Hook

This repository has a pre-commit hook that validates commit messages. If your commit message doesn't follow the Conventional Commits format, the commit will be rejected.

### Example of rejected commit:
```bash
$ git commit -m "added new feature"
Conventional Commit......................................................Failed
- hook id: conventional-pre-commit
- duration: 0.05s
- exit code: 1

[Bad Commit message] >> added new feature
Your commit message does not follow Conventional Commits formatting
https://www.conventionalcommits.org/

Conventional Commits start with one of the below types, followed by a colon,
followed by the commit message:

    build chore ci docs feat fix perf refactor revert style test

Example commit message adding a feature:

    feat: add new feature
```

### Example of accepted commit:
```bash
$ git commit -m "feat: add new feature"
Conventional Commit......................................................Passed
[project-plan a1b2c3d] feat: add new feature
 1 file changed, 10 insertions(+)
```

## Tips

1. **Keep the subject line short**: Aim for 50 characters or less
2. **Use imperative mood**: "add feature" not "added feature" or "adds feature"
3. **Don't end with a period**: The subject line is a title
4. **Capitalize the subject line**: Start with a capital letter after the colon
5. **Use the body to explain what and why**: The body should explain what changed and why, not how

## Bypassing the Hook (Not Recommended)

If you absolutely need to bypass the hook (not recommended):
```bash
git commit -m "message" --no-verify
```

However, this should only be used in exceptional circumstances.

## Resources

- [Conventional Commits Specification](https://www.conventionalcommits.org/en/v1.0.0/)
- [Angular Convention](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#commit)
- [Commitizen](https://github.com/commitizen/cz-cli) - Interactive commit message helper

---

*Last Updated: December 14, 2025*
