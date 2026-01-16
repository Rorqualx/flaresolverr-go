# Contributing to FlareSolverr-Go

Thank you for your interest in contributing! This document provides a quick start guide.

## Before You Start

1. **Read CLAUDE.md** - This is the authoritative guide for architecture, coding standards, and safety rules
2. **Understand the architecture** - Know which package owns which responsibility
3. **Set up your environment** - Install Go 1.22+, golangci-lint, and pre-commit hooks

## Quick Setup

```bash
# Clone the repository
git clone https://github.com/Rorqualx/flaresolverr-go.git
cd flaresolverr-go

# Install tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
pip install pre-commit
pre-commit install

# Verify setup
make test
make lint
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Write Code

Follow the standards in CLAUDE.md:

- Put code in the correct package
- Use the naming conventions
- Add proper error handling
- Include tests

### 3. Test Your Changes

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Run specific package tests
go test -v ./internal/solver/...
```

### 4. Commit Your Changes

```bash
# Pre-commit hooks will run automatically
git add .
git commit -m "feat: add new feature"
```

Commit message format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `refactor:` - Code refactoring
- `test:` - Test changes
- `chore:` - Maintenance

### 5. Submit a Pull Request

1. Push your branch
2. Open a PR against `main`
3. Fill in the PR template
4. Wait for CI checks to pass
5. Request review

## Code Review Checklist

Before requesting review, verify:

- [ ] Code follows CLAUDE.md standards
- [ ] Tests added for new code
- [ ] All tests pass
- [ ] Linter passes with no warnings
- [ ] Documentation updated if needed

## Package Responsibilities

| Package | What Goes Here | What Doesn't |
|---------|---------------|--------------|
| `types/` | Request/response structs, errors | Business logic |
| `config/` | Configuration loading | Runtime state |
| `browser/` | Browser pool, stealth | Challenge solving |
| `sessions/` | Session management | Browser operations |
| `solver/` | Challenge detection/resolution | HTTP handling |
| `handlers/` | HTTP endpoints | Business logic |
| `middleware/` | Request/response processing | Routing |

## Getting Help

- Read CLAUDE.md for detailed standards
- Open an issue for questions
- Join discussions for architecture questions

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
