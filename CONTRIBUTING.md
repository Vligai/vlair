# Contributing to SecOps Helper

Thank you for your interest in contributing to SecOps Helper! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [CI/CD Pipeline](#cicd-pipeline)

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/secops-helper.git
   cd secops-helper
   ```

3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/Vligai/secops-helper.git
   ```

## Development Setup

### Prerequisites

- Python 3.9, 3.10, or 3.11
- Git
- pip

### Installation

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Install pre-commit hooks**:
   ```bash
   pip install pre-commit
   pre-commit install
   ```

### Environment Configuration

Create a `.env` file for API keys (optional for development):

```bash
# VirusTotal API (free tier)
VT_API_KEY=your_virustotal_api_key

# AbuseIPDB API
ABUSEIPDB_KEY=your_abuseipdb_api_key
```

**Note:** Tests use mocked APIs and don't require real API keys.

## Code Quality

We use several tools to maintain code quality:

### Code Formatting

We use **Black** for code formatting:

```bash
# Check formatting
black --check .

# Auto-format code
black .
```

**Configuration:** Line length is 127 characters (see `pyproject.toml`)

### Linting

We use **flake8** for linting:

```bash
# Run flake8
flake8 . --max-line-length=127 --exclude=venv,env,.venv,.tox
```

### Import Sorting

We use **isort** for organizing imports:

```bash
# Check import order
isort --check-only --diff .

# Auto-sort imports
isort .
```

### Security Scanning

We use **bandit** for security analysis:

```bash
# Run security scan
bandit -r . --exclude ./tests,./venv
```

### Pre-commit Hooks

Pre-commit hooks automatically run these checks before each commit:

- Black (code formatting)
- flake8 (linting)
- isort (import sorting)
- bandit (security scanning)
- Trailing whitespace removal
- YAML/JSON validation
- Private key detection

**To run manually:**
```bash
pre-commit run --all-files
```

**To skip hooks (not recommended):**
```bash
git commit --no-verify
```

## Testing

### Running Tests

Run all tests:
```bash
pytest tests/ -v
```

Run with coverage:
```bash
pytest tests/ --cov=. --cov-report=html
```

Run specific test file:
```bash
pytest tests/test_ioc_extractor.py -v
```

Run specific test:
```bash
pytest tests/test_ioc_extractor.py::TestIOCExtractor::test_extract_ipv4_basic -v
```

### Test Coverage

We aim for **>80% test coverage**. Coverage reports are generated in `htmlcov/index.html`.

View coverage report:
```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Name test classes `Test*`
- Name test functions `test_*`
- Use descriptive test names
- Include docstrings explaining what is tested
- Mock external API calls
- Test edge cases and error conditions

**Example test:**
```python
def test_extract_ipv4_basic(self):
    """Test basic IPv4 extraction"""
    extractor = IOCExtractor()
    text = "Malicious traffic from 192.0.2.1"
    result = extractor.extract_from_text(text, types=['ip'])

    assert '192.0.2.1' in result['ips']
    assert len(result['ips']) == 1
```

## Submitting Changes

### Branching Strategy

- `main` - Stable production branch
- `develop` - Development branch (if applicable)
- `feature/feature-name` - Feature branches
- `bugfix/bug-description` - Bug fix branches
- `claude/*` - AI assistant branches

### Creating a Pull Request

1. **Create a new branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit:
   ```bash
   git add .
   git commit -m "Add feature: description"
   ```

3. **Run tests** to ensure everything passes:
   ```bash
   pytest tests/ -v
   black --check .
   flake8 .
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request** on GitHub

### Commit Message Guidelines

Follow this format:

```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Example:**
```
feat: Add domain reputation analysis to intel tool

- Implement domain validation
- Add DNS resolution
- Integrate with VirusTotal API
- Calculate risk scores (0-100)

Closes #123
```

### Pull Request Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass (`pytest tests/`)
- [ ] New tests added for new features
- [ ] Documentation updated (if applicable)
- [ ] Pre-commit hooks pass
- [ ] No merge conflicts with main branch
- [ ] Descriptive PR title and description

## CI/CD Pipeline

### GitHub Actions

Our CI/CD pipeline runs automatically on every push and pull request.

**Workflows:**

1. **Tests** (`.github/workflows/tests.yml`)
   - Runs on Python 3.9, 3.10, 3.11
   - Executes all tests with coverage
   - Uploads coverage to Codecov
   - Runs linting and formatting checks

2. **Security Scan**
   - Runs bandit security scanner
   - Generates security report artifact

### Pipeline Steps

1. **Checkout code**
2. **Set up Python** (matrix: 3.9, 3.10, 3.11)
3. **Install dependencies**
4. **Run flake8** (linting)
5. **Run black** (format check)
6. **Run pytest** (tests + coverage)
7. **Upload coverage** to Codecov
8. **Run bandit** (security scan)

### Status Badges

Add these to your PR:
- ![Tests](https://github.com/Vligai/secops-helper/workflows/Tests/badge.svg)
- ![Coverage](https://codecov.io/gh/Vligai/secops-helper/branch/main/graph/badge.svg)

### Local CI Simulation

Run the same checks locally before pushing:

```bash
# Full CI simulation
./scripts/run-ci-checks.sh  # (if available)

# Or manually:
flake8 . --max-line-length=127 --exclude=venv
black --check .
isort --check-only .
pytest tests/ -v --cov=. --cov-report=term-missing
bandit -r . --exclude ./tests,./venv
```

## Code Review Process

1. **Automated checks** must pass (CI/CD pipeline)
2. **At least one approval** from maintainers required
3. **No merge conflicts** with target branch
4. **All conversations resolved**

Maintainers will review:
- Code quality and style
- Test coverage
- Documentation
- Security considerations
- Performance implications

## Project Structure

Understand the project layout before contributing:

```
secops-helper/
├── emlAnalysis/          # Email analysis tools
├── iocExtractor/         # IOC extraction
├── hashLookup/           # Hash threat intelligence
├── domainIpIntel/        # Domain/IP intelligence
├── logAnalysis/          # Log analysis
├── pcapAnalyzer/         # PCAP network analysis
├── tests/                # Test suite
│   ├── test_data/        # Sample data for tests
│   └── test_*.py         # Test modules
├── .github/workflows/    # GitHub Actions
├── openspec/             # Project specifications
├── requirements.txt      # Project dependencies
├── requirements-dev.txt  # Development dependencies
├── pytest.ini            # Pytest configuration
├── pyproject.toml        # Tool configurations
└── CLAUDE.md             # AI assistant guide
```

## Getting Help

- **Issues:** Open an issue on GitHub for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions
- **Documentation:** Check `README.md` and `CLAUDE.md`

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to SecOps Helper!** 🔒🛡️
