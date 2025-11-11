# Contributing to Cyvest

Thank you for your interest in contributing to Cyvest! This document provides guidelines and instructions for contributing.

## Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/cyvest.git
   cd cyvest
   ```

2. **Install Dependencies**
   ```bash
   # Using uv (recommended)
   uv sync --all-extras
   
   # Or using pip
   pip install -e ".[dev]"
   ```

3. **Verify Setup**
   ```bash
   pytest
   ruff check .
   mypy src/cyvest
   ```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Changes

- Write clear, documented code
- Follow existing code style
- Add tests for new features
- Update documentation as needed

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cyvest --cov-report=html

# Run specific test file
pytest tests/test_model.py

# Run with verbose output
pytest -v
```

### 4. Check Code Quality

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type check
mypy src/cyvest

# Fix auto-fixable issues
ruff check --fix .
```

### 5. Commit Changes

Write clear commit messages:

```bash
git add .
git commit -m "feat: add new observable type support"
# or
git commit -m "fix: resolve score propagation issue"
# or
git commit -m "docs: update API reference"
```

Commit message prefixes:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots/examples if applicable

## Code Style

### Python Style

- Follow PEP 8
- Use type hints for all functions
- Maximum line length: 120 characters
- Use descriptive variable names
- Add docstrings for all public functions/classes

### Example

```python
def observable_create(
    self,
    obs_type: str,
    value: str,
    internal: bool = True,
    score: Decimal | None = None,
) -> Observable:
    """
    Create a new observable.
    
    Args:
        obs_type: Type of observable (ip, url, domain, etc.)
        value: Value of the observable
        internal: Whether this is an internal asset
        score: Optional explicit score
        
    Returns:
        The created observable
    """
    # Implementation
    pass
```

### Documentation

- Use Google-style docstrings
- Document all parameters and return values
- Include examples for complex functions
- Update user guide when adding features

## Testing Guidelines

### Test Structure

```python
def test_feature_description() -> None:
    """Test that feature behaves correctly."""
    # Arrange
    cv = Cyvest()
    
    # Act
    result = cv.some_method()
    
    # Assert
    assert result.expected_value == expected
```

### Test Coverage

- Aim for >90% test coverage
- Test happy paths and error cases
- Test edge cases
- Test integration between components

### Running Specific Tests

```bash
# Run single test
pytest tests/test_model.py::test_observable_creation

# Run tests matching pattern
pytest -k "observable"

# Run with markers
pytest -m "slow"
```

## Documentation

### Building Documentation

```bash
# Serve locally
mkdocs serve

# Build static site
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

### Documentation Structure

- **Getting Started**: Installation, quickstart, concepts
- **User Guide**: Detailed feature documentation
- **API Reference**: Auto-generated from docstrings
- **Examples**: Working code examples

## Pull Request Process

1. **Update Tests**: Add tests for new features
2. **Update Docs**: Update relevant documentation
3. **Run CI Checks**: Ensure all tests pass
4. **Request Review**: Tag maintainers for review
5. **Address Feedback**: Respond to review comments
6. **Merge**: Maintainer will merge when ready

## Issue Guidelines

### Reporting Bugs

Include:
- Python version
- Cyvest version
- Minimal reproduction example
- Expected vs actual behavior
- Error messages/stack traces

### Requesting Features

Include:
- Clear use case description
- Proposed API/interface
- Examples of how it would be used
- Alternative solutions considered

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discriminatory language
- Trolling or insulting comments
- Publishing others' private information
- Other unprofessional conduct

## Questions?

- Open a GitHub Discussion
- Join our community chat
- Email the maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Cyvest!** 🎉
