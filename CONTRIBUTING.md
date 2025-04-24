# Contributing to LAnaLyzer

Thank you for your interest in contributing to LAnaLyzer! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/mxcrafts/lanalyzer.git
   cd lanalyzer
   ```
3. Set up your development environment:
   ```bash
   # Using Poetry (recommended)
   poetry install
   
   # Activate the virtual environment
   poetry shell
   ```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following our coding standards

3. Add tests for your changes

4. Run the tests to ensure everything works:
   ```bash
   pytest
   ```

5. Format your code:
   ```bash
   black .
   isort .
   ```

6. Run static type checking:
   ```bash
   mypy lanalyzer
   ```

7. Commit your changes:
   ```bash
   git commit -m "Add your meaningful commit message here"
   ```

8. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

9. Create a Pull Request from your fork to the main repository

## Coding Standards

- Follow PEP 8 style guidelines
- Use type annotations for all function parameters and return values
- Write docstrings for all modules, classes, and functions
- Keep functions small and focused on a single responsibility
- Write unit tests for all new functionality

## Pull Request Process

1. Ensure your code passes all tests and linting checks
2. Update the documentation if necessary
3. Include a clear description of the changes in your PR
4. Link any related issues in your PR description
5. Be responsive to feedback and be willing to make changes if requested

## Adding New Features

When adding new features:

1. First discuss the feature by creating an issue
2. Design the feature with extensibility in mind
3. Implement the feature with appropriate tests
4. Update documentation to reflect the new feature

## Reporting Bugs

When reporting bugs:

1. Use the bug report template
2. Include detailed steps to reproduce the bug
3. Describe the expected behavior and what actually happened
4. Include relevant logs, error messages, and screenshots
5. Mention your operating system and Python version

## Feature Requests

When requesting features:

1. Use the feature request template
2. Clearly describe the problem the feature would solve
3. Suggest a possible implementation if you have ideas

## Questions?

If you have any questions about contributing, please open an issue with the "question" label.

Thank you for contributing to LAnaLyzer! 