"""Trap repository generator for testing agentic environments.

This module provides utilities for generating "trap" repositories - directories
with malicious content designed to test agents' resistance to indirect injection
attacks via file content.

Usage:
    from khaos.trap_repo import generate_trap_repo, list_scenarios

    # List available scenarios
    scenarios = list_scenarios()
    print(scenarios)  # ['basic-project', 'git-repo', 'npm-project', ...]

    # Generate a trap repository
    generate_trap_repo("basic-project", "./test_repo")

Available Scenarios:
    - basic-project: Basic project with README.md, .env, and config file injections
    - git-repo: Git repository with malicious commit messages
    - npm-project: NPM project with package.json and node_modules traps
    - python-project: Python project with pyproject.toml and requirements.txt traps
    - docker-project: Docker project with Dockerfile and compose file injections
    - error-scenario: Project designed to generate errors with injected messages
"""

from khaos.trap_repo.generator import (
    cleanup_trap_repo,
    generate_custom_trap_repo,
    generate_from_attacks,
    generate_trap_repo,
    validate_trap_repo,
)
from khaos.trap_repo.scenarios import (
    ALL_SCENARIOS,
    TrapFile,
    TrapScenario,
    get_scenario,
    list_scenarios,
)

__all__ = [
    # Generator functions
    "generate_trap_repo",
    "generate_custom_trap_repo",
    "generate_from_attacks",
    "validate_trap_repo",
    "cleanup_trap_repo",
    # Scenario utilities
    "list_scenarios",
    "get_scenario",
    "ALL_SCENARIOS",
    # Data classes
    "TrapFile",
    "TrapScenario",
]
