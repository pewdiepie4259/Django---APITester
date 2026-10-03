# APIHub CLI Developer & CI/CD Manual

## 1. Overview
The APIHub CLI (`apihub` / `apihub_cli`) is a command-line utility for executing requests, running automated test suites, interacting with collections, and triggering CI pipeline checks directly from your terminal.

## 2. Installation & Quick Start

```bash
# Option A: Run via python module inside project repository
python -m apihub_cli --help

# Option B: Authenticate CLI
python -m apihub_cli auth login --url http://127.0.0.1:8000 --token ahp_your_personal_access_token
```

## 3. Command Reference

### Authentication
- `apihub auth login --url <url> --token <token>`: Configures APIHub endpoint target and Personal Access Token.
- `apihub auth logout`: Clears saved CLI credentials from `~/.apihub_config.json`.

### Workspaces & Collections
- `apihub workspace list [--format text|json]`: Lists accessible team and personal workspaces.
- `apihub collections list [--format text|json]`: Lists saved API collections and endpoint counts.

### Request Execution
- `apihub requests run <request_id> [--format text|json]`: Executes a saved request and evaluates assertions.

### Test Suite Execution
- `apihub tests run <suite_id> [--format text|json|junit]`: Runs a complete test suite and outputs results.

## 4. Output Formats & Exit Codes

### Exit Codes
- `0`: Success — All assertions and contract validations passed.
- `1`: Failure — One or more test assertions or contract rules failed.
- `2`: Error — Invalid parameters, network error, or HTTP 401/403 authorization failure.

### JUnit XML Output Example
```bash
python -m apihub_cli tests run 1 --format junit > junit-report.xml
```
Generates standard JUnit XML for GitHub Actions, GitLab CI, and Jenkins test summary widgets.
