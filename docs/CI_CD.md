# CI/CD Pipeline Integration Guide

## 1. Overview
APIHub integrates with GitHub Actions, GitLab CI, and Jenkins to run automated API test suites on every pull request or push event.

## 2. GitHub Actions Workflow Example

Create `.github/workflows/apihub_tests.yml`:

```yaml
name: APIHub Integration Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  api-tests:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Run APIHub Test Suite
        env:
          APIHUB_URL: ${{ secrets.APIHUB_URL }}
          APIHUB_TOKEN: ${{ secrets.APIHUB_TOKEN }}
        run: |
          python -m apihub_cli auth login --url "$APIHUB_URL" --token "$APIHUB_TOKEN"
          python -m apihub_cli tests run 1 --format junit > junit-report.xml

      - name: Publish Test Report
        uses: mikepenz/action-junit-report@v3
        if: always()
        with:
          report_paths: 'junit-report.xml'
```

## 3. Environment Variables
- `APIHUB_URL`: Base URL of target APIHub server (e.g., `https://apihub.your-company.com`).
- `APIHUB_TOKEN`: Personal Access Token or Service Account Token (`ahp_...`).
- Secrets must be stored as masked repository secrets (`${{ secrets.APIHUB_TOKEN }}`) to prevent token exposure in build logs.
