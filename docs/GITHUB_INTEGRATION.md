# GitHub & Git Integration Guide

## 1. Overview
APIHub Git integration connects team workspaces to GitHub repositories to synchronize OpenAPI 3.0 specification files between Git version control and APIHub Collections.

## 2. Configuration Parameters
- **Repository**: GitHub repository (`owner/repo`).
- **Branch**: Target Git branch (default `main`).
- **Path**: Specification file path (e.g., `openapi/users.yaml`).
- **Access Token**: GitHub Personal Access Token (PAT) with `repo` scope.

## 3. Pull & Push Synchronization Workflow
1. **Pull Specification**: Fetches specification file from GitHub, parses OpenAPI structure, and updates workspace Collection endpoints.
2. **Preview Changes**: Displays side-by-side diff preview of modified paths, added endpoints, and removed fields prior to committing.
3. **Push Specification**: Exports Collection into clean OpenAPI 3.0 YAML/JSON and commits to the GitHub branch with user-provided commit message.

## 4. Security Rules
- GitHub Access Tokens are masked in API responses.
- Arbitrary code execution from repositories is strictly prohibited; only static YAML/JSON specification files are parsed.
