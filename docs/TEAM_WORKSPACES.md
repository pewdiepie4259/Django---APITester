# Team Workspaces, Roles & Access Control Guide

## 1. Overview
APIHub supports collaborative team workspaces enabling engineering teams to share Collections, Environments, Test Suites, Monitors, and Mock APIs under a unified role-based authorization model.

## 2. Workspace Types
- **Personal Workspace**: Automatically created for every user. Isolated and private. Cannot be deleted.
- **Team Workspaces**: Created by users for team collaboration (e.g., "Engineering Team", "College Project"). Can contain multiple members with granular roles.

## 3. Role-Based Access Control (RBAC) Matrix

| Role | Workspace Mgmt | Invite Members | Edit Collections / Requests | Read Collections / Docs | View Secret Values | Run Tests / CI | Delete Workspace |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **OWNER** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **ADMIN** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **EDITOR** | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **VIEWER** | ❌ | ❌ | ❌ | ✅ | ❌ (Masked `••••••••`) | ✅ | ❌ |

## 4. Invitation Flow
1. Workspace `OWNER` or `ADMIN` sends an invitation target (`user@example.com`).
2. An unpredictable, single-use invitation token is generated (`uuid.uuid4()`) with a 7-day expiration.
3. The invited user accepts the invitation via `/api/invitations/<token>/accept/`.
4. The user is added to `WorkspaceMember` with the designated role.

## 5. Server-Side Enforcement
Authorization checks are strictly enforced on the server-side via `_has_workspace_permission(user, workspace, required_role)`. Frontend visibility rules are supplementary; direct API access without sufficient permissions yields HTTP `403 Forbidden`.
