# Role-Based Access Control (RBAC) System

A Flask reference implementation of **NIST SP 800-162** core RBAC,
built to align with the **OWASP Access Control Cheat Sheet**.

## Stack
Python 3 · Flask · SQLite (via Flask-SQLAlchemy) · JWT (PyJWT) · Bootstrap 5

## Features
- **Roles**: Admin, Manager, User, Guest — ranked hierarchy (`models.ROLE_HIERARCHY`)
- **Fine-grained permissions**: every route checks a specific `(resource, operation)`
  pair against the database `PermissionAssignment` table — not just a role name
  (see `seed.py` for the full permission matrix)
- **JWT auth with role claims**: tokens carry `sub`, `username`, `role`, and a
  `tv` (token_version) claim
- **Privilege escalation detection** (`auth.py`):
  1. Forged/invalid signatures → rejected by JWT verification itself
  2. Role-claim vs. DB-role mismatch → logged as `PRIVILEGE_ESCALATION_ATTEMPT` (CRITICAL)
  3. Stale tokens after a role change → rejected via `token_version` check
  4. Self-escalation via a `role` field in a request body → `detect_role_field_tampering()`
- **Security audit log**: every login, denial, role change, and escalation
  attempt is recorded and viewable in the Admin Console
- **Deny-by-default**: `@require_permission` rejects unless an explicit grant exists
- **Admin user management**: create new users with any role (guarded against
  self-escalation), delete users (self-delete and last-Admin deletion are blocked)
- **Manual permission editor**: Admin can define brand-new `(resource, operation)`
  permissions on the fly and grant/revoke them per role from a matrix UI.
  Admin's own permissions are locked to prevent accidental system lockout —
  only Guest/User/Manager permissions are editable.
- **Persisted documents & reports**: Documents and reports are now real
  database records (not stub responses), with create + delete tracked
  per user in the audit log.

## Setup
```bash
pip install -r requirements.txt
python app.py
```
Visit http://localhost:5000 — the database is auto-created and seeded on first run.

## Demo accounts
| Username | Password      | Role    |
|----------|---------------|---------|
| admin    | Admin!2345    | Admin   |
| manager  | Manager!2345  | Manager |
| alice    | User!2345     | User    |
| guest    | Guest!2345    | Guest   |

## Run the test suite
```bash
python test_rbac.py
```
This exercises: permission denials, permission grants, stale-token rejection,
forged-signature rejection, role-claim-mismatch detection, and self-escalation
rejection — printing the resulting audit log at the end.

## Why this matters (Project Outcome 3)
Broken Access Control has topped the OWASP Top 10 since 2021. Most real-world
breaches in this category aren't exotic — they're missing server-side checks
(client-only enforcement), trusting a JWT claim without re-verifying it against
the database, or forgetting to invalidate tokens after a privilege change. This
project deliberately implements and *demonstrates* each of those failure modes
being caught, rather than just describing them.

## Project structure
```
rbac-system/
├── app.py            # Flask app + all routes
├── auth.py           # JWT issuance/verification + RBAC decorators + escalation detection
├── models.py         # SQLAlchemy models (User, Role, Permission, AuditLog)
├── seed.py           # Permission matrix + demo data
├── test_rbac.py       # Functional test suite
├── templates/         # Bootstrap UI (login, dashboard, admin console)
├── static/            # CSS/JS
└── requirements.txt
```
