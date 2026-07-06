"""
models.py
Database models for the RBAC System.

Implements the NIST SP 800-162 core RBAC entities:
  - Users
  - Roles
  - Permissions (Operation x Object)
  - UserAssignment (User <-> Role)
  - PermissionAssignment (Role <-> Permission)

Also implements an AuditLog table used to record privilege escalation
attempts and other access-control-relevant security events, per the
OWASP Access Control Cheat Sheet recommendation to log all access
control failures.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


# ---------------------------------------------------------------------------
# Core NIST RBAC roles, ranked by seniority (higher number = more privilege)
# ---------------------------------------------------------------------------
ROLE_HIERARCHY = {
    "Guest": 0,
    "User": 1,
    "Manager": 2,
    "Admin": 3,
}

ROLE_NAMES = list(ROLE_HIERARCHY.keys())


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    rank = db.Column(db.Integer, nullable=False)  # mirrors ROLE_HIERARCHY
    description = db.Column(db.String(255))

    permissions = db.relationship(
        "Permission", secondary="permission_assignment", back_populates="roles"
    )
    users = db.relationship("User", back_populates="role")

    def __repr__(self):
        return f"<Role {self.name}>"


class Permission(db.Model):
    """
    A Permission is an (operation, resource) pair, matching the NIST
    RBAC definition of a permission as an approval to perform an
    operation on a protected object (resource).
    """
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    resource = db.Column(db.String(100), nullable=False)   # e.g. "documents"
    operation = db.Column(db.String(50), nullable=False)   # e.g. "read", "write", "delete", "manage"

    roles = db.relationship(
        "Role", secondary="permission_assignment", back_populates="permissions"
    )

    __table_args__ = (
        db.UniqueConstraint("resource", "operation", name="uq_resource_operation"),
    )

    def __repr__(self):
        return f"<Permission {self.operation}:{self.resource}>"


# Many-to-many association: PermissionAssignment (NIST calls this PA)
permission_assignment = db.Table(
    "permission_assignment",
    db.Column("role_id", db.Integer, db.ForeignKey("roles.id"), primary_key=True),
    db.Column("permission_id", db.Integer, db.ForeignKey("permissions.id"), primary_key=True),
)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Role", back_populates="users")

    is_active = db.Column(db.Boolean, default=True)
    failed_login_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Token versioning lets an admin invalidate all outstanding JWTs for a
    # user (e.g. after a role change or a detected escalation attempt) by
    # bumping this counter. The JWT carries the version it was issued with.
    token_version = db.Column(db.Integer, default=0)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def has_permission(self, resource, operation):
        if not self.role:
            return False
        return any(
            p.resource == resource and p.operation == operation
            for p in self.role.permissions
        )

    def __repr__(self):
        return f"<User {self.username} ({self.role.name if self.role else 'no role'})>"


class AuditLog(db.Model):
    """
    Records security-relevant access control events:
      - LOGIN_SUCCESS / LOGIN_FAILURE
      - ACCESS_DENIED (authenticated, but insufficient permission)
      - PRIVILEGE_ESCALATION_ATTEMPT (JWT/role tampering or self-elevation)
      - ROLE_CHANGE (admin action)
    """
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80))       # who triggered it (may be unauthenticated)
    ip_address = db.Column(db.String(45))
    resource = db.Column(db.String(100))
    operation = db.Column(db.String(50))
    detail = db.Column(db.Text)
    severity = db.Column(db.String(20), default="INFO")  # INFO, WARNING, CRITICAL

    def __repr__(self):
        return f"<AuditLog {self.event_type} {self.username} @ {self.timestamp}>"


class Document(db.Model):
    """A persisted 'document' resource — created via the documents:write permission."""
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, default="")
    created_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Report(db.Model):
    """A persisted 'report' resource — created via the reports:write permission."""
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, default="")
    created_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def log_event(event_type, username=None, ip_address=None, resource=None,
              operation=None, detail=None, severity="INFO"):
    entry = AuditLog(
        event_type=event_type,
        username=username,
        ip_address=ip_address,
        resource=resource,
        operation=operation,
        detail=detail,
        severity=severity,
    )
    db.session.add(entry)
    db.session.commit()
    return entry
