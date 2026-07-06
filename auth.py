"""
auth.py
JWT-based authentication and RBAC enforcement.

Key security properties (mapped to OWASP Access Control Cheat Sheet):

1. Deny by default: any route protected by @require_permission rejects
   access unless an explicit permission grant is found.
2. Enforce on the server, not the client: role claims in the JWT are
   only ever used AFTER verifying the token's signature server-side.
   The Bootstrap UI may hide buttons for a Guest, but every backend
   route re-checks permissions independently (never trust the client).
3. Fail securely: a malformed/expired/tampered token or unknown role
   results in a 401/403, never a fallback to an elevated default role.
4. Detect privilege escalation:
     a. Token/role tampering  - the role embedded in the JWT claim is
        cross-checked against the role currently stored in the DB for
        that user_id. A mismatch means either the token was forged/
        edited, or the DB role changed after issuance (e.g. a demotion) -
        either way, access is denied and the event is logged.
     b. Horizontal/vertical escalation via request payload - e.g. a
        User-role account sending a "role": "Admin" field on a
        profile-update request. This is detected in the routes that
        accept role fields, using detect_role_field_tampering().
"""

import functools
from datetime import datetime, timedelta, timezone

import jwt
from flask import request, jsonify, current_app, g

from models import db, User, Role, ROLE_HIERARCHY, log_event

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = 30


def generate_token(user: User) -> str:
    """Issue a JWT carrying the user's id, username, role, and token_version."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role.name,
        "tv": user.token_version,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    """Decode + verify signature/expiry. Raises jwt exceptions on failure."""
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=[JWT_ALGORITHM])


def _extract_token_from_request():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    # fall back to a cookie, so the same decorator works for the
    # server-rendered Bootstrap UI as well as an API client
    return request.cookies.get("access_token")


def login_required(view):
    """
    Verifies the JWT and re-derives the user's *current* role from the
    database (never trusting the role claim alone), then stores both the
    claim and the authoritative DB user on flask.g for downstream checks.
    """
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_token_from_request()
        if not token:
            log_event("ACCESS_DENIED", detail="Missing token",
                       ip_address=request.remote_addr, resource=request.path,
                       severity="INFO")
            return jsonify({"error": "Authentication required"}), 401

        try:
            claims = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            log_event("PRIVILEGE_ESCALATION_ATTEMPT",
                       detail="Invalid/forged JWT signature presented",
                       ip_address=request.remote_addr, resource=request.path,
                       severity="CRITICAL")
            return jsonify({"error": "Invalid token"}), 401

        user = User.query.get(claims.get("sub"))
        if not user or not user.is_active:
            return jsonify({"error": "Invalid session"}), 401

        # --- Privilege escalation detection: token/role tampering ---------
        # Token version check: catches tokens issued before a forced
        # logout/role-change (admin bumped token_version).
        if claims.get("tv") != user.token_version:
            log_event("ACCESS_DENIED",
                       username=user.username,
                       detail="Stale token_version presented (session was invalidated)",
                       ip_address=request.remote_addr, resource=request.path,
                       severity="WARNING")
            return jsonify({"error": "Session invalidated, please log in again"}), 401

        # Role claim vs. authoritative DB role: catches forged/edited
        # tokens (e.g. a User account editing its own JWT payload to
        # claim "Admin") as well as tokens issued before a demotion.
        if claims.get("role") != user.role.name:
            log_event(
                "PRIVILEGE_ESCALATION_ATTEMPT",
                username=user.username,
                detail=(f"JWT role claim '{claims.get('role')}' does not match "
                        f"authoritative DB role '{user.role.name}'"),
                ip_address=request.remote_addr,
                resource=request.path,
                severity="CRITICAL",
            )
            return jsonify({"error": "Role mismatch detected, access denied"}), 403

        g.current_user = user
        g.token_claims = claims
        return view(*args, **kwargs)

    return wrapper


def require_permission(resource, operation):
    """
    Deny-by-default authorization decorator. Must be stacked *under*
    @login_required so g.current_user is populated. Always re-checks the
    permission against the database (PermissionAssignment), never against
    the JWT claim alone, so that permission changes take effect immediately
    without waiting for token expiry.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return jsonify({"error": "Authentication required"}), 401

            if not user.has_permission(resource, operation):
                log_event(
                    "ACCESS_DENIED",
                    username=user.username,
                    detail=f"Role '{user.role.name}' lacks permission",
                    ip_address=request.remote_addr,
                    resource=resource,
                    operation=operation,
                    severity="WARNING",
                )
                return jsonify({"error": "Forbidden: insufficient permissions"}), 403

            return view(*args, **kwargs)
        return wrapper
    return decorator


def detect_role_field_tampering(requesting_user: User, submitted_role_name: str):
    """
    Vertical privilege escalation check for endpoints that accept a
    "role" field in the request body (e.g. a self-service profile
    update that should NOT be able to change role, or an admin
    role-change endpoint that should reject self-elevation beyond the
    admin's own rank).

    Returns True (and logs a CRITICAL event) if the submitted role
    represents an escalation the requesting_user is not entitled to
    grant.
    """
    if submitted_role_name not in ROLE_HIERARCHY:
        return True  # unknown role name is itself suspicious / invalid

    requester_rank = ROLE_HIERARCHY.get(requesting_user.role.name, -1)
    target_rank = ROLE_HIERARCHY[submitted_role_name]

    # Only Admins may assign roles at all; an Admin may not grant a role
    # of a HIGHER rank than their own (defense in depth - in this model
    # Admin is the ceiling, but this guards against future role additions).
    is_escalation = requesting_user.role.name != "Admin" or target_rank > requester_rank

    if is_escalation:
        log_event(
            "PRIVILEGE_ESCALATION_ATTEMPT",
            username=requesting_user.username,
            detail=(f"Attempted to assign role '{submitted_role_name}' "
                    f"(requester role: '{requesting_user.role.name}')"),
            ip_address=request.remote_addr,
            resource="users",
            operation="manage_roles",
            severity="CRITICAL",
        )
    return is_escalation
