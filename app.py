"""
app.py
Flask application entry point for the RBAC System.
"""

import os
from datetime import datetime

from flask import Flask, request, jsonify, render_template, redirect, url_for, g, make_response

from models import db, User, Role, Permission, AuditLog, Document, Report, ROLE_HIERARCHY, log_event
from auth import (
    generate_token, login_required, require_permission,
    detect_role_field_tampering,
)
from seed import seed_database

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("RBAC_SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "instance", "rbac.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()
        seed_database()

    register_routes(app)
    return app


def register_routes(app):

    # ------------------------------------------------------------------
    # Static / view pages (Bootstrap UI shell — real enforcement happens
    # in the API routes below; the UI only reflects permissions to hide
    # buttons for convenience, per OWASP "don't rely on client for
    # security" guidance)
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login-page")
    def login_page():
        return render_template("login.html")

    @app.route("/dashboard-page")
    def dashboard_page():
        return render_template("dashboard.html")

    @app.route("/admin-page")
    def admin_page():
        return render_template("admin.html")

    # ------------------------------------------------------------------
    # Auth API
    # ------------------------------------------------------------------
    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            log_event(
                "LOGIN_FAILURE", username=username or "(unknown)",
                ip_address=request.remote_addr, severity="INFO",
                detail="Invalid username or password",
            )
            if user:
                user.failed_login_count += 1
                db.session.commit()
            return jsonify({"error": "Invalid credentials"}), 401

        if not user.is_active:
            return jsonify({"error": "Account disabled"}), 403

        user.failed_login_count = 0
        db.session.commit()

        token = generate_token(user)
        log_event("LOGIN_SUCCESS", username=user.username,
                   ip_address=request.remote_addr, severity="INFO")

        resp = make_response(jsonify({
            "token": token,
            "user": {"username": user.username, "role": user.role.name},
        }))
        # httpOnly cookie so the server-rendered UI works too; API clients
        # can instead use the Authorization: Bearer header.
        resp.set_cookie("access_token", token, httponly=True, samesite="Lax", max_age=1800)
        return resp

    @app.route("/api/logout", methods=["POST"])
    def logout():
        resp = make_response(jsonify({"message": "Logged out"}))
        resp.delete_cookie("access_token")
        return resp

    @app.route("/api/me", methods=["GET"])
    @login_required
    def me():
        user = g.current_user
        return jsonify({
            "username": user.username,
            "role": user.role.name,
            "permissions": [f"{p.operation}:{p.resource}" for p in user.role.permissions],
        })

    # ------------------------------------------------------------------
    # Business resources — each demonstrates fine-grained permission
    # checks at the (resource, operation) level.
    # ------------------------------------------------------------------
    @app.route("/api/dashboard", methods=["GET"])
    @login_required
    @require_permission("dashboard", "read")
    def api_dashboard():
        return jsonify({"message": f"Welcome, {g.current_user.username}!",
                         "role": g.current_user.role.name})

    @app.route("/api/documents", methods=["GET"])
    @login_required
    @require_permission("documents", "read")
    def list_documents():
        docs = Document.query.order_by(Document.created_at.desc()).all()
        return jsonify({"documents": [
            {"id": d.id, "name": d.name, "created_by": d.created_by,
             "created_at": d.created_at.isoformat()} for d in docs
        ]})

    @app.route("/api/documents", methods=["POST"])
    @login_required
    @require_permission("documents", "write")
    def create_document():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip() or f"untitled-{datetime.utcnow().strftime('%H%M%S')}.txt"
        doc = Document(name=name, content=data.get("content", ""), created_by=g.current_user.username)
        db.session.add(doc)
        db.session.commit()
        log_event("RESOURCE_CREATED", username=g.current_user.username,
                   resource="documents", operation="write", detail=f"Created document '{name}'")
        return jsonify({"message": f"Document '{name}' created.", "id": doc.id}), 201

    @app.route("/api/documents/<int:doc_id>", methods=["DELETE"])
    @login_required
    @require_permission("documents", "delete")
    def delete_document(doc_id):
        doc = Document.query.get_or_404(doc_id)
        name = doc.name
        db.session.delete(doc)
        db.session.commit()
        log_event("RESOURCE_DELETED", username=g.current_user.username,
                   resource="documents", operation="delete", detail=f"Deleted document '{name}'")
        return jsonify({"message": f"Document '{name}' deleted."})

    @app.route("/api/reports", methods=["GET"])
    @login_required
    @require_permission("reports", "read")
    def list_reports():
        reports = Report.query.order_by(Report.created_at.desc()).all()
        return jsonify({"reports": [
            {"id": r.id, "name": r.name, "created_by": r.created_by,
             "created_at": r.created_at.isoformat()} for r in reports
        ]})

    @app.route("/api/reports", methods=["POST"])
    @login_required
    @require_permission("reports", "write")
    def create_report():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip() or f"report-{datetime.utcnow().strftime('%H%M%S')}.csv"
        report = Report(name=name, content=data.get("content", ""), created_by=g.current_user.username)
        db.session.add(report)
        db.session.commit()
        log_event("RESOURCE_CREATED", username=g.current_user.username,
                   resource="reports", operation="write", detail=f"Created report '{name}'")
        return jsonify({"message": f"Report '{name}' created.", "id": report.id}), 201

    @app.route("/api/reports/<int:report_id>", methods=["DELETE"])
    @login_required
    @require_permission("reports", "delete")
    def delete_report(report_id):
        report = Report.query.get_or_404(report_id)
        name = report.name
        db.session.delete(report)
        db.session.commit()
        log_event("RESOURCE_DELETED", username=g.current_user.username,
                   resource="reports", operation="delete", detail=f"Deleted report '{name}'")
        return jsonify({"message": f"Report '{name}' deleted."})

    # ------------------------------------------------------------------
    # Admin console — user & role management
    # ------------------------------------------------------------------
    @app.route("/api/admin/users", methods=["GET"])
    @login_required
    @require_permission("users", "read")
    def admin_list_users():
        users = User.query.all()
        return jsonify({"users": [
            {"id": u.id, "username": u.username, "email": u.email,
             "role": u.role.name, "is_active": u.is_active}
            for u in users
        ]})

    @app.route("/api/admin/users", methods=["POST"])
    @login_required
    @require_permission("users", "write")
    def admin_create_user():
        actor = g.current_user
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
        role_name = data.get("role") or "User"

        if not username or not email or not password:
            return jsonify({"error": "username, email, and password are required"}), 400
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already in use"}), 409

        # Only Admins may create Admin accounts is already enforced by the
        # users:write gate above, but we still reuse the escalation guard so
        # a non-Admin who somehow reaches this route can't hand out roles
        # above their own rank. Also flags nonsense role names.
        if detect_role_field_tampering(actor, role_name):
            return jsonify({"error": "Invalid or unauthorized role assignment"}), 403

        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"error": "Role does not exist"}), 400

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        log_event("USER_CREATED", username=actor.username,
                   detail=f"Created user '{username}' with role '{role_name}'",
                   ip_address=request.remote_addr, resource="users", operation="write")
        return jsonify({"message": f"User '{username}' created.", "id": user.id}), 201

    @app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
    @login_required
    @require_permission("users", "delete")
    def admin_delete_user(user_id):
        actor = g.current_user
        target = User.query.get_or_404(user_id)

        if target.id == actor.id:
            return jsonify({"error": "You cannot delete your own account"}), 400

        if target.role.name == "Admin":
            remaining_admins = User.query.join(Role).filter(
                Role.name == "Admin", User.id != target.id
            ).count()
            if remaining_admins == 0:
                log_event("ACCESS_DENIED", username=actor.username,
                           detail="Blocked deletion of the last remaining Admin account",
                           ip_address=request.remote_addr, resource="users",
                           operation="delete", severity="WARNING")
                return jsonify({"error": "Cannot delete the last remaining Admin account"}), 400

        username = target.username
        db.session.delete(target)
        db.session.commit()
        log_event("USER_DELETED", username=actor.username,
                   detail=f"Deleted user '{username}'",
                   ip_address=request.remote_addr, resource="users", operation="delete")
        return jsonify({"message": f"User '{username}' deleted."})

    @app.route("/api/admin/users/<int:user_id>/role", methods=["PUT"])
    @login_required
    @require_permission("users", "manage_roles")
    def admin_change_role(user_id):
        actor = g.current_user
        data = request.get_json(silent=True) or {}
        new_role_name = data.get("role", "")

        # Privilege escalation guard: is this role change something the
        # actor is actually entitled to grant?
        if detect_role_field_tampering(actor, new_role_name):
            return jsonify({"error": "Invalid or unauthorized role assignment"}), 403

        target_user = User.query.get_or_404(user_id)
        new_role = Role.query.filter_by(name=new_role_name).first()
        if not new_role:
            return jsonify({"error": "Role does not exist"}), 400

        old_role_name = target_user.role.name
        target_user.role = new_role
        # Invalidate any outstanding JWTs for this user immediately.
        target_user.token_version += 1
        db.session.commit()

        log_event(
            "ROLE_CHANGE", username=actor.username,
            detail=f"Changed {target_user.username}'s role from {old_role_name} to {new_role_name}",
            ip_address=request.remote_addr, resource="users", operation="manage_roles",
            severity="INFO",
        )
        return jsonify({"message": f"{target_user.username} is now {new_role_name}"})

    # ------------------------------------------------------------------
    # Manual permission management
    # ------------------------------------------------------------------
    # Roles whose permissions may be edited via the UI. Admin is
    # deliberately excluded so an admin can't accidentally lock every
    # admin out of the system by revoking a permission they all rely on.
    EDITABLE_ROLES = ("Guest", "User", "Manager")

    @app.route("/api/admin/permissions", methods=["GET"])
    @login_required
    @require_permission("permissions", "manage")
    def admin_list_permissions():
        permissions = Permission.query.order_by(Permission.resource, Permission.operation).all()
        roles = Role.query.order_by(Role.rank).all()
        return jsonify({
            "roles": [r.name for r in roles],
            "editable_roles": list(EDITABLE_ROLES),
            "permissions": [
                {
                    "id": p.id,
                    "resource": p.resource,
                    "operation": p.operation,
                    "granted_to": [r.name for r in p.roles],
                }
                for p in permissions
            ],
        })

    @app.route("/api/admin/permissions", methods=["POST"])
    @login_required
    @require_permission("permissions", "manage")
    def admin_create_permission():
        actor = g.current_user
        data = request.get_json(silent=True) or {}
        resource = (data.get("resource") or "").strip().lower()
        operation = (data.get("operation") or "").strip().lower()

        if not resource or not operation:
            return jsonify({"error": "resource and operation are required"}), 400
        if Permission.query.filter_by(resource=resource, operation=operation).first():
            return jsonify({"error": "That permission already exists"}), 409

        perm = Permission(resource=resource, operation=operation)
        db.session.add(perm)
        db.session.commit()

        log_event("PERMISSION_CREATED", username=actor.username,
                   detail=f"Created new permission '{operation}:{resource}'",
                   ip_address=request.remote_addr, resource=resource, operation=operation)
        return jsonify({"message": f"Permission '{operation}:{resource}' created.", "id": perm.id}), 201

    @app.route("/api/admin/roles/<role_name>/permissions", methods=["PUT"])
    @login_required
    @require_permission("permissions", "manage")
    def admin_update_role_permission(role_name):
        actor = g.current_user
        data = request.get_json(silent=True) or {}
        permission_id = data.get("permission_id")
        grant = bool(data.get("grant"))

        if role_name not in ROLE_HIERARCHY:
            return jsonify({"error": "Unknown role"}), 400
        if role_name not in EDITABLE_ROLES:
            log_event(
                "ACCESS_DENIED", username=actor.username,
                detail=f"Blocked attempt to edit permissions of protected role '{role_name}'",
                ip_address=request.remote_addr, resource="permissions",
                operation="manage", severity="WARNING",
            )
            return jsonify({"error": f"Permissions for '{role_name}' cannot be edited"}), 403

        role = Role.query.filter_by(name=role_name).first()
        perm = Permission.query.get(permission_id)
        if not role or not perm:
            return jsonify({"error": "Role or permission not found"}), 404

        already_has = perm in role.permissions
        if grant and not already_has:
            role.permissions.append(perm)
        elif not grant and already_has:
            role.permissions.remove(perm)
        db.session.commit()

        log_event(
            "PERMISSION_CHANGE", username=actor.username,
            detail=(f"{'Granted' if grant else 'Revoked'} '{perm.operation}:{perm.resource}' "
                    f"{'to' if grant else 'from'} role '{role_name}'"),
            ip_address=request.remote_addr, resource=perm.resource, operation=perm.operation,
        )
        return jsonify({"message": f"Updated '{role_name}' permissions."})

    @app.route("/api/admin/audit-log", methods=["GET"])
    @login_required
    @require_permission("audit_log", "read")
    def admin_audit_log():
        entries = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
        return jsonify({"entries": [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "username": e.username,
                "ip_address": e.ip_address,
                "resource": e.resource,
                "operation": e.operation,
                "detail": e.detail,
                "severity": e.severity,
            } for e in entries
        ]})

    # ------------------------------------------------------------------
    # Error handlers — fail securely, no stack traces leaked
    # ------------------------------------------------------------------
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
