"""
seed.py
Seeds the database with the RBAC role/permission matrix and demo users.

Permission matrix (fine-grained, per-resource, per-operation) —
this is the "PA" (Permission Assignment) relation from NIST SP 800-162:

Resource        Operation   Guest   User    Manager   Admin
--------------------------------------------------------------
dashboard       read          X       X        X        X
documents       read                  X        X        X
documents       write                          X        X
documents       delete                                  X
reports         read                           X        X
reports         write                                    X
users           read                                     X
users           write                                    X
users           manage_roles                              X
audit_log       read                                     X
settings        manage                                    X
"""

from models import db, Role, Permission, User, ROLE_HIERARCHY

PERMISSION_MATRIX = {
    "Guest": [
        ("dashboard", "read"),
    ],
    "User": [
        ("dashboard", "read"),
        ("documents", "read"),
    ],
    "Manager": [
        ("dashboard", "read"),
        ("documents", "read"),
        ("documents", "write"),
        ("reports", "read"),
    ],
    "Admin": [
        ("dashboard", "read"),
        ("documents", "read"),
        ("documents", "write"),
        ("documents", "delete"),
        ("reports", "read"),
        ("reports", "write"),
        ("reports", "delete"),
        ("users", "read"),
        ("users", "write"),
        ("users", "delete"),
        ("users", "manage_roles"),
        ("permissions", "manage"),
        ("audit_log", "read"),
        ("settings", "manage"),
    ],
}

DEMO_USERS = [
    ("admin", "admin@example.com", "Admin!2345", "Admin"),
    ("manager", "manager@example.com", "Manager!2345", "Manager"),
    ("alice", "alice@example.com", "User!2345", "User"),
    ("guest", "guest@example.com", "Guest!2345", "Guest"),
]


def seed_database():
    # 1. Create roles
    roles = {}
    for name, rank in ROLE_HIERARCHY.items():
        role = Role.query.filter_by(name=name).first()
        if not role:
            role = Role(name=name, rank=rank, description=f"{name} role")
            db.session.add(role)
        roles[name] = role
    db.session.commit()

    # 2. Create permissions + assign to roles
    perm_cache = {}
    for role_name, perms in PERMISSION_MATRIX.items():
        role = roles[role_name]
        for resource, operation in perms:
            key = (resource, operation)
            perm = perm_cache.get(key) or Permission.query.filter_by(
                resource=resource, operation=operation
            ).first()
            if not perm:
                perm = Permission(resource=resource, operation=operation)
                db.session.add(perm)
                db.session.flush()
            perm_cache[key] = perm
            if perm not in role.permissions:
                role.permissions.append(perm)
    db.session.commit()

    # 3. Create demo users
    for username, email, password, role_name in DEMO_USERS:
        if not User.query.filter_by(username=username).first():
            user = User(username=username, email=email, role=roles[role_name])
            user.set_password(password)
            db.session.add(user)
    db.session.commit()

    print("Database seeded: roles, permissions, and demo users created.")
    print("Demo credentials:")
    for username, _, password, role_name in DEMO_USERS:
        print(f"  {username:10s} / {password:15s} -> {role_name}")
