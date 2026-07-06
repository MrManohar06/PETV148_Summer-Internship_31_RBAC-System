from app import create_app
import jwt as pyjwt
from datetime import datetime, timedelta, timezone

app = create_app()
client = app.test_client()


def login(u, p):
    r = client.post('/api/login', json={'username': u, 'password': p})
    return r.get_json()['token']


print('--- Guest tries to read documents (expect 403) ---')
tok_guest = login('guest', 'Guest!2345')
r = client.get('/api/documents', headers={'Authorization': f'Bearer {tok_guest}'})
print(r.status_code, r.get_json())

print('\n--- User (alice) reads documents (expect 200) ---')
tok_alice = login('alice', 'User!2345')
r = client.get('/api/documents', headers={'Authorization': f'Bearer {tok_alice}'})
print(r.status_code, r.get_json())

print('\n--- User (alice) tries to write documents (expect 403) ---')
r = client.post('/api/documents', headers={'Authorization': f'Bearer {tok_alice}'}, json={})
print(r.status_code, r.get_json())

print('\n--- Manager writes a document (expect 201) ---')
tok_mgr = login('manager', 'Manager!2345')
r = client.post('/api/documents', headers={'Authorization': f'Bearer {tok_mgr}'}, json={})
print(r.status_code, r.get_json())

print('\n--- Manager tries to change roles (expect 403, lacks manage_roles) ---')
r = client.put('/api/admin/users/1/role', headers={'Authorization': f'Bearer {tok_mgr}'}, json={'role': 'Admin'})
print(r.status_code, r.get_json())

print('\n--- Admin promotes alice to Manager (expect 200) ---')
tok_admin = login('admin', 'Admin!2345')
users = client.get('/api/admin/users', headers={'Authorization': f'Bearer {tok_admin}'}).get_json()['users']
alice_id = [u['id'] for u in users if u['username'] == 'alice'][0]
r = client.put(f'/api/admin/users/{alice_id}/role', headers={'Authorization': f'Bearer {tok_admin}'}, json={'role': 'Manager'})
print(r.status_code, r.get_json())

print('\n--- STALE TOKEN TEST: alice reuses her OLD (pre-promotion) token (expect 401, token_version mismatch) ---')
r = client.get('/api/documents', headers={'Authorization': f'Bearer {tok_alice}'})
print(r.status_code, r.get_json())

print('\n--- FORGED TOKEN TEST: attacker forges a token claiming role=Admin, signed with wrong secret (expect 401) ---')
forged = pyjwt.encode(
    {'sub': alice_id, 'username': 'alice', 'role': 'Admin', 'tv': 99,
     'iat': datetime.now(timezone.utc), 'exp': datetime.now(timezone.utc) + timedelta(minutes=5)},
    'WRONG-SECRET', algorithm='HS256')
r = client.get('/api/admin/users', headers={'Authorization': f'Bearer {forged}'})
print(r.status_code, r.get_json())

print('\n--- ROLE-CLAIM TAMPER TEST: valid signature (correct secret) but role claim forged to Admin ---')
# Simulates an attacker who somehow knows the secret / a bug that lets them edit claims
# but the server still cross-checks against the DB's authoritative role.
tampered = pyjwt.encode(
    {'sub': alice_id, 'username': 'alice', 'role': 'Admin', 'tv': 1,
     'iat': datetime.now(timezone.utc), 'exp': datetime.now(timezone.utc) + timedelta(minutes=5)},
    app.config['SECRET_KEY'], algorithm='HS256')
r = client.get('/api/admin/users', headers={'Authorization': f'Bearer {tampered}'})
print(r.status_code, r.get_json())

print('\n--- Manager (now alice, freshly logged in) attempts self-escalation to Admin via role field (expect 403) ---')
tok_alice_new = login('alice', 'User!2345')
r = client.put(f'/api/admin/users/{alice_id}/role', headers={'Authorization': f'Bearer {tok_alice_new}'}, json={'role': 'Admin'})
print(r.status_code, r.get_json())

print('\n--- Admin creates a new user (expect 201) ---')
r = client.post('/api/admin/users', headers={'Authorization': f'Bearer {tok_admin}'},
                 json={'username': 'bob', 'email': 'bob@example.com', 'password': 'Bobby!2345', 'role': 'User'})
print(r.status_code, r.get_json())

print('\n--- Manager tries to create a new user (expect 403, lacks users:write) ---')
r = client.post('/api/admin/users', headers={'Authorization': f'Bearer {tok_mgr}'},
                 json={'username': 'eve', 'email': 'eve@example.com', 'password': 'Evilpass1', 'role': 'User'})
print(r.status_code, r.get_json())

print('\n--- Admin tries to create a duplicate username (expect 409) ---')
r = client.post('/api/admin/users', headers={'Authorization': f'Bearer {tok_admin}'},
                 json={'username': 'bob', 'email': 'bob2@example.com', 'password': 'Bobby!2345', 'role': 'User'})
print(r.status_code, r.get_json())

print('\n--- Admin deletes bob (expect 200) ---')
users = client.get('/api/admin/users', headers={'Authorization': f'Bearer {tok_admin}'}).get_json()['users']
bob_id = [u['id'] for u in users if u['username'] == 'bob'][0]
r = client.delete(f'/api/admin/users/{bob_id}', headers={'Authorization': f'Bearer {tok_admin}'})
print(r.status_code, r.get_json())

print('\n--- Admin tries to delete their own account (expect 400) ---')
admin_id = [u['id'] for u in users if u['username'] == 'admin'][0]
r = client.delete(f'/api/admin/users/{admin_id}', headers={'Authorization': f'Bearer {tok_admin}'})
print(r.status_code, r.get_json())

print('\n--- Admin manually adds a new permission "approve:invoices" (expect 201) ---')
r = client.post('/api/admin/permissions', headers={'Authorization': f'Bearer {tok_admin}'},
                 json={'resource': 'invoices', 'operation': 'approve'})
print(r.status_code, r.get_json())
new_perm_id = r.get_json()['id']

print('\n--- Admin grants "approve:invoices" to Manager (expect 200) ---')
r = client.put('/api/admin/roles/Manager/permissions', headers={'Authorization': f'Bearer {tok_admin}'},
                json={'permission_id': new_perm_id, 'grant': True})
print(r.status_code, r.get_json())

print('\n--- Admin tries to edit permissions of the protected Admin role (expect 403) ---')
r = client.put('/api/admin/roles/Admin/permissions', headers={'Authorization': f'Bearer {tok_admin}'},
                json={'permission_id': new_perm_id, 'grant': False})
print(r.status_code, r.get_json())

print('\n--- Manager creates a persisted report (expect 201) ---')
r = client.post('/api/reports', headers={'Authorization': f'Bearer {tok_mgr}'}, json={'name': 'headcount.csv'})
print(r.status_code, r.get_json())

print('\n--- User (alice) lists documents, sees persisted docs (expect 200) ---')
r = client.get('/api/documents', headers={'Authorization': f'Bearer {tok_alice_new}'})
print(r.status_code, r.get_json())

print('\n--- FULL AUDIT LOG ---')
r = client.get('/api/admin/audit-log', headers={'Authorization': f'Bearer {tok_admin}'})
for e in r.get_json()['entries'][::-1]:
    print(f"{e['severity']:8s} | {e['event_type']:28s} | {str(e['username']):8s} | {e['detail']}")
