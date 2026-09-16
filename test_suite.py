import app, sqlite3, json

# Test database connection and table counts
con = app.db()
cur = con.cursor()
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables in DB:", sorted(tables))
assert 'users' in tables and 'products' in tables and 'orders' in tables and 'remediation_config' in tables and 'security_events' in tables

prod_count = cur.execute('SELECT COUNT(*) FROM products').fetchone()[0]
cat_count = cur.execute('SELECT COUNT(*) FROM categories').fetchone()[0]
user_count = cur.execute('SELECT COUNT(*) FROM users').fetchone()[0]
rem_count = cur.execute('SELECT COUNT(*) FROM remediation_config').fetchone()[0]

print(f"Products: {prod_count}, Categories: {cat_count}, Users: {user_count}, Remediations: {rem_count}")
assert prod_count >= 14
assert cat_count >= 4
assert rem_count == 6

# Test Flask app client
client = app.app.test_client()

# Ensure fresh unmitigated state for initial tests
client.post('/api/security/toggle-remediation', json={'vuln_key': 'ALL', 'state': 0})

# 1. Test Home page
r_home = client.get('/')
assert r_home.status_code == 200
print("Home Route: OK")

# 2. Test Catalog
r_prod = client.get('/products')
assert r_prod.status_code == 200
print("Products Catalog: OK")

# 3. Test Attack 1: Port Scan API
r_scan = client.post('/api/security/scan')
assert r_scan.status_code == 200
assert r_scan.get_json()['success'] == True
print("Attack 1 (Port Scan API): OK")

# 4. Test Attack 2: Brute Force API
r_bf = client.post('/api/security/bruteforce', json={'email': 'student@paysecure.local'})
assert r_bf.status_code == 200
assert r_bf.get_json()['cracked'] == True
print("Attack 2 (Brute Force API): OK")

# 5. Test Attack 3: SQLi API
r_sqli = client.post('/api/security/sqli', json={'payload': "' OR 1=1 --"})
assert r_sqli.status_code == 200
assert r_sqli.get_json()['result_status'] == 'EXPLOITED'
print("Attack 3 (SQL Injection API): OK")

# 6. Test Attack 4: Stored XSS API
r_xss = client.post('/api/security/xss', json={'payload': '<img src=x onerror=alert(1)>'})
assert r_xss.status_code == 200
assert 'STORED' in r_xss.get_json()['result_status']
print("Attack 4 (Stored XSS API): OK")

# 7. Test Attack 5: Session Hijack API
r_sess = client.post('/api/security/session-hijack')
assert r_sess.status_code == 200
assert r_sess.get_json()['hijack_success'] == True
print("Attack 5 (Session Hijack API): OK")

# 8. Test Attack 6: DoS Flood API
r_dos = client.post('/api/security/flood-test')
assert r_dos.status_code == 200
print("Attack 6 (HTTP GET Flood API): OK")

# 9. Test Remediation Toggle ALL to ON
r_toggle = client.post('/api/security/toggle-remediation', json={'vuln_key': 'ALL', 'state': 1})
assert r_toggle.status_code == 200
print("Toggle All Remediations to PROTECTED: OK")

# 10. Re-test SQLi when mitigated
r_sqli_mit = client.post('/api/security/sqli', json={'payload': "' OR 1=1 --"})
assert r_sqli_mit.get_json()['result_status'] == 'PROTECTED'
print("Retest SQLi (Protected): OK")

# 11. Re-test Brute Force when mitigated
r_bf_mit = client.post('/api/security/bruteforce', json={'email': 'student@paysecure.local'})
assert r_bf_mit.get_json()['cracked'] == False
print("Retest Brute Force (Protected / Rate Limited): OK")

# 12. Test Security Report Endpoint
r_rep = client.get('/api/security/report')
assert r_rep.status_code == 200
assert 'findings' in r_rep.get_json()
print("Assessment Report Endpoint: OK")

# Reset remediations for fresh demo
client.post('/api/security/toggle-remediation', json={'vuln_key': 'ALL', 'state': 0})
con.close()
print("\nALL 12 VERIFICATION TESTS PASSED SUCCESSFULLY!")
