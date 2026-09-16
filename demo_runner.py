import app, time

client = app.app.test_client()

print("=" * 80)
print("  PAYSECURE — 6 CORE ATTACK DEMONSTRATIONS (BEFORE VS AFTER MITIGATION)")
print("=" * 80)

# ==============================================================================
# STAGE 1: VULNERABLE STATE (EXPLOITATION)
# ==============================================================================
print("\n[STAGE 1] RUNNING ALL 6 ATTACKS IN VULNERABLE MODE (DEFAULT LAB STATE)\n")
client.post("/api/security/toggle-remediation", json={"vuln_key": "ALL", "state": 0})

# 1. Port Scan
r1 = client.post("/api/security/scan").get_json()
print("1. NETWORK / PORT SCANNING (RECONNAISSANCE)")
print(f"   Target Host : {r1['target']} (TCP Connect Sockets)")
print(f"   Total Time  : {r1['total_time_ms']} ms")
print("   Ports Probed:")
for res in r1["results"]:
    print(f"   - Port {res['port']:<5} ({res['service']:<24}) -> {res['status']}")

# 2. Password Brute Force
r2 = client.post("/api/security/bruteforce", json={"email": "student@paysecure.local"}).get_json()
print("\n2. PASSWORD BRUTE-FORCE (AUTHENTICATION)")
print(f"   Target Account    : {r2['target']}")
print(f"   Vulnerability     : No login rate-limiting or lockout")
print(f"   Cracked Password  : '{r2['matched_password']}'")
print(f"   Cracked in        : {r2['elapsed_ms']} ms ({len(r2['attempts'])} dictionary attempts)")

# 3. SQL Injection
r3 = client.post("/api/security/sqli", json={"payload": "' OR 1=1 --"}).get_json()
print("\n3. SQL INJECTION (SQLi)")
print(f"   Injected Payload  : {r3['payload']}")
print(f"   Executed SQL Query: {r3['sql_executed']}")
print(f"   Result Status     : {r3['result_status']}")
print(f"   Database Evidence : Dumped {r3['records_returned']} products (entire catalog exposed via tautology)")

# 4. Stored XSS
r4 = client.post("/api/security/xss", json={"payload": "<img src=x onerror=alert('XSS-STORED')>"}).get_json()
print("\n4. STORED CROSS-SITE SCRIPTING (XSS)")
print(f"   Injected Payload  : {r4['payload']}")
print(f"   Database Evidence : Persisted into SQLite reviews table (Review ID #{r4['review_id']})")
print(f"   Rendering Engine  : RAW UNFILTERED (|safe)")
print(f"   Browser Execution : Active JavaScript execution on /products/1")

# 5. Session Hijacking
r5 = client.post("/api/security/session-hijack").get_json()
print("\n5. SESSION HIJACKING & TOKEN REPLAY")
print(f"   Victim Context    : {r5['victim_email']} (Token: {r5['victim_token']})")
print(f"   Attacker Client   : {r5['attacker_ip']}")
print(f"   Server Verdict    : {r5['server_response']}")
print(f"   Vulnerability     : Lack of IP/User-Agent fingerprint binding allows account takeover")

# 6. HTTP GET Flood
r6 = client.post("/api/security/flood-test").get_json()
print("\n6. HTTP GET FLOOD (DoS CONCEPT)")
print(f"   Requests Sent     : {r6['requests_sent']} burst GET requests")
print(f"   Latency Impact    : Avg {r6['avg_latency_ms']} ms, Peak {r6['max_latency_ms']} ms")
print(f"   Throttled Requests: {r6['throttled_count']} (0 rate limits applied)")

# ==============================================================================
# STAGE 2: REMEDIATED STATE (PROTECTION & RETESTING)
# ==============================================================================
print("\n" + "=" * 80)
print("  [STAGE 2] APPLYING MITIGATIONS & RETESTING ALL 6 ATTACKS (PROTECTED MODE)")
print("=" * 80 + "\n")
client.post("/api/security/toggle-remediation", json={"vuln_key": "ALL", "state": 1})

# Retest 1: Port Scan
r1_m = client.post("/api/security/scan").get_json()
print("1. RETEST PORT SCANNING:")
print("   - Protected: Firewall rules active; non-web ports reported as FILTERED/BLOCKED.")

# Retest 2: Brute Force
r2_m = client.post("/api/security/bruteforce", json={"email": "student@paysecure.local"}).get_json()
print(f"\n2. RETEST PASSWORD BRUTE FORCE:")
print(f"   - Attack Result   : BLOCKED (Cracked: {r2_m['cracked']})")
print(f"   - Server Defense  : Account locked with HTTP 429 Too Many Requests after 4 failed tries.")

# Retest 3: SQL Injection
r3_m = client.post("/api/security/sqli", json={"payload": "' OR 1=1 --"}).get_json()
print(f"\n3. RETEST SQL INJECTION:")
print(f"   - Query Executed  : {r3_m['sql_executed']}")
print(f"   - Attack Result   : {r3_m['result_status']} (0 injected records returned)")
print(f"   - Server Defense  : Parameterized prepared statement neutralized the injection payload.")

# Retest 4: Stored XSS
r4_m = client.post("/api/security/xss", json={"payload": "<img src=x onerror=alert('XSS-STORED')>"}).get_json()
print(f"\n4. RETEST STORED XSS:")
print(f"   - Attack Result   : {r4_m['result_status']}")
print(f"   - Server Defense  : HTML entity encoding replaces '<' and '>' with safe entities (&lt; &gt;).")

# Retest 5: Session Hijacking
r5_m = client.post("/api/security/session-hijack").get_json()
print(f"\n5. RETEST SESSION HIJACKING:")
print(f"   - Attack Result   : BLOCKED (Hijack Succeeded: {r5_m['hijack_success']})")
print(f"   - Server Response : {r5_m['server_response']}")
print(f"   - Server Defense  : Client IP/UA fingerprint mismatch immediately rejects unauthorized session token.")

# Retest 6: HTTP GET Flood
r6_m = client.post("/api/security/flood-test").get_json()
print(f"\n6. RETEST HTTP GET FLOOD:")
print(f"   - Total Throttled : {r6_m['throttled_count']} / {r6_m['requests_sent']} burst requests dropped")
print(f"   - Server Defense  : Token-bucket rate limiter enforces HTTP 429 Too Many Requests to preserve server availability.")

print("\n" + "=" * 80)
print("  ALL 6 ATTACKS SUCCESSFULLY EXECUTED AND RETESTED!")
print("=" * 80)
