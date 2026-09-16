import requests

BASE = "http://127.0.0.1:5000"

# Reset to unmitigated state
requests.post(f"{BASE}/api/security/toggle-remediation", json={"vuln_key": "ALL", "state": 0})

print("================================================================================")
print("  INDIVIDUAL ATTACK EXECUTION TRACE (PAYSECURE LAB)")
print("================================================================================\n")

# ATTACK 1: PORT SCANNING
print("--- [ATTACK 1] NETWORK & PORT SCANNING (RECONNAISSANCE) ---")
r1 = requests.post(f"{BASE}/api/security/scan").json()
print(f"Target: {r1['target']} | Scan Time: {r1['total_time_ms']} ms")
for p in r1['results']:
    print(f"  Port {p['port']:<5} ({p['service']:<24}) -> {p['status']}")

# ATTACK 2: BRUTE FORCE
print("\n--- [ATTACK 2] PASSWORD BRUTE FORCE (AUTHENTICATION) ---")
r2 = requests.post(f"{BASE}/api/security/bruteforce", json={"email": "student@paysecure.local"}).json()
print(f"Target Account: {r2['target']}")
print(f"Cracked Status: {r2['cracked']} | Recovered Password: '{r2['matched_password']}'")
for a in r2['attempts']:
    print(f"  Attempt #{a['attempt']}: {a['password']:<14} -> {a['status']}")

# ATTACK 3: SQL INJECTION
print("\n--- [ATTACK 3] SQL INJECTION (DATABASE ACCESS) ---")
r3 = requests.post(f"{BASE}/api/security/sqli", json={"payload": "' OR 1=1 --"}).json()
print(f"Injected Payload : {r3['payload']}")
print(f"Executed SQL     : {r3['sql_executed']}")
print(f"Result Status    : {r3['result_status']}")
print(f"Database Impact  : Returned {r3['records_returned']} items across database")

# ATTACK 4: STORED XSS
print("\n--- [ATTACK 4] STORED CROSS-SITE SCRIPTING (WEB FRONTEND) ---")
r4 = requests.post(f"{BASE}/api/security/xss", json={"payload": "<img src=x onerror=alert('XSS-DEMO')>"}).json()
print(f"Stored Payload   : {r4['payload']}")
print(f"SQLite Review ID : #{r4['review_id']}")
print(f"Result Status    : {r4['result_status']}")

# ATTACK 5: SESSION HIJACKING
print("\n--- [ATTACK 5] SESSION HIJACKING (MAINTAINING ACCESS) ---")
r5 = requests.post(f"{BASE}/api/security/session-hijack").json()
print(f"Victim Context   : {r5['victim_email']}")
print(f"Stolen Token     : {r5['victim_token']}")
print(f"Attacker Host    : {r5['attacker_ip']}")
print(f"Server Response  : {r5['server_response']}")

# ATTACK 6: HTTP GET FLOOD
print("\n--- [ATTACK 6] HTTP GET FLOOD (AVAILABILITY TESTING) ---")
r6 = requests.post(f"{BASE}/api/security/flood-test").json()
print(f"Burst Count      : {r6['requests_sent']} requests")
print(f"Average Latency  : {r6['avg_latency_ms']} ms (Peak: {r6['max_latency_ms']} ms)")
print(f"Throttled        : {r6['throttled_count']}")

print("\n================================================================================")
print("  ALL 6 ATTACKS SEPARATELY EXECUTED AGAINST LIVE 127.0.0.1:5000 APPLICATION")
print("================================================================================")
