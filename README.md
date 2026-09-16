# PaySecure E-Commerce Platform & Cybersecurity Assessment Lab

A full-fledged simulated e-commerce payment platform integrated with a **Security Operations Center (SOC)** and a complete **Ethical Hacking Penetration Testing Workflow** mapped to university cybersecurity modules and OWASP/NIST guidelines.

---

## 🎯 Project Overview & Methodology

PaySecure transforms standard cybersecurity demonstrations into a realistic enterprise environment:

```
Planning & Reconnaissance ➔ Scanning ➔ Controlled Exploitation ➔ Maintaining Access ➔ Reporting ➔ Remediation & Retesting
```

1. **Realistic Storefront**: 14+ database products across 4 categories, interactive shopping cart, order placement, customer checkout, invoices, and persistent reviews.
2. **Relational Database Engine**: SQLite 3 (`paysecure.db`) managing 12 relational tables for business data, security telemetry, audit trails, and remediation states.
3. **Security Operations Center (SOC)**: Browser-based dashboard featuring real-time risk gauges, live attack runners, before/after code diffs, telemetry event streams, and viva assessment report generator.
4. **Interactive CLI & Web Exploitation**: Both CLI (`python attack_simulator.py`) and Web SOC triggers for all 6 core attack vectors.

---

## 🛡️ The Six Core Attack Demonstrations

| # | Attack Vector | Ethical Hacking Phase | Vulnerable Target Surface | Mitigated Defense |
|---|---------------|-----------------------|---------------------------|-------------------|
| **1** | **Network / Port Scanning** | Phase 1 & 2: Reconnaissance | Probes diagnostic ports on 127.0.0.1 | Firewall port filtering & ingress rules |
| **2** | **Password Brute-Force** | Phase 3: Controlled Exploitation | Rapid password guessing against `/login` | Account lockout & rate limiting (`HTTP 429`) |
| **3** | **SQL Injection (SQLi)** | Phase 3: Controlled Exploitation | Query concatenation in `/products?q=` | Parameterized prepared statements (`?`) |
| **4** | **Stored XSS** | Phase 3: Controlled Exploitation | Unsanitized reviews stored in SQLite | Contextual HTML output encoding (`|e`) |
| **5** | **Session Hijacking** | Phase 4: Maintaining Access | Replay of intercepted `PAYSESSION` cookie | HttpOnly flags + client fingerprint binding |
| **6** | **HTTP GET Flood / DoS** | Phase 3: Controlled Exploitation | Burst requests against `/health` | Token-bucket rate limiter (`HTTP 429`) |

---

## 🚀 How to Run

### Step 1: Install Dependencies & Start the Web Server (Terminal 1)
```powershell
cd D:\PaySecure_CyberSecurity_Lab_Final
python -m pip install -r requirements.txt
python app.py
```

### Step 2: Access the Application in Your Browser
- **Customer Storefront**: [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Security Operations Center (SOC)**: [http://127.0.0.1:5000/security](http://127.0.0.1:5000/security)
- **Default Lab Credentials**:
  - Student: `student@paysecure.local` / `paysecure123`
  - Admin: `admin@paysecure.local` / `admin-lab-2026`

### Step 3: Run the CLI Penetration Testing Suite (Terminal 2 - Optional)
```powershell
cd D:\PaySecure_CyberSecurity_Lab_Final
python attack_simulator.py
```

---

## 🎓 Step-by-Step Viva / Professor Demonstration Script

1. **Show Normal Commerce**: Browse `/products`, filter by categories, view product details, add items to cart, and complete a checkout to demonstrate live SQLite order and payment generation.
2. **Open Security Operations Center (SOC)**: Navigate to `/security`. Point out the active telemetry, risk gauges, and the 6 ethical hacking workflow tabs.
3. **Demonstrate Reconnaissance (Attack 1)**: Run the TCP Port Scan to identify open services on localhost.
4. **Demonstrate Exploitation (Attacks 2-6)**:
   - **Brute Force**: Show candidate dictionary cracking `student@paysecure.local` and logging failed attempts in the database.
   - **SQL Injection**: Inject `' OR 1=1 --` into the search bar or SOC runner to dump the database and show altered query logic.
   - **Stored XSS**: Post a review payload and show it persisting in SQLite and executing in the browser.
   - **Session Hijacking**: Open Tab 4 (Dual Panel) to show an attacker on a rogue IP replaying the victim's session token and hijacking access.
   - **HTTP Flood**: Execute 35 burst requests and observe latency telemetry.
5. **Show Remediation Switchboard**: Open Tab 5, inspect side-by-side code comparisons (Vulnerable vs Remediated), and click **"Enable All Protections"**.
6. **Retest All 6 Attacks**: Click **"Run All 6 Security Tests"**. Observe that SQL injection is neutralized, brute-force is rate limited (HTTP 429), XSS is escaped, session replay is rejected, and traffic is throttled.
7. **Generate Assessment Report**: Open Tab 6 to present the complete, printable Penetration Testing & Vulnerability Assessment Report to the professor.
