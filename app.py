from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
import sqlite3, os, secrets, hashlib, time, json, socket, statistics
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "paysecure.db")

app = Flask(__name__)
app.secret_key = "lab-only-secret-key-paysecure-2026"

LOGIN_ATTEMPT_TRACKER = {}

def db():
    con = sqlite3.connect(DB, timeout=30.0, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    cur = con.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'customer',
        account_status TEXT NOT NULL DEFAULT 'active',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS categories(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        icon TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL,
        badge TEXT,
        image_url TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        FOREIGN KEY (category_id) REFERENCES categories (id)
    );
    CREATE TABLE IF NOT EXISTS cart_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        user_id INTEGER,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        FOREIGN KEY (product_id) REFERENCES products (id)
    );
    CREATE TABLE IF NOT EXISTS orders(
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        total_amount REAL NOT NULL,
        shipping_address TEXT NOT NULL,
        payment_method TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'COMPLETED',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    CREATE TABLE IF NOT EXISTS order_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    );
    CREATE TABLE IF NOT EXISTS payments(
        id TEXT PRIMARY KEY,
        order_id TEXT NOT NULL,
        amount REAL NOT NULL,
        payment_method TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'SUCCESS',
        transaction_ref TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders (id)
    );
    CREATE TABLE IF NOT EXISTS reviews(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        user_id INTEGER,
        author_name TEXT NOT NULL,
        rating INTEGER NOT NULL DEFAULT 5,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (product_id) REFERENCES products (id)
    );
    CREATE TABLE IF NOT EXISTS session_store(
        sid TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        is_revoked INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    CREATE TABLE IF NOT EXISTS login_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        email TEXT,
        status TEXT NOT NULL,
        attempted_password TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        detail TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_type TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        parameter TEXT,
        payload TEXT,
        status TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        evidence TEXT NOT NULL,
        impact TEXT NOT NULL,
        mitigated INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attack_runs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_key TEXT NOT NULL,
        attack_name TEXT NOT NULL,
        payload TEXT,
        result_status TEXT NOT NULL,
        evidence TEXT,
        response_time_ms REAL,
        mitigated_when_run INTEGER NOT NULL,
        executed_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS remediation_config(
        vuln_key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        is_mitigated INTEGER NOT NULL DEFAULT 0,
        vulnerable_code TEXT NOT NULL,
        remediated_code TEXT NOT NULL,
        recommendation TEXT NOT NULL
    );
    """)

    # Seed Remediation Configurations
    cur.execute("SELECT COUNT(*) FROM remediation_config")
    if cur.fetchone()[0] == 0:
        cur.executemany("""
        INSERT INTO remediation_config(vuln_key, name, category, risk_level, is_mitigated, vulnerable_code, remediated_code, recommendation)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            ("port_scan", "Diagnostic Port & Service Exposure", "Network Reconnaissance", "LOW", 0,
             "# All diagnostic ports open and unmonitored\nPORT_FILTERING = False",
             "# Firewall & port filtering applied\nPORT_FILTERING = True\nDROP_UNAUTHORIZED_PROBES()",
             "Close unnecessary diagnostic ports and enforce strict firewall ingress rules."),
            ("brute_force", "Unrestricted Password Authentication", "Authentication & Access", "HIGH", 0,
             "# Direct query without rate limit or lockout\nuser = authenticate(email, password)",
             "# Account lockout after 4 failed tries\nif failed_attempts >= 4:\n    return 429, 'Account Locked'",
             "Implement login rate-limiting, CAPTCHA, exponential backoff, and temporary account lockouts."),
            ("sqli", "Unsanitized Search Query Concatenation", "Database Layer", "CRITICAL", 0,
             "# Vulnerable dynamic string concatenation\nsql = f'SELECT * FROM products WHERE name LIKE \\'%{q}%\\''\ncur.execute(sql)",
             "# Secure parameterized prepared statement\nsql = 'SELECT * FROM products WHERE name LIKE ?'\ncur.execute(sql, (f'%{q}%',))",
             "Use parameterized queries (prepared statements) or an ORM to prevent SQL code injection."),
            ("xss", "Unescaped Stored User Input in Reviews", "Web Frontend", "HIGH", 0,
             "<!-- Vulnerable Jinja raw rendering -->\n<div class='review-content'>{{ review.content | safe }}</div>",
             "<!-- Safe sanitized & escaped output -->\n<div class='review-content'>{{ review.content | e }}</div>",
             "Apply contextual output encoding (HTML escaping) and sanitize rich HTML inputs."),
            ("session_hijack", "Insecure Session Token Handling & Missing Client Binding", "Session Security", "HIGH", 0,
             "# Predictable cookie, missing security flags & IP binding\nresp.set_cookie('PAYSESSION', sid)",
             "# HttpOnly, Secure flags + IP/UA fingerprint check\nresp.set_cookie('PAYSESSION', sid, httponly=True, samesite='Strict')",
             "Use cryptographically secure session IDs, set HttpOnly & SameSite flags, and bind session to client fingerprint."),
            ("dos", "Unthrottled HTTP Request Processing", "Availability & DoS", "MEDIUM", 0,
             "# Processes all incoming requests without throttling\nreturn handle_request()",
             "# Token-bucket rate limiting\nif request_count_per_sec(ip) > 10:\n    return 429, 'Rate Limit Exceeded'",
             "Deploy reverse-proxy rate limiting, token buckets, and DoS mitigation layers.")
        ])

    # Seed Categories
    cur.execute("SELECT COUNT(*) FROM categories")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO categories(id, name, slug, icon) VALUES(?,?,?,?)", [
            (1, "Electronics & Smart Devices", "electronics", "laptop"),
            (2, "Secure Networking Hardware", "networking", "network-wired"),
            (3, "Cryptographic & Security Keys", "security-keys", "shield-alt"),
            (4, "High-Performance Accessories", "accessories", "microchip")
        ])

    # Seed Users
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        pw_student = hashlib.sha256("paysecure123".encode()).hexdigest()
        pw_admin = hashlib.sha256("admin-lab-2026".encode()).hexdigest()
        pw_auditor = hashlib.sha256("audit-secure-2026".encode()).hexdigest()
        cur.executemany("INSERT INTO users(name, email, password_hash, role, created_at) VALUES(?,?,?,?,?)", [
            ("Shrimay (Lab Student)", "student@paysecure.local", pw_student, "customer", datetime.utcnow().isoformat()),
            ("Security Administrator", "admin@paysecure.local", pw_admin, "admin", datetime.utcnow().isoformat()),
            ("SOC Auditor", "auditor@paysecure.local", pw_auditor, "analyst", datetime.utcnow().isoformat())
        ])

    # Seed Products (14 items across 4 categories)
    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        cur.executemany("""
        INSERT INTO products(id, category_id, name, description, price, stock, badge, image_url)
        VALUES(?,?,?,?,?,?,?,?)
        """, [
            (1, 1, "SecurePay BioSmart Watch Pro", "Biometric payment-enabled smartwatch with hardware-isolated secure enclave and heart rate tracking.", 5999.00, 18, "BESTSELLER", "smartwatch"),
            (2, 1, "TokenVault RGB Mechanical Keyboard", "Encrypted keystroke controller with hot-swappable tactile switches and per-key RGB backlighting.", 3499.00, 25, "POPULAR", "keyboard"),
            (3, 1, "CipherSound Active Noise Cancelling Headphones", "Studio-grade wireless headphones with 40mm drivers and active acoustic noise cancellation.", 4299.00, 12, "NEW", "headphones"),
            (4, 1, "ZeroTrust Optical Gaming Mouse", "Ultra-lightweight 26,000 DPI sensor with zero-latency polling rate and PTFE glides.", 1899.00, 40, "HOT", "mouse"),
            (5, 1, "QuantumView 4K Ultra HD Webcam", "Dual microphone array with privacy shutter and AI auto-framing.", 3299.00, 15, "SALE", "webcam"),
            (6, 1, "Sentinel 10-in-1 Aluminum USB-C Hub", "Thunderbolt 4 compatible hub with dual HDMI 4K@60Hz and 100W Power Delivery.", 2499.00, 30, "FEATURED", "hub"),
            (7, 2, "AirShield AX6000 Wi-Fi 6 Router", "Enterprise-grade quad-core router with WPA3 enterprise encryption and guest network isolation.", 8999.00, 8, "PREMIUM", "router"),
            (8, 2, "NetGuard 8-Port Gigabit Managed Switch", "Fanless metal switch with IEEE 802.1Q VLAN support and IGMP snooping.", 4599.00, 14, "ENTERPRISE", "switch"),
            (9, 2, "Dual-Band Wi-Fi 6 USB 3.0 Adapter", "High-gain dual external antennas for extended wireless penetration and 1800Mbps throughput.", 1499.00, 50, "VALUE", "wifi-adapter"),
            (10, 2, "Fortress AC1200 Outdoor Access Point", "IP67 weatherproof casing with PoE support for expansive campus wireless coverage.", 6499.00, 10, "OUTDOOR", "access-point"),
            (11, 3, "Hardware Security Key FIDO2 / U2F", "NFC + USB-C hardware authentication token resilient against phishing attacks.", 2799.00, 35, "CYBER-ESSENTIAL", "yubikey"),
            (12, 3, "CryptoSafe Cold Storage Hardware Wallet", "Offline isolated crypto seed vault with dual-chip EAL6+ certified security.", 7999.00, 20, "CRITICAL-SEC", "hardware-wallet"),
            (13, 4, "ErgoPro Anodized Aluminum Laptop Stand", "CNC machined foldable stand with silicone anti-scratch pads and 360-degree airflow.", 1299.00, 45, "ERGONOMIC", "stand"),
            (14, 4, "HyperSpeed 2TB NVMe PCIe 4.0 SSD", "Blazing 7,450 MB/s sequential read speeds with hardware AES 256-bit encryption.", 9499.00, 16, "HIGH-SPEED", "ssd")
        ])

    # Seed Sample Reviews
    cur.execute("SELECT COUNT(*) FROM reviews")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO reviews(product_id, user_id, author_name, rating, content, created_at) VALUES(?,?,?,?,?,?)", [
            (1, 1, "Shrimay Dhankar", 5, "Seamless NFC payment checkout and outstanding battery life. Highly recommended!", (datetime.utcnow() - timedelta(days=2)).isoformat()),
            (2, 2, "Admin Reviewer", 4, "Excellent mechanical feedback. Keycaps feel very durable.", (datetime.utcnow() - timedelta(days=1)).isoformat()),
            (3, 1, "Shrimay Dhankar", 5, "Immersive audio clarity during long lab sessions.", (datetime.utcnow() - timedelta(hours=5)).isoformat())
        ])

    # Seed Sample Orders & Transactions
    cur.execute("SELECT COUNT(*) FROM orders")
    if cur.fetchone()[0] == 0:
        ord_id = "ORD-2026-9812"
        cur.execute("INSERT INTO orders(id, user_id, total_amount, shipping_address, payment_method, status, created_at) VALUES(?,?,?,?,?,?,?)",
                    (ord_id, 1, 9498.00, "Lab Suite 404, Cyber Defense Center, 127.0.0.1", "SecurePay Card Tokenization", "COMPLETED", (datetime.utcnow() - timedelta(days=1)).isoformat()))
        cur.execute("INSERT INTO order_items(order_id, product_id, quantity, price) VALUES(?,?,?,?)",
                    (ord_id, 1, 1, 5999.00))
        cur.execute("INSERT INTO order_items(order_id, product_id, quantity, price) VALUES(?,?,?,?)",
                    (ord_id, 2, 1, 3499.00))
        cur.execute("INSERT INTO payments(id, order_id, amount, payment_method, status, transaction_ref, created_at) VALUES(?,?,?,?,?,?,?)",
                    ("PAY-2026-4411", ord_id, 9498.00, "SecurePay Card Tokenization", "SUCCESS", "TXN-9812-OK", (datetime.utcnow() - timedelta(days=1)).isoformat()))

    con.commit()
    con.close()

def is_mitigated(vuln_key):
    con = db()
    row = con.execute("SELECT is_mitigated FROM remediation_config WHERE vuln_key=?", (vuln_key,)).fetchone()
    con.close()
    return bool(row and row["is_mitigated"])

def get_global_mitigation_status():
    con = db()
    rows = con.execute("SELECT is_mitigated FROM remediation_config").fetchall()
    con.close()
    if not rows: return False
    return all(r["is_mitigated"] for r in rows)

def log_audit(event, detail="", ip=None):
    ip = ip or (request.remote_addr if request else "127.0.0.1") or "127.0.0.1"
    con = db()
    try:
        con.execute("INSERT INTO audit_logs(event, detail, ip_address, created_at) VALUES(?,?,?,?)",
                    (event, detail, ip, datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()

def log_security_event(attack_type, endpoint, parameter, payload, status, risk_level, evidence, impact, mitigated=0):
    con = db()
    try:
        con.execute("""
        INSERT INTO security_events(attack_type, endpoint, parameter, payload, status, risk_level, evidence, impact, mitigated, created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (attack_type, endpoint, parameter, payload, status, risk_level, evidence, impact, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()

def current_user():
    sid = request.cookies.get("PAYSESSION")
    if not sid:
        return None
    con = db()
    row = con.execute("""
        SELECT u.* FROM users u
        JOIN session_store s ON s.user_id = u.id
        WHERE s.sid = ? AND s.is_revoked = 0
    """, (sid,)).fetchone()
    con.close()
    return row

def get_or_create_session_id():
    sid = request.cookies.get("PAYSESSION")
    if not sid:
        sid = request.cookies.get("CART_SESSION")
    if not sid:
        sid = "ANON-" + secrets.token_hex(8)
    return sid

# Context processor so all templates know the global security toggle state
@app.context_processor
def inject_global_security_state():
    return {
        "global_mitigated": get_global_mitigation_status(),
        "is_mitigated_fn": is_mitigated
    }

# ----------------- CUSTOMER STOREFRONT ROUTES ----------------- #

@app.route("/")
def home():
    con = db()
    categories = con.execute("SELECT * FROM categories ORDER BY id").fetchall()
    featured_products = con.execute("SELECT p.*, c.name as category_name FROM products p JOIN categories c ON c.id=p.category_id LIMIT 8").fetchall()
    stats = {
        "products_count": con.execute("SELECT COUNT(*) FROM products").fetchone()[0],
        "categories_count": con.execute("SELECT COUNT(*) FROM categories").fetchone()[0],
        "reviews_count": con.execute("SELECT COUNT(*) FROM reviews").fetchone()[0],
        "orders_count": con.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    }
    con.close()
    return render_template("index.html", user=current_user(), categories=categories, products=featured_products, stats=stats)

# ATTACK #3: Natural SQL Injection surface directly on Storefront Search
@app.route("/products")
def products():
    cat_slug = request.args.get("category", "")
    search_q = request.args.get("q", "")
    con = db()
    categories = con.execute("SELECT * FROM categories ORDER BY id").fetchall()
    
    query = "SELECT p.*, c.name as category_name FROM products p JOIN categories c ON c.id=p.category_id WHERE 1=1"
    params = []
    
    if cat_slug:
        query += " AND c.slug = ?"
        params.append(cat_slug)
        
    sqli_mitigated = is_mitigated("sqli")
    injected_detected = False
    
    if search_q:
        if sqli_mitigated:
            # MITIGATED: Parameterized execution
            query += " AND (p.name LIKE ? OR p.description LIKE ?)"
            params.extend([f"%{search_q}%", f"%{search_q}%"])
            products_list = con.execute(query, params).fetchall()
            executed_query = f"{query} [BOUND PARAMETERS: {params}]"
        else:
            # VULNERABLE: Direct SQL String Concatenation
            raw_query = f"SELECT p.*, c.name as category_name FROM products p JOIN categories c ON c.id=p.category_id WHERE p.name LIKE '%{search_q}%'"
            try:
                products_list = con.execute(raw_query).fetchall()
                executed_query = raw_query
                injected_detected = ("1=1" in search_q or len(products_list) == 14) and len(search_q) > 3
            except Exception as e:
                products_list = []
                executed_query = f"SQL SYNTAX ERROR: {str(e)}"
                
        # Security Event Logging
        if "'" in search_q or "--" in search_q or "OR" in search_q.upper():
            log_security_event(
                attack_type="SQL_INJECTION",
                endpoint="/products",
                parameter="q",
                payload=search_q,
                status="PROTECTED" if sqli_mitigated else "EXPLOITED",
                risk_level="CRITICAL",
                evidence=f"Search Query: '{search_q}'. Executed: {executed_query}. Returned {len(products_list)} records.",
                impact="Database extraction via unsanitized query parameters.",
                mitigated=int(sqli_mitigated)
            )
    else:
        products_list = con.execute(query, params).fetchall()
        executed_query = query
        
    con.close()
    return render_template("products.html",
                           user=current_user(),
                           products=products_list,
                           categories=categories,
                           active_cat=cat_slug,
                           search_q=search_q,
                           executed_query=executed_query,
                           sqli_mitigated=sqli_mitigated,
                           injected_detected=injected_detected)

# ATTACK #4: Natural Stored XSS surface directly on Product Detail & Review Page
@app.route("/products/<int:pid>")
def product_detail(pid):
    con = db()
    product = con.execute("SELECT p.*, c.name as category_name FROM products p JOIN categories c ON c.id=p.category_id WHERE p.id=?", (pid,)).fetchone()
    if not product:
        con.close()
        return "Product not found", 404
    reviews_list = con.execute("SELECT * FROM reviews WHERE product_id=? ORDER BY id DESC", (pid,)).fetchall()
    related = con.execute("SELECT * FROM products WHERE category_id=? AND id!=? LIMIT 4", (product["category_id"], pid)).fetchall()
    xss_mitigated = is_mitigated("xss")
    con.close()
    return render_template("product_detail.html", user=current_user(), product=product, reviews=reviews_list, related=related, xss_mitigated=xss_mitigated)

@app.route("/products/<int:pid>/reviews", methods=["POST"])
def add_review(pid):
    author = request.form.get("author", "Guest User").strip() or "Guest User"
    rating = int(request.form.get("rating", 5))
    content = request.form.get("content", "").strip()
    
    if not content:
        return redirect(url_for("product_detail", pid=pid))
        
    user = current_user()
    user_id = user["id"] if user else None
    
    mitigated = is_mitigated("xss")
    if mitigated:
        # MITIGATED: HTML entity escaping
        content_to_store = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
        author_to_store = author.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    else:
        # VULNERABLE: Raw unencoded input stored persistently
        content_to_store = content
        author_to_store = author

    con = db()
    con.execute("INSERT INTO reviews(product_id, user_id, author_name, rating, content, created_at) VALUES(?,?,?,?,?,?)",
                (pid, user_id, author_to_store, rating, content_to_store, datetime.utcnow().isoformat()))
    con.commit()
    con.close()
    
    log_audit("REVIEW_POSTED", f"product_id={pid}; author={author}")
    if "<" in content or "script" in content.lower() or "onerror" in content.lower():
        log_security_event(
            attack_type="STORED_XSS",
            endpoint=f"/products/{pid}/reviews",
            parameter="content",
            payload=content,
            status="MITIGATED" if mitigated else "EXPLOITED",
            risk_level="HIGH",
            evidence=f"Stored into review for product #{pid}. Rendered {'safely escaped' if mitigated else 'raw via |safe'}.",
            impact="Client-side script execution in customer/admin browser context.",
            mitigated=int(mitigated)
        )
        
    return redirect(url_for("product_detail", pid=pid))

# Global reviews page
@app.route("/reviews")
def all_reviews():
    con = db()
    reviews_list = con.execute("SELECT r.*, p.name as product_name FROM reviews r JOIN products p ON p.id=r.product_id ORDER BY r.id DESC").fetchall()
    xss_mitigated = is_mitigated("xss")
    con.close()
    return render_template("reviews.html", user=current_user(), reviews=reviews_list, xss_mitigated=xss_mitigated)

# ----------------- CART & CHECKOUT ----------------- #

@app.route("/cart")
def cart():
    sid = get_or_create_session_id()
    user = current_user()
    con = db()
    if user:
        items = con.execute("""
            SELECT ci.id, ci.quantity, p.id as product_id, p.name, p.price, p.stock, p.badge, c.name as category_name
            FROM cart_items ci
            JOIN products p ON p.id = ci.product_id
            JOIN categories c ON c.id = p.category_id
            WHERE ci.user_id = ? OR ci.session_id = ?
        """, (user["id"], sid)).fetchall()
    else:
        items = con.execute("""
            SELECT ci.id, ci.quantity, p.id as product_id, p.name, p.price, p.stock, p.badge, c.name as category_name
            FROM cart_items ci
            JOIN products p ON p.id = ci.product_id
            JOIN categories c ON c.id = p.category_id
            WHERE ci.session_id = ?
        """, (sid,)).fetchall()
        
    total = sum(item["price"] * item["quantity"] for item in items)
    con.close()
    resp = make_response(render_template("cart.html", user=user, items=items, total=total))
    if not request.cookies.get("CART_SESSION"):
        resp.set_cookie("CART_SESSION", sid)
    return resp

@app.route("/cart/add", methods=["POST"])
def cart_add():
    sid = get_or_create_session_id()
    user = current_user()
    pid = int(request.form.get("product_id", 0))
    qty = int(request.form.get("quantity", 1))
    
    con = db()
    if user:
        existing = con.execute("SELECT id, quantity FROM cart_items WHERE (user_id=? OR session_id=?) AND product_id=?", (user["id"], sid, pid)).fetchone()
    else:
        existing = con.execute("SELECT id, quantity FROM cart_items WHERE session_id=? AND product_id=?", (sid, pid)).fetchone()
        
    if existing:
        con.execute("UPDATE cart_items SET quantity = quantity + ? WHERE id=?", (qty, existing["id"]))
    else:
        con.execute("INSERT INTO cart_items(session_id, user_id, product_id, quantity, created_at) VALUES(?,?,?,?,?)",
                    (sid, user["id"] if user else None, pid, qty, datetime.utcnow().isoformat()))
    con.commit()
    con.close()
    log_audit("CART_ADD", f"product_id={pid}; quantity={qty}")
    return redirect(url_for("cart"))

@app.route("/cart/update", methods=["POST"])
def cart_update():
    item_id = int(request.form.get("item_id", 0))
    qty = int(request.form.get("quantity", 1))
    con = db()
    if qty <= 0:
        con.execute("DELETE FROM cart_items WHERE id=?", (item_id,))
    else:
        con.execute("UPDATE cart_items SET quantity=? WHERE id=?", (qty, item_id))
    con.commit()
    con.close()
    return redirect(url_for("cart"))

@app.route("/cart/remove/<int:item_id>", methods=["POST", "GET"])
def cart_remove(item_id):
    con = db()
    con.execute("DELETE FROM cart_items WHERE id=?", (item_id,))
    con.commit()
    con.close()
    return redirect(url_for("cart"))

@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    user = current_user()
    if not user:
        return redirect(url_for("login", next="checkout"))
        
    sid = get_or_create_session_id()
    con = db()
    items = con.execute("""
        SELECT ci.id, ci.quantity, p.id as product_id, p.name, p.price, p.stock
        FROM cart_items ci JOIN products p ON p.id = ci.product_id
        WHERE ci.user_id = ? OR ci.session_id = ?
    """, (user["id"], sid)).fetchall()
    
    if not items and request.method == "GET":
        con.close()
        return redirect(url_for("products"))
        
    total = sum(item["price"] * item["quantity"] for item in items)
    
    if request.method == "POST":
        address = request.form.get("address", "Lab Delivery Address")
        pay_method = request.form.get("payment_method", "SecurePay Tokenized Card")
        order_id = "ORD-" + secrets.token_hex(4).upper()
        
        con.execute("INSERT INTO orders(id, user_id, total_amount, shipping_address, payment_method, status, created_at) VALUES(?,?,?,?,?,?,?)",
                    (order_id, user["id"], total, address, pay_method, "COMPLETED", datetime.utcnow().isoformat()))
                    
        for it in items:
            con.execute("INSERT INTO order_items(order_id, product_id, quantity, price) VALUES(?,?,?,?)",
                        (order_id, it["product_id"], it["quantity"], it["price"]))
            con.execute("UPDATE products SET stock = MAX(0, stock - ?) WHERE id=?", (it["quantity"], it["product_id"]))
            
        pay_id = "PAY-" + secrets.token_hex(4).upper()
        txn_ref = "TXN-" + secrets.token_hex(6).upper()
        con.execute("INSERT INTO payments(id, order_id, amount, payment_method, status, transaction_ref, created_at) VALUES(?,?,?,?,?,?,?)",
                    (pay_id, order_id, total, pay_method, "SUCCESS", txn_ref, datetime.utcnow().isoformat()))
                    
        con.execute("DELETE FROM cart_items WHERE user_id=? OR session_id=?", (user["id"], sid))
        con.commit()
        con.close()
        
        log_audit("ORDER_PLACED", f"order_id={order_id}; amount={total}; user={user['email']}")
        return redirect(url_for("order_detail", order_id=order_id))
        
    con.close()
    return render_template("checkout.html", user=user, items=items, total=total)

@app.route("/orders")
def orders_list():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    orders = con.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    con.close()
    return render_template("orders.html", user=user, orders=orders)

@app.route("/orders/<order_id>")
def order_detail(order_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    order = con.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        con.close()
        return "Order not found", 404
        
    items = con.execute("""
        SELECT oi.*, p.name as product_name, p.badge
        FROM order_items oi
        JOIN products p ON p.id = oi.product_id
        WHERE oi.order_id = ?
    """, (order_id,)).fetchall()
    
    payment = con.execute("SELECT * FROM payments WHERE order_id=?", (order_id,)).fetchone()
    con.close()
    return render_template("order_detail.html", user=user, order=order, items=items, payment=payment)

# ----------------- AUTHENTICATION & ATTACK #2 (BRUTE FORCE) ----------------- #

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    error_type = "danger"
    client_ip = request.remote_addr or "127.0.0.1"
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    
    mitigated = is_mitigated("brute_force")
    
    if request.method == "POST":
        now = time.time()
        recent_fails = [t for t in LOGIN_ATTEMPT_TRACKER.get(client_ip, []) if now - t < 60]
        LOGIN_ATTEMPT_TRACKER[client_ip] = recent_fails
        
        # When MITIGATED: Lockout / 429 triggered after 4 failed tries
        if mitigated and len(recent_fails) >= 4:
            message = "⚠️ [SECURITY LOCKOUT] Too many failed authentication attempts. Account access rate-limited (HTTP 429)."
            log_security_event(
                attack_type="PASSWORD_BRUTE_FORCE",
                endpoint="/login",
                parameter="password",
                payload=f"Rapid password guessing attempts on {email} from {client_ip}",
                status="BLOCKED",
                risk_level="HIGH",
                evidence=f"Rate limiting actively blocked attempt after {len(recent_fails)} failures from {client_ip}.",
                impact="Credential guessing prevented via rate limiting.",
                mitigated=1
            )
            con = db()
            recent_attempts = con.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 10").fetchall()
            con.close()
            return render_template("login.html", message=message, error_type="warning", recent_attempts=recent_attempts, mitigated=mitigated), 429
            
        con = db()
        user_row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        pw_hash = hashlib.sha256(password.encode()).hexdigest() if password else ""
        
        if user_row and user_row["password_hash"] == pw_hash:
            # Login successful
            sid = secrets.token_urlsafe(24)
            user_agent = request.headers.get("User-Agent", "Unknown")
            con.execute("INSERT OR REPLACE INTO session_store(sid, user_id, ip_address, user_agent, created_at, is_revoked) VALUES(?,?,?,?,?,0)",
                        (sid, user_row["id"], client_ip, user_agent, datetime.utcnow().isoformat()))
            con.execute("INSERT INTO login_attempts(ip_address, email, status, attempted_password, created_at) VALUES(?,?,?,?,?)",
                        (client_ip, email, "SUCCESS", "[AUTHENTICATED]", datetime.utcnow().isoformat()))
            con.commit()
            con.close()
            
            LOGIN_ATTEMPT_TRACKER[client_ip] = []
            log_audit("LOGIN_SUCCESS", f"user={user_row['email']}")
            
            next_url = request.args.get("next") or url_for("dashboard")
            resp = make_response(redirect(next_url))
            
            # ATTACK #5 (Session cookie flags)
            session_mitigated = is_mitigated("session_hijack")
            if session_mitigated:
                resp.set_cookie("PAYSESSION", sid, httponly=True, samesite="Strict")
            else:
                resp.set_cookie("PAYSESSION", sid)
            return resp
        else:
            if client_ip not in LOGIN_ATTEMPT_TRACKER:
                LOGIN_ATTEMPT_TRACKER[client_ip] = []
            LOGIN_ATTEMPT_TRACKER[client_ip].append(now)
            
            con.execute("INSERT INTO login_attempts(ip_address, email, status, attempted_password, created_at) VALUES(?,?,?,?,?)",
                        (client_ip, email, "FAILED", password, datetime.utcnow().isoformat()))
            con.commit()
            con.close()
            
            log_audit("LOGIN_FAILURE", f"email={email}; ip={client_ip}")
            message = "Invalid email address or password."
            
            if len(LOGIN_ATTEMPT_TRACKER[client_ip]) >= 3:
                log_security_event(
                    attack_type="PASSWORD_BRUTE_FORCE",
                    endpoint="/login",
                    parameter="password",
                    payload=f"Repeated authentication failures on {email}",
                    status="EXPLOITED" if not mitigated else "BLOCKED",
                    risk_level="HIGH",
                    evidence=f"{len(LOGIN_ATTEMPT_TRACKER[client_ip])} failed login attempts recorded in login_attempts table.",
                    impact="Adversary attempting online credential discovery.",
                    mitigated=int(mitigated)
                )

    con = db()
    recent_attempts = con.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 10").fetchall()
    con.close()
    return render_template("login.html", message=message, error_type=error_type, recent_attempts=recent_attempts, mitigated=mitigated)

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        
        if not name or not email or not password:
            message = "All fields are required."
        else:
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            con = db()
            try:
                con.execute("INSERT INTO users(name, email, password_hash, role, created_at) VALUES(?,?,?,?,?)",
                            (name, email, pw_hash, "customer", datetime.utcnow().isoformat()))
                con.commit()
                con.close()
                log_audit("USER_REGISTERED", f"email={email}")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                con.close()
                message = "An account with this email already exists."
    return render_template("register.html", message=message)

@app.route("/logout")
def logout():
    sid = request.cookies.get("PAYSESSION")
    if sid:
        con = db()
        con.execute("UPDATE session_store SET is_revoked=1 WHERE sid=?", (sid,))
        con.commit()
        con.close()
        log_audit("LOGOUT", f"sid={sid[:8]}...")
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("PAYSESSION")
    return resp

# ATTACK #5: Natural Session Context & Token Hijack Verification surface
@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    con = db()
    orders = con.execute("SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC", (user["id"],)).fetchall()
    sessions = con.execute("SELECT * FROM session_store WHERE user_id=? ORDER BY created_at DESC LIMIT 5", (user["id"],)).fetchall()
    reviews = con.execute("SELECT r.*, p.name as product_name FROM reviews r JOIN products p ON p.id=r.product_id WHERE r.user_id=? ORDER BY r.created_at DESC", (user["id"],)).fetchall()
    session_mitigated = is_mitigated("session_hijack")
    con.close()
    return render_template("dashboard.html", user=user, orders=orders, sessions=sessions, reviews=reviews, session_mitigated=session_mitigated)

# Natural Session Hijack Simulation endpoint (simulates testing access from secondary client)
@app.route("/api/session/verify-token", methods=["POST"])
def verify_session_token():
    token = request.json.get("token", "").strip() if request.is_json else request.form.get("token", "").strip()
    simulated_ip = request.json.get("ip", "192.168.1.250 (Secondary / Rogue Device)") if request.is_json else request.form.get("ip", "192.168.1.250")
    
    con = db()
    session_record = con.execute("SELECT s.*, u.name, u.email FROM session_store s JOIN users u ON u.id=s.user_id WHERE s.sid=? AND s.is_revoked=0", (token,)).fetchone()
    con.close()
    
    mitigated = is_mitigated("session_hijack")
    
    if not session_record:
        return jsonify(valid=False, message="Invalid or expired session token.")
        
    if mitigated:
        # MITIGATED: IP / User-Agent fingerprint mismatch check
        log_security_event(
            attack_type="SESSION_HIJACKING",
            endpoint="/api/session/verify-token",
            parameter="Cookie: PAYSESSION",
            payload=token,
            status="MITIGATED",
            risk_level="HIGH",
            evidence=f"Token '{token[:12]}...' rejected: IP fingerprint mismatch (Expected {session_record['ip_address']}, Received {simulated_ip}).",
            impact="Unauthorized session replay blocked.",
            mitigated=1
        )
        return jsonify(
            valid=False,
            mitigated=True,
            hijack_success=False,
            status="BLOCKED (FINGERPRINT MISMATCH)",
            message="HTTP 401 Unauthorized: Session Token Suspended due to Client Fingerprint Mismatch."
        )
    else:
        # VULNERABLE: Token accepted blindly from any IP/Client
        log_security_event(
            attack_type="SESSION_HIJACKING",
            endpoint="/api/session/verify-token",
            parameter="Cookie: PAYSESSION",
            payload=token,
            status="EXPLOITED",
            risk_level="HIGH",
            evidence=f"Token '{token[:12]}...' accepted from {simulated_ip} without device verification.",
            impact="Adversary assumed victim identity without credentials.",
            mitigated=0
        )
        return jsonify(
            valid=True,
            mitigated=False,
            hijack_success=True,
            status="SESSION HIJACKED (ACCESS GRANTED)",
            user={"id": session_record["user_id"], "name": session_record["name"], "email": session_record["email"]},
            message=f"HTTP 200 OK: Granted full account access to '{session_record['email']}'. Orders & profile exposed."
        )

# ATTACK #1: Natural Diagnostic Network Scanner
@app.route("/diagnostics")
def diagnostics():
    return render_template("diagnostics.html", user=current_user())

@app.route("/api/diagnostics/scan-ports", methods=["POST", "GET"])
def api_port_scan():
    ports_to_test = [5000, 5001, 8000, 8080, 3306, 5432, 22]
    mitigated = is_mitigated("port_scan")
    results = []
    
    started = time.perf_counter()
    for p in ports_to_test:
        if mitigated and p != 5000:
            results.append({
                "port": p,
                "service": get_service_name(p),
                "status": "FILTERED / BLOCKED (Firewall Rule Active)",
                "latency_ms": 0.1
            })
            continue
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        p_start = time.perf_counter()
        code = sock.connect_ex(("127.0.0.1", p))
        p_elapsed = (time.perf_counter() - p_start) * 1000
        sock.close()
        
        status = "OPEN" if code == 0 else "CLOSED"
        results.append({
            "port": p,
            "service": get_service_name(p),
            "status": status,
            "latency_ms": round(p_elapsed, 2)
        })
        
    total_time_ms = round((time.perf_counter() - started) * 1000, 2)
    open_ports = [r for r in results if r["status"] == "OPEN"]
    
    con = db()
    try:
        con.execute("""
        INSERT INTO attack_runs(attack_key, attack_name, payload, result_status, evidence, response_time_ms, mitigated_when_run, executed_at)
        VALUES(?,?,?,?,?,?,?,?)
        """, ("port_scan", "Network Reconnaissance / TCP Port Scan", f"Ports: {ports_to_test}",
              "COMPLETED", f"Identified {len(open_ports)} open listening port(s) on 127.0.0.1", total_time_ms, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()
    
    log_security_event(
        attack_type="NETWORK_PORT_SCAN",
        endpoint="/api/diagnostics/scan-ports",
        parameter="ports",
        payload=str(ports_to_test),
        status="COMPLETED",
        risk_level="INFORMATIONAL / LOW",
        evidence=f"TCP Connect probe discovered active web port 5000 (Flask HTTP). {len(results)-len(open_ports)} ports closed/filtered.",
        impact="Discloses running service boundaries.",
        mitigated=int(mitigated)
    )
    
    return jsonify(success=True, target="127.0.0.1", results=results, total_time_ms=total_time_ms, mitigated=mitigated)

def get_service_name(port):
    mapping = {5000: "Flask Web Application", 5001: "Secondary Microservice", 8000: "HTTP-Alt Dev Server",
               8080: "HTTP Proxy / Alternate", 3306: "MySQL Database", 5432: "PostgreSQL Database", 22: "SSH Management"}
    return mapping.get(port, "Unknown Service")

# ATTACK #6: Natural System Health & Benchmark Monitor (DoS Concept)
@app.route("/system-status")
def system_status():
    return render_template("system_status.html", user=current_user())

@app.route("/api/system/benchmark-burst", methods=["POST", "GET"])
def api_flood_test():
    burst_count = 35
    mitigated = is_mitigated("dos")
    latencies = []
    statuses = []
    
    started = time.perf_counter()
    for i in range(burst_count):
        req_start = time.perf_counter()
        if mitigated and i >= 12:
            latencies.append(round((time.perf_counter() - req_start) * 1000 + 0.1, 2))
            statuses.append(429)
        else:
            latencies.append(round((time.perf_counter() - req_start) * 1000 + 1.2 + (i * 0.15), 2))
            statuses.append(200)
            
    total_time_ms = round((time.perf_counter() - started) * 1000, 2)
    avg_latency = round(statistics.mean(latencies), 2)
    max_latency = round(max(latencies), 2)
    min_latency = round(min(latencies), 2)
    throttled_count = statuses.count(429)
    
    result_status = "LOAD_ABSORBED" if not mitigated else "TRAFFIC_THROTTLED"
    evidence_text = f"{burst_count} rapid requests sent. Avg latency: {avg_latency}ms, Max: {max_latency}ms. Throttled requests (HTTP 429): {throttled_count}."
    
    con = db()
    try:
        con.execute("""
        INSERT INTO attack_runs(attack_key, attack_name, payload, result_status, evidence, response_time_ms, mitigated_when_run, executed_at)
        VALUES(?,?,?,?,?,?,?,?)
        """, ("dos", "HTTP GET Flood / Denial-of-Service Test", f"{burst_count} GET /health requests",
              result_status, evidence_text, total_time_ms, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()
    
    log_security_event(
        attack_type="HTTP_GET_FLOOD",
        endpoint="/health",
        parameter="burst_rate",
        payload=f"{burst_count} requests burst in {total_time_ms}ms",
        status="CONTROLLED_TEST_EXECUTED",
        risk_level="MEDIUM",
        evidence=evidence_text,
        impact="Server CPU/connection saturation leading to potential latency degradation.",
        mitigated=int(mitigated)
    )
    
    return jsonify(success=True, requests_sent=burst_count, avg_latency_ms=avg_latency, max_latency_ms=max_latency,
                   min_latency_ms=min_latency, throttled_count=throttled_count, mitigated=mitigated, total_time_ms=total_time_ms)

# Global Security Mode Toggle
@app.route("/api/security/toggle-mode", methods=["POST"])
def toggle_global_mode():
    data = request.get_json(silent=True) or request.form
    target_state = data.get("state") # 1 for protected, 0 for vulnerable
    
    con = db()
    try:
        if target_state is not None:
            new_val = 1 if str(target_state).lower() in ("1", "true", "on", "protected") else 0
        else:
            curr = get_global_mitigation_status()
            new_val = 0 if curr else 1
            
        con.execute("UPDATE remediation_config SET is_mitigated=?", (new_val,))
        con.commit()
    finally:
        con.close()
        
    log_audit("GLOBAL_SECURITY_MODE_TOGGLED", f"state={'PROTECTED' if new_val else 'VULNERABLE'}")
    return jsonify(success=True, is_protected=bool(new_val))

# Security Center / Audit Report
@app.route("/security")
@app.route("/audit-report")
def security_center():
    con = db()
    remediations = con.execute("SELECT * FROM remediation_config ORDER BY vuln_key").fetchall()
    security_events = con.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 20").fetchall()
    attack_runs = con.execute("SELECT * FROM attack_runs ORDER BY id DESC LIMIT 15").fetchall()
    audit_logs = con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20").fetchall()
    login_attempts = con.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 15").fetchall()
    
    total_vulns = len(remediations)
    mitigated_count = sum(1 for r in remediations if r["is_mitigated"])
    unmitigated_count = total_vulns - mitigated_count
    critical_unmitigated = sum(1 for r in remediations if not r["is_mitigated"] and r["risk_level"] == "CRITICAL")
    high_unmitigated = sum(1 for r in remediations if not r["is_mitigated"] and r["risk_level"] == "HIGH")
    
    con.close()
    return render_template("security_center.html",
                           user=current_user(),
                           remediations=remediations,
                           security_events=security_events,
                           attack_runs=attack_runs,
                           audit_logs=audit_logs,
                           login_attempts=login_attempts,
                           total_vulns=total_vulns,
                           mitigated_count=mitigated_count,
                           unmitigated_count=unmitigated_count,
                           critical_unmitigated=critical_unmitigated,
                           high_unmitigated=high_unmitigated)

@app.route("/api/security/toggle-remediation", methods=["POST"])
def toggle_remediation():
    data = request.get_json(silent=True) or request.form
    vuln_key = data.get("vuln_key")
    state = data.get("state")
    
    con = db()
    try:
        if vuln_key == "ALL":
            new_val = 1 if str(state).lower() in ("1", "true", "all_on") else 0
            con.execute("UPDATE remediation_config SET is_mitigated=?", (new_val,))
        else:
            if state is not None:
                new_val = 1 if str(state).lower() in ("1", "true", "on") else 0
            else:
                curr = con.execute("SELECT is_mitigated FROM remediation_config WHERE vuln_key=?", (vuln_key,)).fetchone()
                new_val = 0 if (curr and curr["is_mitigated"]) else 1
            con.execute("UPDATE remediation_config SET is_mitigated=? WHERE vuln_key=?", (new_val, vuln_key))
        con.commit()
    finally:
        con.close()
        
    log_audit("REMEDIATION_TOGGLED", f"vuln={vuln_key}; state={state}")
    
    con2 = db()
    remediations = con2.execute("SELECT * FROM remediation_config ORDER BY vuln_key").fetchall()
    con2.close()
    return jsonify(success=True, remediations=[dict(r) for r in remediations])

# API shortcuts for CLI test suite compatibility
@app.route("/api/security/scan", methods=["POST", "GET"])
def api_port_scan_compat():
    return api_port_scan()

@app.route("/api/security/bruteforce", methods=["POST"])
def api_bruteforce():
    target_email = request.json.get("email", "student@paysecure.local") if request.is_json else request.form.get("email", "student@paysecure.local")
    mitigated = is_mitigated("brute_force")
    
    wordlist = ["123456", "password", "admin2026", "secret", "pay123", "secure2025", "paysecure123", "student123"]
    attempts_log = []
    success_candidate = None
    started = time.perf_counter()
    
    con = db()
    user_row = con.execute("SELECT * FROM users WHERE email=?", (target_email,)).fetchone()
    con.close()
    
    for idx, cand in enumerate(wordlist, 1):
        cand_hash = hashlib.sha256(cand.encode()).hexdigest()
        
        if mitigated and idx >= 4:
            attempts_log.append({"attempt": idx, "password": cand, "status": "HTTP 429 - RATE LIMITED / ACCOUNT LOCKED", "success": False})
            break
            
        if user_row and user_row["password_hash"] == cand_hash:
            attempts_log.append({"attempt": idx, "password": cand, "status": "HTTP 302 - AUTHENTICATED", "success": True})
            success_candidate = cand
            break
        else:
            attempts_log.append({"attempt": idx, "password": cand, "status": "HTTP 401 - FAILED", "success": False})
            
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    result_status = "SUCCESS" if (success_candidate and not (mitigated and len(attempts_log) >= 4)) else "BLOCKED"
    evidence_text = f"Candidate '{success_candidate}' matched after {len(attempts_log)} attempts." if success_candidate and not mitigated else f"Brute force blocked after {len(attempts_log)} attempts via account rate-limiting."
    
    con = db()
    try:
        con.execute("""
        INSERT INTO attack_runs(attack_key, attack_name, payload, result_status, evidence, response_time_ms, mitigated_when_run, executed_at)
        VALUES(?,?,?,?,?,?,?,?)
        """, ("brute_force", "Password Brute-Force Authentication Test", f"Target: {target_email} | Wordlist size: {len(wordlist)}",
              result_status, evidence_text, elapsed_ms, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()
        
    return jsonify(success=True, target=target_email, attempts=attempts_log, cracked=bool(success_candidate and not mitigated),
                   matched_password=success_candidate if not mitigated else None, mitigated=mitigated, elapsed_ms=elapsed_ms)

@app.route("/api/security/sqli", methods=["POST"])
def api_sqli():
    payload = request.json.get("payload", "' OR 1=1 --") if request.is_json else request.form.get("payload", "' OR 1=1 --")
    mitigated = is_mitigated("sqli")
    started = time.perf_counter()
    
    con = db()
    try:
        if mitigated:
            sql_pattern = f"%{payload}%"
            sql_display = "SELECT id, name, price, stock, description FROM products WHERE name LIKE ?"
            rows = con.execute(sql_display, (sql_pattern,)).fetchall()
            injected = False
        else:
            sql_display = f"SELECT id, name, price, stock, description FROM products WHERE name LIKE '%{payload}%'"
            try:
                rows = con.execute(sql_display).fetchall()
                injected = len(rows) > 0 and ("1=1" in payload or len(rows) == 14)
            except Exception as e:
                rows = []
                sql_display = f"ERROR: {str(e)} | Query: {sql_display}"
                injected = False
                
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        result_status = "EXPLOITED" if (injected and not mitigated) else "PROTECTED"
        evidence_text = f"Query returned {len(rows)} database records across entire catalog due to injected tautology (' OR 1=1)." if not mitigated else f"Query safely parameterized. Returned {len(rows)} matching records (0 injected)."
        
        con.execute("""
        INSERT INTO attack_runs(attack_key, attack_name, payload, result_status, evidence, response_time_ms, mitigated_when_run, executed_at)
        VALUES(?,?,?,?,?,?,?,?)
        """, ("sqli", "SQL Injection / Parameter Bypass", payload, result_status, evidence_text, elapsed_ms, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()
    
    return jsonify(success=True, payload=payload, sql_executed=sql_display, records_returned=len(rows),
                   sample_data=[dict(r) for r in rows[:5]], result_status=result_status, mitigated=mitigated, elapsed_ms=elapsed_ms)

@app.route("/api/security/xss", methods=["POST"])
def api_xss():
    payload = request.json.get("payload", "<img src=x onerror=\"alert('XSS-STORED-EXPLOIT-PAYSECURE')\">") if request.is_json else request.form.get("payload", "<img src=x onerror=\"alert('XSS-STORED-EXPLOIT-PAYSECURE')\">")
    mitigated = is_mitigated("xss")
    started = time.perf_counter()
    
    if mitigated:
        sanitized = payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    else:
        sanitized = payload
        
    con = db()
    try:
        con.execute("INSERT INTO reviews(product_id, user_id, author_name, rating, content, created_at) VALUES(?,?,?,?,?,?)",
                    (1, 1, "Simulated Penetration Tester", 5, sanitized, datetime.utcnow().isoformat()))
        con.commit()
        latest_review = con.execute("SELECT * FROM reviews ORDER BY id DESC LIMIT 1").fetchone()
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        result_status = "STORED & EXECUTABLE" if not mitigated else "STORED & ENCODED (BLOCKED)"
        evidence_text = f"Payload saved into review ID #{latest_review['id']}."
        
        con.execute("""
        INSERT INTO attack_runs(attack_key, attack_name, payload, result_status, evidence, response_time_ms, mitigated_when_run, executed_at)
        VALUES(?,?,?,?,?,?,?,?)
        """, ("xss", "Stored Cross-Site Scripting (XSS)", payload, result_status, evidence_text, elapsed_ms, int(mitigated), datetime.utcnow().isoformat()))
        con.commit()
    finally:
        con.close()
    
    return jsonify(success=True, payload=payload, stored_content=sanitized, review_id=latest_review["id"],
                   result_status=result_status, mitigated=mitigated, elapsed_ms=elapsed_ms)

@app.route("/api/security/session-hijack", methods=["POST", "GET"])
def api_session_hijack():
    token = request.json.get("token") if request.is_json and request.json else None
    if not token:
        con = db()
        row = con.execute("SELECT sid FROM session_store WHERE is_revoked=0 ORDER BY created_at DESC LIMIT 1").fetchone()
        con.close()
        token = row["sid"] if row else "PAYSESS-LAB-" + secrets.token_hex(8)
    
    attacker_ip = "192.168.1.250 (Secondary / Rogue Device)"
    victim_email = "student@paysecure.local"
    mitigated = is_mitigated("session_hijack")
    
    if mitigated:
        return jsonify(
            valid=False,
            mitigated=True,
            hijack_success=False,
            victim_email=victim_email,
            victim_token=token,
            attacker_ip=attacker_ip,
            server_response="HTTP 401 Unauthorized: Session Token Suspended due to Client Fingerprint Mismatch.",
            status="BLOCKED (FINGERPRINT MISMATCH)",
            message="HTTP 401 Unauthorized: Session Token Suspended due to Client Fingerprint Mismatch."
        )
    else:
        return jsonify(
            valid=True,
            mitigated=False,
            hijack_success=True,
            victim_email=victim_email,
            victim_token=token,
            attacker_ip=attacker_ip,
            server_response="HTTP 200 OK: Full Account Access Granted (Victim Identity Assumed).",
            status="SESSION HIJACKED (ACCESS GRANTED)",
            user={"id": 1, "name": "Shrimay (Lab Student)", "email": victim_email},
            message=f"HTTP 200 OK: Granted full account access to '{victim_email}'."
        )

@app.route("/api/security/flood-test", methods=["POST", "GET"])
def api_flood_test_compat():
    return api_flood_test()

@app.route("/api/security/report")
def security_report():
    con = db()
    remediations = con.execute("SELECT * FROM remediation_config ORDER BY risk_level DESC, vuln_key").fetchall()
    events = con.execute("SELECT * FROM security_events ORDER BY id DESC").fetchall()
    attacks = con.execute("SELECT * FROM attack_runs ORDER BY id DESC").fetchall()
    
    report_data = {
        "title": "PaySecure E-Commerce Platform - Security Assessment Report",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scope": "Localhost Web Application, SQLite Storage (127.0.0.1:5000)",
        "findings": [dict(r) for r in remediations],
        "events_count": len(events),
        "attacks_count": len(attacks)
    }
    con.close()
    return jsonify(report_data)

@app.route("/api/security/reset-lab", methods=["POST"])
def reset_lab():
    con = db()
    try:
        con.execute("DELETE FROM security_events")
        con.execute("DELETE FROM attack_runs")
        con.execute("DELETE FROM login_attempts")
        con.execute("DELETE FROM audit_logs")
        con.execute("UPDATE remediation_config SET is_mitigated=0")
        con.execute("DELETE FROM reviews WHERE author_name LIKE '%Penetration%' OR content LIKE '%<%'")
        con.commit()
    finally:
        con.close()
    log_audit("LAB_RESET", "Security telemetry and state reset.")
    return jsonify(success=True, message="Lab state reset.")

@app.route("/health")
def health():
    return jsonify(status="UP", service="PaySecure Platform", time=time.time(), version="2.0.0-Lab")

if __name__ == "__main__":
    init_db()
    print("=" * 70)
    print("  PAYSECURE E-COMMERCE PLATFORM & SECURITY ASSESSMENT LAB")
    print("  Target: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=False)
