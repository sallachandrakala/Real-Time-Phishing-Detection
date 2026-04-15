import os
import sqlite3
import requests
import socket
import datetime
import whois
import re
import math
import ssl
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from urllib.parse import urlparse
from flask import Flask, render_template, request, session, redirect, url_for, make_response
from fpdf import FPDF

# Google OAuth imports REMOVED permanently

app = Flask(__name__)
app.secret_key = 'veriscope_key_master_2026_fixed'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['SESSION_COOKIE_HTTPONLY'] = True
DB_NAME = 'veriscope.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    # Add email column if not exists
    try: c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except: pass
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY, user_id TEXT, url TEXT, status TEXT, details TEXT,
                  domain_age TEXT, ip_address TEXT, website_status TEXT, threat_score REAL,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    try: c.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'admin', 'admin@veriscope.local')")
    except: pass
    conn.commit()
    conn.close()

init_db()

KNOWN_SITES = {
    'google.com': 'Search Engine', 'bing.com': 'Search Engine', 'yahoo.com': 'Search Engine',
    'duckduckgo.com': 'Search Engine', 'baidu.com': 'Search Engine', 'yandex.com': 'Search Engine',
    'chatgpt.com': 'AI Platform', 'openai.com': 'AI Platform', 'anthropic.com': 'AI Platform',
    'claude.ai': 'AI Platform', 'perplexity.ai': 'AI Platform', 'jasper.ai': 'AI Platform',
    'huggingface.co': 'AI Platform', 'midjourney.com': 'AI Platform', 'gemini.google.com': 'AI Platform',
    'wikipedia.org': 'Reference', 'quora.com': 'Knowledge Sharing',
    'facebook.com': 'Social Media', 'instagram.com': 'Social Media', 'twitter.com': 'Social Media',
    'x.com': 'Social Media', 'linkedin.com': 'Social Media', 'pinterest.com': 'Social Media',
    'tiktok.com': 'Social Media', 'snapchat.com': 'Social Media', 'reddit.com': 'Social Media',
    'whatsapp.com': 'Messaging', 'telegram.org': 'Messaging', 'discord.com': 'Communication',
    'slack.com': 'Communication', 'zoom.us': 'Communication', 'skype.com': 'Communication',
    'messenger.com': 'Messaging',
    'microsoft.com': 'Big Tech', 'apple.com': 'Big Tech', 'amazon.com': 'Big Tech',
    'ibm.com': 'Big Tech', 'oracle.com': 'Big Tech', 'adobe.com': 'Big Tech',
    'intel.com': 'Big Tech', 'nvidia.com': 'Big Tech', 'cisco.com': 'Big Tech',
    'salesforce.com': 'Cloud Services', 'github.com': 'Developer Platform',
    'gitlab.com': 'Developer Platform', 'bitbucket.org': 'Developer Platform',
    'stackoverflow.com': 'Developer Community', 'dropbox.com': 'Cloud Storage',
    'box.com': 'Cloud Storage', 'mega.nz': 'Cloud Storage', 'cloudflare.com': 'Web Infrastructure',
    'godaddy.com': 'Web Services',
    'paypal.com': 'FinTech', 'stripe.com': 'FinTech', 'wise.com': 'FinTech',
    'revolut.com': 'FinTech', 'chime.com': 'FinTech', 'cash.app': 'FinTech',
    'venmo.com': 'FinTech', 'visa.com': 'Finance', 'mastercard.com': 'Finance',
    'americanexpress.com': 'Finance', 'chase.com': 'Banking', 'bankofamerica.com': 'Banking',
    'wellsfargo.com': 'Banking', 'citi.com': 'Banking', 'hsbc.com': 'Banking',
    'sbi.co.in': 'Banking (India)', 'hdfcbank.com': 'Banking (India)',
    'icicibank.com': 'Banking (India)', 'axisbank.com': 'Banking (India)', 'kotak.com': 'Banking (India)',
    'walmart.com': 'Retail', 'ebay.com': 'E-Commerce', 'target.com': 'Retail',
    'aliexpress.com': 'E-Commerce', 'alibaba.com': 'E-Commerce', 'flipkart.com': 'E-Commerce (India)',
    'myntra.com': 'E-Commerce (India)', 'shopify.com': 'E-Commerce Platform', 'etsy.com': 'E-Commerce',
    'bestbuy.com': 'Retail', 'ikea.com': 'Retail', 'nike.com': 'Retail',
    'zara.com': 'Retail', 'booking.com': 'Travel', 'airbnb.com': 'Travel',
    'uber.com': 'Transport', 'ola.cabs': 'Transport',
    'netflix.com': 'Streaming', 'youtube.com': 'Video Platform', 'twitch.tv': 'Streaming',
    'spotify.com': 'Music Streaming', 'disneyplus.com': 'Streaming', 'hulu.com': 'Streaming',
    'primevideo.com': 'Streaming', 'hbo.com': 'Streaming', 'soundcloud.com': 'Music',
    'steamcommunity.com': 'Gaming', 'steampowered.com': 'Gaming', 'roblox.com': 'Gaming',
    'epicgames.com': 'Gaming', 'playstation.com': 'Gaming', 'xbox.com': 'Gaming',
    'cnn.com': 'News Media', 'bbc.com': 'News Media', 'nytimes.com': 'News Media',
    'forbes.com': 'Business News', 'bloomberg.com': 'Business News', 'wsj.com': 'News Media',
    'theguardian.com': 'News Media'
}

BRAND_CORRECT_DOMAINS = {
    'google': 'google.com', 'amazon': 'amazon.com', 'apple': 'apple.com',
    'microsoft': 'microsoft.com', 'paypal': 'paypal.com', 'netflix': 'netflix.com',
    'facebook': 'facebook.com', 'instagram': 'instagram.com', 'flipkart': 'flipkart.com',
    'linkedin': 'linkedin.com', 'twitter': 'twitter.com', 'sbi': 'sbi.co.in',
    'hdfc': 'hdfcbank.com', 'icici': 'icicibank.com', 'youtube': 'youtube.com',
    'whatsapp': 'whatsapp.com', 'snapchat': 'snapchat.com', 'reddit': 'reddit.com',
    'discord': 'discord.com', 'spotify': 'spotify.com',
}

def calculate_entropy(string):
    if not string: return 0
    entropy = 0
    for x in range(256):
        p_x = float(string.count(chr(x))) / len(string)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_page_details(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        r = requests.get(url, timeout=3, headers=headers, allow_redirects=True)
        return r.headers, r.text[:20000], r.status_code, r.url
    except: return {}, "", 0, url

def get_domain_age_raw(domain):
    try:
        w = whois.whois(domain)
        if w.creation_date:
            date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(date, datetime.datetime):
                return (datetime.datetime.now() - date).days, date.year
    except: pass
    return 0, 0

def get_ip_address(domain):
    try: return socket.gethostbyname(domain)
    except: return "Hidden"

def check_website_availability(domain):
    try: requests.get(f"https://{domain}", timeout=2); return "Online (HTTPS)"
    except:
        try: requests.get(f"http://{domain}", timeout=2); return "Online (HTTP)"
        except: return "Offline"

def get_ssl_issuer(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(2); s.connect((domain, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            return str(issuer)
    except: return ""

def normalize_visuals(text):
    text = text.lower()
    for char, rep in {'0':'o','1':'i','l':'i','I':'i','!':'i','|':'i','3':'e','4':'a','@':'a','5':'s','$':'s','8':'b','rn':'m','vv':'w'}.items():
        text = text.replace(char, rep)
    return text

def run_analysis(raw_url):
    if not raw_url.startswith(('http://', 'https://')):
        url_to_parse = 'https://' + raw_url
    else:
        url_to_parse = raw_url

    # Quick URL-only checks before any network calls
    parsed_quick = urlparse(url_to_parse)
    domain_quick = parsed_quick.netloc or url_to_parse
    if domain_quick.startswith("www."): domain_quick = domain_quick[4:]

    if "@" in raw_url:
        return create_result_fast("PHISHING", "Malicious Redirect (@ Symbol)", domain_quick, 0, "Hidden", "Offline")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_quick):
        return create_result_fast("PHISHING", "Raw IP Address Usage", domain_quick, 0, "Hidden", "Offline")

    # Check known safe sites before any network call
    for safe_domain, category in KNOWN_SITES.items():
        if domain_quick == safe_domain or domain_quick.endswith('.' + safe_domain):
            ip = get_ip_address(domain_quick)
            return create_result_fast("SAFE", f"Verified Global Site ({category})", domain_quick, 0, ip, "Online (HTTPS)")

    # Run all slow network calls in parallel
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_page    = ex.submit(get_page_details, url_to_parse)
        f_age     = ex.submit(get_domain_age_raw, domain_quick)
        f_ip      = ex.submit(get_ip_address, domain_quick)
        f_avail   = ex.submit(check_website_availability, domain_quick)

        try: page_headers, page_html, status_code, final_url = f_page.result(timeout=4)
        except: page_headers, page_html, status_code, final_url = {}, "", 0, url_to_parse

        try: age_days, reg_year = f_age.result(timeout=6)
        except: age_days, reg_year = 0, 0

        try: ip_addr = f_ip.result(timeout=3)
        except: ip_addr = "Hidden"

        try: web_status = f_avail.result(timeout=4)
        except: web_status = "Unknown"

    # SSL check only if HTTPS (fast, reuse connection)
    ssl_info = ""
    if final_url.startswith("https"):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain_quick) as s:
                s.settimeout(2); s.connect((domain_quick, 443))
                cert = s.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                ssl_info = str(issuer)
        except: pass

    parsed = urlparse(final_url)
    domain = parsed.netloc or final_url
    if domain.startswith("www."): domain = domain[4:]
    path = parsed.path
    entropy = calculate_entropy(domain)

    page_title = ""
    if page_html:
        title_match = re.search('<title>(.*?)</title>', page_html, re.IGNORECASE)
        if title_match: page_title = title_match.group(1).lower()

    brand_signatures = {
        'paypal': ['paypal.com'], 'microsoft': ['microsoft.com', 'live.com', 'azure.com'],
        'google': ['google.com', 'gmail.com'], 'facebook': ['facebook.com', 'fb.com'],
        'netflix': ['netflix.com'], 'amazon': ['amazon.com', 'ssl-images-amazon.com']
    }
    for brand, safe_domains in brand_signatures.items():
        if brand in page_title:
            if not any(domain.endswith(sd) for sd in safe_domains):
                return create_result_fast("PHISHING", f"Fake {brand.title()} Login Page Detected", domain, reg_year, ip_addr, web_status, suggestion=BRAND_CORRECT_DOMAINS.get(brand))

    targets = ['google','amazon','apple','microsoft','paypal','netflix','facebook','instagram',
               'flipkart','linkedin','twitter','sbi','hdfc','icici','youtube','whatsapp','snapchat','reddit','discord','spotify']
    norm_domain = normalize_visuals(domain.split('.')[0])

    for target in targets:
        norm_target = normalize_visuals(target)
        suggestion = BRAND_CORRECT_DOMAINS.get(target)
        if norm_domain == norm_target:
            return create_result_fast("PHISHING", f"Homograph Attack Detected (Imitating {target})", domain, reg_year, ip_addr, web_status, suggestion=suggestion)
        similarity = difflib.SequenceMatcher(None, norm_domain, norm_target).ratio()
        if 0.80 < similarity < 1.0:
            return create_result_fast("PHISHING", f"Typosquatting Detected (Imitating {target})", domain, reg_year, ip_addr, web_status, suggestion=suggestion)
        if target in domain and domain not in KNOWN_SITES:
            return create_result_fast("PHISHING", f"Brand Impersonation Detected ({target})", domain, reg_year, ip_addr, web_status, suggestion=suggestion)

    if domain.count('-') > 2: return create_result_fast("PHISHING", "Multiple Hyphens (Deceptive Domain)", domain, reg_year, ip_addr, web_status)
    if len(final_url) > 75: return create_result_fast("PHISHING", "Suspiciously Long URL", domain, reg_year, ip_addr, web_status)
    if entropy > 4.5: return create_result_fast("PHISHING", "High Entropy (Random Domain Name)", domain, reg_year, ip_addr, web_status)

    for kw in ['login','secure','account','update','bank','verify','wallet','confirm','signin','free','win']:
        if kw in domain or kw in path:
            return create_result_fast("PHISHING", f"Deceptive Keyword '{kw}' in URL", domain, reg_year, ip_addr, web_status)

    if any(domain.endswith(tld) for tld in ['.xyz','.top','.tk','.cn','.zip','.mov','.loan','.click']):
        return create_result_fast("PHISHING", "High-Risk Top Level Domain", domain, reg_year, ip_addr, web_status)

    if 0 < age_days < 30:
        return create_result_fast("PHISHING", f"Newly Registered Domain ({age_days} days old)", domain, reg_year, ip_addr, web_status)

    if domain.endswith(('.gov','.edu','.mil','.gov.in','.ac.in','.org')):
        return create_result_fast("SAFE", "Trusted Top-Level Domain", domain, reg_year, ip_addr, web_status)
    if "DigiCert" in ssl_info or "Entrust" in ssl_info or "GlobalSign" in ssl_info:
        return create_result_fast("SAFE", "High-Assurance SSL Certificate", domain, reg_year, ip_addr, web_status)

    return {'status':'UNVERIFIED','message':"CAUTION: Website Unknown. Proceed with Care.",
            'domain':domain,'age':f"{age_days} days",'ip':ip_addr,'website_status':web_status,
            'threat_score':50,'suggestion':None}


def create_result_fast(status, msg, domain, reg_year, ip, web_status, suggestion=None):
    current_year = datetime.datetime.now().year
    if status == "PHISHING": age = "Hidden"
    elif status == "SAFE" and reg_year != 0: age = f"{current_year - reg_year} Years (Since {reg_year})"
    else: age = f"Since {reg_year}" if reg_year != 0 else "Unknown"
    score = 10 if status == "SAFE" else 95 if status == "PHISHING" else 50
    return {'status':status,'message':msg,'domain':domain,'age':age,'ip':ip,
            'website_status':web_status,'threat_score':score,'suggestion':suggestion}


from authlib.integrations.flask_client import OAuth

# ── OAUTH SETUP ───────────────────────────────────────────────────────────────
# To enable real Google login:
# 1. Go to https://console.cloud.google.com/
# 2. Create a project → APIs & Services → Credentials → OAuth 2.0 Client ID
# 3. Set redirect URI: http://localhost:3000/auth/google/callback
# 4. Paste your Client ID and Secret below

GOOGLE_CLIENT_ID     = "YOUR_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/social-login/<provider>")
def social_login(provider):
    if provider not in ['Google', 'Apple', 'Phone']:
        return redirect('/')
    prefill = request.args.get('u', '')
    return render_template("social_login.html", provider=provider, prefill=prefill)

@app.route("/login/google")
def login_google():
    if GOOGLE_CLIENT_ID == "YOUR_GOOGLE_CLIENT_ID":
        # Not configured — fall back to login page with message
        return render_template("login.html", error="Google login not configured yet. Use email login below.")
    redirect_uri = "http://localhost:3000/auth/google/callback"
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()
        userinfo = token.get('userinfo')
        email = userinfo.get('email', '').lower()
        name  = userinfo.get('name', email)
        if not email:
            return redirect('/login')
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        c.execute("SELECT id, username, email FROM users WHERE LOWER(COALESCE(email,''))=? OR LOWER(username)=?", (email, email))
        user = c.fetchone()
        if not user:
            import secrets
            c.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (email, secrets.token_hex(16), email))
            conn.commit()
            c.execute("SELECT id, username, email FROM users WHERE username=?", (email,))
            user = c.fetchone()
        conn.close()
        session['user']     = user[1]
        session['username'] = user[1]
        session['user_id']  = str(user[0])
        session['email']    = user[2]
        return redirect(url_for('scan'))
    except Exception as e:
        return render_template("login.html", error=f"Google login failed: {str(e)}")

@app.route("/quick-access", methods=["POST"])
def quick_access():
    email = request.form.get("email","").strip().lower()
    provider = request.form.get("provider","email")
    if not email or "@" not in email:
        return redirect("/")
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    # Check if user exists
    c.execute("SELECT id, username, email FROM users WHERE LOWER(username)=? OR LOWER(COALESCE(email,''))=?", (email, email))
    user = c.fetchone()
    if user:
        # existing user — log in directly (social login, no password needed)
        session['user'] = user[1]
        session['username'] = user[1]
        session['user_id'] = str(user[0])
        session['email'] = user[2] if user[2] else user[1]
        conn.close()
    else:
        # new user — auto create account
        import secrets
        auto_pass = secrets.token_hex(16)
        c.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (email, auto_pass, email))
        conn.commit()
        c.execute("SELECT id, username, email FROM users WHERE username=?", (email,))
        user = c.fetchone()
        conn.close()
        session['user'] = user[1]
        session['username'] = user[1]
        session['user_id'] = str(user[0])
        session['email'] = user[2]
    return redirect(url_for('scan'))

@app.route("/debug-session")
def debug_session():
    return f"user={session.get('user')} | username={session.get('username')} | email={session.get('email')} | logged_in={'user' in session}"

@app.route("/")
def home():
    logged_in = bool(session.get('user'))
    uname = session.get('username', '')
    uemail = session.get('email', uname)
    if uemail and '@' in uemail:
        display_name = uemail.split('@')[0].replace('.', ' ').replace('_', ' ').title()
    elif uname:
        display_name = uname.replace('.', ' ').replace('_', ' ').title()
    else:
        display_name = ''
    return render_template("home.html",
        logged_in=logged_in,
        uname=uname,
        uemail=uemail,
        display_name=display_name
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route("/login", methods=["GET","POST"])
def login():
    if 'user' in session: return redirect(url_for('scan'))
    if request.method == "POST":
        u = request.form.get("username","").strip().lower()
        p = request.form.get("password","")
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        c.execute("SELECT id, username, email FROM users WHERE (LOWER(username)=? OR LOWER(COALESCE(email,''))=?) AND password=?", (u, u, p))
        user = c.fetchone(); conn.close()
        if user:
            session['user'] = user[1]
            session['username'] = user[1]
            session['user_id'] = str(user[0])
            session['email'] = user[2] if user[2] else user[1]
            return redirect(url_for('scan'))
        return render_template("login.html", error="Invalid email or password.")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        p = request.form.get("password", "")
        if not email or "@" not in email:
            return render_template("register.html", error="Please enter a valid email address.")
        if len(p) < 6:
            return render_template("register.html", error="Password must be at least 6 characters.")
        conn = sqlite3.connect(DB_NAME); c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?,?,?)", (email, p, email))
            conn.commit()
            # auto login after register
            c.execute("SELECT id, username, email FROM users WHERE username=?", (email,))
            user = c.fetchone(); conn.close()
            session['user'] = user[1]
            session['username'] = user[1]
            session['user_id'] = str(user[0])
            session['email'] = user[2]
            return redirect(url_for('scan'))
        except:
            conn.close()
            return render_template("register.html", error="An account with this email already exists.")
    prefill = request.args.get('u', '')
    return render_template("register.html", prefill_email=prefill)

# CHANGE 2: /login/google and /auth/google/callback REMOVED permanently

# CHANGE 3: /scan is open access — anyone can scan, history saved only if logged in
@app.route("/scan", methods=['GET','POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')
        result = run_analysis(url)
        if 'user' in session and result.get('status') not in ['INVALID']:
            conn = sqlite3.connect(DB_NAME); c = conn.cursor()
            c.execute("INSERT INTO scan_history (user_id,url,status,details,domain_age,ip_address,website_status,threat_score) VALUES (?,?,?,?,?,?,?,?)",
                      (str(session['user_id']),url,result['status'],result['message'],
                       result.get('age','Unknown'),result.get('ip','Hidden'),
                       result.get('website_status','Unknown'),result['threat_score']))
            result['id'] = c.lastrowid; conn.commit(); conn.close()
        else:
            result['id'] = None
        return render_template("result.html", result=result)
    return render_template("home.html")

@app.route("/dashboard")
def dashboard():
    if 'user' not in session: return redirect("/login")
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    uid = session['user_id']
    c.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=?",(uid,)); total = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_history WHERE status='PHISHING' AND user_id=?",(uid,)); threats = c.fetchone()[0] or 0
    c.execute("SELECT AVG(threat_score) FROM scan_history WHERE user_id=?",(uid,)); avg = round(c.fetchone()[0] or 0,1)
    c.execute("SELECT id,url,status,threat_score,timestamp FROM scan_history WHERE user_id=? ORDER BY id DESC LIMIT 5",(uid,)); recent = c.fetchall()
    c.execute("SELECT COUNT(*) FROM scan_history WHERE status='SAFE' AND user_id=?",(uid,)); safe = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_history WHERE status='UNVERIFIED' AND user_id=?",(uid,)); susp = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM scan_history WHERE status='PHISHING' AND user_id=?",(uid,)); phish = c.fetchone()[0] or 0
    conn.close()
    return render_template("dashboard.html", stats=[total,threats,avg], recent_scans=recent,
                           threat_dist=[{'0':'SAFE','1':safe},{'0':'UNVERIFIED','1':susp},{'0':'PHISHING','1':phish}])

@app.route("/history")
def history():
    if 'user' not in session: return redirect("/login")
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    c.execute("SELECT id,url,status,threat_score,timestamp FROM scan_history WHERE user_id=? ORDER BY id DESC",(session['user_id'],))
    scans = c.fetchall(); conn.close()
    return render_template("history.html", scans=scans)

@app.route("/about")
def about(): return render_template("about.html")

@app.route("/settings")
def settings():
    if 'user' not in session: return redirect("/login")
    return render_template("settings.html")

@app.route("/learn-more")
def learn_more(): return render_template("learn_more.html")

@app.route('/download_enhanced_report/<int:scan_id>')
def download_report(scan_id):
    if 'user' not in session: return redirect("/login")
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    c.execute("SELECT url,status,details,domain_age,ip_address,website_status,threat_score,timestamp FROM scan_history WHERE id=? AND user_id=?",
              (scan_id, session['user_id']))
    data = c.fetchone(); conn.close()
    if not data: return "Report not found", 404
    url, status, details, age, ip, web_status, score, timestamp = data
    pdf = FPDF(); pdf.add_page(); pdf.set_auto_page_break(auto=False)
    pdf.set_fill_color(11,17,32); pdf.rect(0,0,210,297,'F')
    pdf.set_fill_color(37,99,235); pdf.rect(0,0,210,2,'F')
    pdf.set_font("Arial",'B',28); pdf.set_text_color(255,255,255); pdf.set_xy(15,15); pdf.cell(0,10,"VeriScope",0,1)
    pdf.set_font("Arial",'',11); pdf.set_text_color(148,163,184)
    pdf.set_xy(15,27); pdf.cell(0,6,"Phishing Website Detection – Forensic Report",0,1)
    pdf.set_xy(15,34); pdf.cell(0,6,f"Generated: {timestamp}",0,1)
    if status=='SAFE': r,g,b,lbl=16,185,129,"SECURE"
    elif status=='PHISHING': r,g,b,lbl=239,68,68,"THREAT DETECTED"
    else: r,g,b,lbl=234,179,8,"CAUTION – UNVERIFIED"
    pdf.set_fill_color(30,41,59); pdf.rect(15,48,180,50,'F')
    pdf.set_fill_color(r,g,b); pdf.rect(15,48,6,50,'F')
    pdf.set_xy(26,54); pdf.set_font("Arial",'B',10); pdf.set_text_color(148,163,184); pdf.cell(0,6,"SCANNED URL",0,1)
    pdf.set_xy(26,61); pdf.set_font("Arial",'B',14); pdf.set_text_color(255,255,255); pdf.cell(120,8,url[:60]+("..." if len(url)>60 else ""),0,0)
    pdf.set_xy(150,58); pdf.set_font("Arial",'B',18); pdf.set_text_color(r,g,b); pdf.cell(40,10,lbl,0,0,'R')
    pdf.set_xy(26,75); pdf.set_font("Arial",'',11); pdf.set_text_color(203,213,225); pdf.cell(0,6,f"Detection Reason: {details}",0,1)
    def draw_card(x,y,icon_label,label,value,val_color=None):
        pdf.set_fill_color(22,32,64); pdf.rect(x,y,85,35,'F')
        pdf.set_fill_color(37,99,235); pdf.rect(x,y,85,1,'F')
        pdf.set_xy(x+5,y+5); pdf.set_font("Arial",'B',8); pdf.set_text_color(100,149,237); pdf.cell(80,5,icon_label.upper(),0,1)
        pdf.set_xy(x+5,y+13); pdf.set_font("Arial",'B',8); pdf.set_text_color(100,116,139); pdf.cell(80,5,label.upper(),0,1)
        pdf.set_xy(x+5,y+22); pdf.set_font("Arial",'B',12)
        pdf.set_text_color(*(val_color if val_color else (255,255,255))); pdf.cell(80,8,str(value)[:30],0,0)
    sc=(16,185,129) if score<30 else (239,68,68) if score>=70 else (234,179,8)
    draw_card(15,110,"THREAT LEVEL","Threat Score",f"{score} / 100",val_color=sc)
    draw_card(110,110,"RISK FINDING","Detection Reason",details[:28])
    draw_card(15,155,"DOMAIN INFO","Domain Age",age)
    draw_card(110,155,"NETWORK INFO","Server IP Address",ip)
    draw_card(15,200,"CONNECTIVITY","Website Status",web_status,val_color=(16,185,129) if "Online" in web_status else (239,68,68))
    draw_card(110,200,"PROTOCOL","SSL / HTTPS","Secure (HTTPS)" if "HTTPS" in web_status else "Not Verified",val_color=(16,185,129) if "HTTPS" in web_status else (234,179,8))
    pdf.set_xy(15,248); pdf.set_font("Arial",'B',13); pdf.set_text_color(255,255,255); pdf.cell(0,8,"Executive Summary",0,1)
    pdf.set_font("Arial",'',10); pdf.set_text_color(203,213,225); pdf.set_xy(15,258)
    pdf.multi_cell(180,6,f'The domain "{url}" was analyzed by VeriScope on {timestamp}. Verdict: {status}. {details}.')
    pdf.set_fill_color(37,99,235); pdf.rect(0,292,210,5,'F')
    pdf.set_y(284); pdf.set_font("Arial",'I',8); pdf.set_text_color(100,116,139)
    pdf.cell(0,6,"Confidential Security Report | VeriScope Phishing Detection | NBKRIST 2026",0,0,'C')
    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=VeriScope_Report_{scan_id}.pdf'
    return response

if __name__ == '__main__': app.run(host="localhost", port=3000, debug=True)
