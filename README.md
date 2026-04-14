# VeriScope AI — Phishing Website Detection

A real-time phishing detection web app built with Flask. Paste any URL and instantly know if it's safe, suspicious, or a phishing attempt.

---

## Features

- **Real-time URL scanning** — detects phishing, typosquatting, homograph attacks, brand impersonation
- **Threat score** — 0–100 risk rating with visual gauge
- **Forensic details** — domain age (WHOIS), IP address, SSL status, website availability
- **PDF reports** — download a full forensic report for any scan (logged-in users)
- **Scan history** — all scans saved per user
- **3 free scans** — guests get 3 scans, then prompted to sign up
- **Email-based auth** — register and login with email + password

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite |
| PDF Generation | fpdf |
| WHOIS Lookup | python-whois |
| HTTP Analysis | requests |
| Parallel Scanning | ThreadPoolExecutor |
| Frontend | HTML, CSS, Vanilla JS |

---

## Detection Methods

- Homograph / lookalike domain detection
- Typosquatting (fuzzy string matching)
- Brand impersonation (PayPal, Google, SBI, etc.)
- Raw IP address usage
- High-entropy domain names
- Deceptive keywords in URL (`login`, `secure`, `verify`, etc.)
- High-risk TLDs (`.xyz`, `.tk`, `.top`, etc.)
- Newly registered domains (< 30 days)
- Fake login page detection via page title analysis
- SSL certificate issuer verification

---

## Setup & Run

### 1. Install dependencies

```bash
pip install flask requests python-whois fpdf scipy scikit-learn numpy pandas
```

### 2. Run the app

```bash
python app.py
```

### 3. Open in browser

```
http://localhost:3000
```

---

## Default Admin Account

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `admin` |

---

## Project Structure

```
├── app.py               # Main Flask application
├── veriscope.db         # SQLite database
├── requirements.txt     # Python dependencies
├── templates/
│   ├── home.html        # Landing page + scanner
│   ├── result.html      # Scan result page
│   ├── login.html       # Login page
│   ├── register.html    # Register page
│   ├── dashboard.html   # User dashboard
│   ├── history.html     # Scan history
│   ├── about.html       # About page
│   ├── settings.html    # Settings page
│   └── learn_more.html  # Security tips
```

---

## Screenshots

| Page | Description |
|---|---|
| Home | URL input with 3-scan free counter |
| Result | Verdict banner, threat gauge, forensic cards |
| Login/Register | ChatGPT-style dark modal |
| Dashboard | Stats, recent scans, threat distribution |

---

## Notes

- Guest users get **3 free scans** tracked via `localStorage`
- After 3 scans a login modal appears automatically
- After login/register the counter resets and scans are unlimited
- All scans by logged-in users are saved to history
- PDF reports require login

---

*Built for NBKRIST 2026 — VeriScope Phishing Detection System*
