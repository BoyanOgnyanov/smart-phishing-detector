from mitmproxy import http
from openai import OpenAI
import json
import re
import requests
from datetime import datetime
from urllib.parse import urlparse, urlunparse
import base64
from bs4 import BeautifulSoup

# 🔑 API-Keys
OPENAI_API_KEY = "<YOUR-API-KEY>"
VIRUSTOTAL_API_KEY = "YOUR-API-KEY"
GOOGLE_API_KEY = "YOUR-API-KEY"

# Scoring weight per engine (Scale 1–3)
RELIABILITY_WEIGHTS = {

    # Highly trusted
    "BitDefender": 3,
    "ESET": 3,
    "Fortinet": 3,
    "G-Data": 3,
    "Kaspersky": 3,
    "Sophos": 3,
    "Google Safebrowsing": 3,
    "Dr.Web": 3,
    "Emsisoft": 3,
    "Webroot": 3,
    "PhishTank": 3,
    "Avira": 3,        # If available
    "Microsoft": 3,    # If available

    # Medium trust
    "AlienVault": 2,
    "McAfee": 2,
    "OpenPhish": 2,
    "malwares.com URL checker": 2,
    "Quick Heal": 2,
    "Phishing Database": 2,
    "Sucuri SiteCheck": 2,
    "Spam404": 2,
    "StopForumSpam": 2,
    "EmergingThreats": 2,
    "Yandex Safebrowsing": 2,
    "Feodo Tracker": 2,
    "URLhaus": 2,
    "ViriBack": 2,
    "Trustwave": 2,
    "desenmascara.me": 2,
    "GreenSnow": 2,
    "ThreatHive": 2,
}

# Minimum total score to classify a site as phishing
PHISHING_SCORE_THRESHOLD = 5

# New OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY)

# === OpenAI classification ===
def classify_with_openai(url: str, title: str = "", html_code: str = "") -> str:
    prompt = f"""
You are a cybersecurity analyst specializing in phishing detection.
Analyze the website based on the URL, page title, and HTML content and return **only one** of the following classifications: `"phishing"` or `"legitimate"`.

Evaluation criteria:

🔴 **Phishing indicators:**
- Domain mimics well-known brands (e.g., `paypal-secure-login.com`, `cloud-trezor-wallet.webflow.io`)
- Hosted on GitHub Pages, Webflow, Cloudflare Workers, etc., with login, wallet, seed phrase content
- Forms requesting sensitive data like passwords, wallets, seeds
- No legal imprint or contact, suspicious redirects
- Design or wording creates urgency or pressure

🟢 **Legitimate indicators:**
- Domain matches the represented brand (e.g., `paypal.com`, `trezor.io`)
- No sensitive forms or suspicious scripts
- Clear source, legal information visible

Do not be misled by harmless-looking domains. Use the HTML content, especially forms, scripts, and visible text.

Respond with only: `"phishing"` or `"legitimate"` (no explanation, no extra output).

URL: {url}
Page title: {title}
HTML content (truncated): {html_code[:1000]}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an experienced cybersecurity analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        result = response.choices[0].message.content.lower()
        return "phishing" if "phishing" in result else "legitimate" if "legitimate" in result else "unknown"
    except Exception as e:
        print(f"[OpenAI Error] {url}: {e}")
        return "error"

# === Load HTML content and title ===
def load_html_and_title(url: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }
        res = requests.get(url, headers=headers, timeout=10)
        html = res.text
        soup = BeautifulSoup(html, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        return html, title
    except Exception as e:
        print(f"[HTML Load Error] {url}: {e}")
        return "", ""

# === Normalize URL: remove query parameters and fragments ===
def normalize_url(url):
    parsed = urlparse(url)
    cleaned = parsed._replace(query="", fragment="")
    return urlunparse(cleaned)

# === VIRUSTOTAL ===
def check_virustotal(url: str) -> str:
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_api = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        res = requests.get(url_api, headers=headers)
        
        if res.status_code != 200:
            print(f"[VT Error] {url}: Status {res.status_code}")
            return "error"

        data = res.json()
        analysis = data["data"]["attributes"]["last_analysis_results"]

        score = 0
        print(f"\n Evaluation for: {url}")
        for engine, result in analysis.items():
            category = result.get("category", "")
            if category in ["malicious", "phishing", "suspicious"]:
                weight = RELIABILITY_WEIGHTS.get(engine, 1)
                score += weight
                print(f"⚠️ {engine}: {category} (Weight: {weight})")

        print(f"🧮 Total Score: {score} (Threshold: {PHISHING_SCORE_THRESHOLD})")

        return "phishing" if score >= PHISHING_SCORE_THRESHOLD else "legitimate"
    
    except Exception as e:
        print(f"[VT Exception] {url}: {e}")
        return "error"

# === GOOGLE SAFE BROWSING ===
def check_google_safe_browsing(url: str) -> str:
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {
                "clientId": "firewall-ai-proxy",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(endpoint, json=payload)
        if res.status_code == 200:
            return "phishing" if "matches" in res.json() else "legitimate"
        return "unknown"
    except Exception as e:
        print(f"Google Safe Browsing Error: {e}")
        return "unknown"

# === Main logic to analyze and decide ===
def analyze_and_block(flow: http.HTTPFlow):
    original_url = flow.request.pretty_url.lower()
    url = normalize_url(original_url)

    if not flow.response:
        return
    
    content_type = flow.response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return

    if any(url.endswith(ext) for ext in [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", 
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".avi", ".pdf"
    ]):
        return

    print(f"🔍 Analyzing URL: {url}")

    html_code, title = load_html_and_title(url)
    openai_result = classify_with_openai(url, title, html_code)
    print(f"🔍 OpenAI classification: {openai_result}")

    gsb_result = check_google_safe_browsing(url)
    vt_result = check_virustotal(url)

    print(f"➡️ Google: {gsb_result}, VirusTotal: {vt_result}")

    if "phishing" in [gsb_result, vt_result, openai_result]:
        decision = "phishing"
    elif gsb_result == vt_result == openai_result == "legitimate":
        decision = "legitimate"
    else:
        decision = "uncertain"

    if decision == "phishing":
        flow.response = http.Response.make(
            403,
            f"""
            <html>
                <head><title>Phishing Blocked</title></head>
                <body>
                    <h1 style="color:red;">⚠️ Access Blocked</h1>
                    <p>This website was classified as <strong>phishing</strong>.</p>
                    <p>URL: {url}</p>
                </body>
            </html>
            """.encode(),
            {"Content-Type": "text/html; charset=utf-8"}
        )
    elif decision == "uncertain":
        flow.response = http.Response.make(
            403,
            f"""
            <html>
                <head><title>Uncertain Classification</title></head>
                <body>
                    <h1>⚠️ Access Blocked</h1>
                    <p>This page could not be clearly verified.</p>
                    <p>URL: {url}</p>
                </body>
            </html>
            """.encode(),
            {"Content-Type": "text/html; charset=utf-8"}
        )
    else:
        print(f"✅ Access allowed: {url}")

# === mitmproxy Hook ===
def response(flow: http.HTTPFlow):
    analyze_and_block(flow)
