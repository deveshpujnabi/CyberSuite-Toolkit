import requests
import gradio as gr
import validators
import tldextract
from bs4 import BeautifulSoup

# Your Google Safe Browsing API key
GOOGLE_API_KEY = "Your-API-Key"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# List of suspicious keywords commonly found in phishing pages
suspicious_keywords = [
    'login', 'verify', 'update', 'secure', 'account', 'password',
    'free', 'urgent', 'click', 'offer', 'limited', 'winner', 'claim'
]

# Check with Google Safe Browsing API
def check_google_safe_browsing(url):
    payload = {
        "client": {
            "clientId": "phishing-link-scanner",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(f"{SAFE_BROWSING_URL}?key={GOOGLE_API_KEY}", json=payload, timeout=5)
        data = response.json()

        if "matches" in data:
            return True, data["matches"]
        else:
            return False, None

    except requests.exceptions.RequestException as e:
        return False, f"Error checking with Safe Browsing: {str(e)}"

# Function to check if a domain is suspicious
def is_suspicious_domain(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # Flag unusual subdomains (e.g., "secure-login.bank.com")
    if extracted.subdomain and extracted.subdomain not in ["www", ""]:
        return True

    return False

# Function to scan the URL for phishing indicators
def scan_phishing(url):
    # Validate URL
    if not validators.url(url):
        return "❌ Invalid URL. Please enter a valid URL."

    # Check with Google Safe Browsing API
    safe, details = check_google_safe_browsing(url)
    if safe:
        return f"🚨 Unsafe URL detected by Google Safe Browsing!\nDetails: {details}"

    # Check domain for suspicious patterns
    if is_suspicious_domain(url):
        return "⚠️ Suspicious domain detected! This could be a phishing link."

    try:
        # Request webpage with timeout
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code != 200:
            return f"⚠️ Failed to access page. HTTP Status Code: {response.status_code}"

        # Extract page title
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else "No title found"

        # Check if title contains phishing indicators
        if any(keyword in title.lower() for keyword in suspicious_keywords):
            return f"⚠️ Phishing warning! The page title contains suspicious words: {title}"

        return f"✅ Safe! No phishing indicators detected. Page Title: {title}"

    except requests.exceptions.RequestException as e:
        return f"❌ Error scanning URL: {str(e)}"
