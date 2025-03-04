# phishing_checker/phishing_checker.py
import requests
import re
import dns.resolver
from urllib.parse import urlparse

def phishing_url_checker(url, api_key=None):
    """
    Checks if a URL is potentially malicious using keyword analysis and optional urlscan.io API.
    
    Args:
        url (str): The URL to check.
        api_key (str, optional): API key for urlscan.io.
    
    Returns:
        str: Analysis result.
    """
    if not url.startswith(("http://", "https://")):
        return "Invalid URL format. Make sure it starts with http:// or https://"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Check for phishing-related keywords
    phishing_keywords = ["login", "verify", "banking", "secure", "update", "password", "account"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return f"⚠️ Suspicious URL detected: Contains phishing-related keywords ({', '.join(phishing_keywords)})"

    # Check for excessive subdomains
    if domain.count('.') > 2:
        return f"⚠️ Suspicious URL: {domain} has too many subdomains, a common phishing technique."

    # Optional: Check with urlscan.io
    if api_key:
        return check_with_urlscan(api_key, url)
    
    return "✅ URL appears safe (No immediate threats detected). However, always verify manually."


def check_with_urlscan(api_key, url):
    urlscan_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}
    
    try:
        response = requests.post(urlscan_url, json=payload, headers=headers)
        response.raise_for_status()
        result_data = response.json()
        scan_id = result_data.get("uuid")
        if scan_id:
            return f"🔍 URL submitted for scanning. View detailed report here: https://urlscan.io/result/{scan_id}/"
        else:
            return "⚠️ Error: Unable to retrieve scan result."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Error contacting urlscan.io: {str(e)}"


def phishing_email_checker(email):
    """
    Checks if an email domain has valid MX records.
    
    Args:
        email (str): The email address to check.
    
    Returns:
        str: Email validation result.
    """
    if "@" not in email:
        return "Invalid email format."
    
    domain = email.split('@')[-1]
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if answers:
            return f"✅ Email domain '{domain}' has valid MX records. Likely legitimate."
    except:
        return f"⚠️ Warning: Email domain '{domain}' has no valid mail exchange records."
    
    return f"⚠️ Unable to verify email domain '{domain}'."


def phishing_sms_checker(sms_text):
    """
    Scans an SMS message for phishing indicators.
    
    Args:
        sms_text (str): The SMS content.
    
    Returns:
        str: Analysis result.
    """
    phishing_keywords = ["urgent", "bank", "click here", "verify", "account locked", "reset password"]
    shortened_url_patterns = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]

    if any(keyword in sms_text.lower() for keyword in phishing_keywords):
        return f"⚠️ Suspicious SMS detected: Contains phishing-related keywords ({', '.join(phishing_keywords)})"

    if any(url in sms_text.lower() for url in shortened_url_patterns):
        return f"⚠️ Suspicious SMS detected: Contains a shortened URL ({', '.join(shortened_url_patterns)}), often used in phishing."

    return "✅ SMS appears safe. No immediate threats detected."
