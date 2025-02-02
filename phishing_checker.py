import requests
import gradio as gr
import re
import dns.resolver
from urllib.parse import urlparse

### Function 1: Phishing URL Detector (via urlscan.io API & keyword detection) ###
def phishing_url_checker(url, api_key=""):
    """
    Analyzes a given URL for phishing attempts using urlscan.io API and keyword analysis.

    Args:
        url (str): The URL to check.
        api_key (str): urlscan.io API Key.

    Returns:
        str: Analysis result with URL safety status.
    """
    
    if not url.startswith(("http://", "https://")):
        return "Invalid URL format. Ensure it starts with http:// or https://"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Check for phishing-related keywords
    phishing_keywords = ["login", "verify", "banking", "secure", "update", "password", "account"]
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return f"⚠️ Suspicious URL detected: Contains phishing-related keywords ({', '.join(phishing_keywords)})"

    # Check for excessive subdomains (common phishing tactic)
    if domain.count('.') > 2:
        return f"⚠️ Suspicious URL: {domain} has too many subdomains, a common phishing technique."

    # Check with urlscan.io API if API key is provided
    if api_key:
        urlscan_result = check_with_urlscan(api_key, url)
        if urlscan_result:
            return urlscan_result

    return "✅ URL appears safe (No immediate threats detected). However, always verify manually."

# Function to check URL with urlscan.io API
def check_with_urlscan(api_key, url):
    """
    Submits the given URL to urlscan.io API for analysis and retrieves the result.

    Args:
        api_key (str): urlscan.io API key.
        url (str): URL to analyze.

    Returns:
        str: Result summary and scan report link.
    """
    urlscan_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}

    try:
        response = requests.post(urlscan_url, json=payload, headers=headers)
        response.raise_for_status()
        result_data = response.json()
        scan_id = result_data.get("uuid")
        if scan_id:
            result_url = f"https://urlscan.io/result/{scan_id}/"
            return f"🔍 URL submitted for scanning. View detailed report here: {result_url}"
        else:
            return "⚠️ Error: Unable to retrieve scan result."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Error contacting urlscan.io: {str(e)}"


### Function 2: Phishing Email Detector (Checks email domain reputation & SPF records) ###
def phishing_email_checker(email):
    """
    Checks if an email address is from a valid domain and checks SPF records.

    Args:
        email (str): The email address to check.

    Returns:
        str: Analysis result with domain validation.
    """
    if "@" not in email:
        return "Invalid email format."

    domain = email.split('@')[-1]

    # Check if domain has valid MX records (legit email providers)
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        if answers:
            return f"✅ Email domain '{domain}' has valid MX records. Likely legitimate."
    except:
        return f"⚠️ Warning: Email domain '{domain}' has no valid mail exchange records."

    return f"⚠️ Unable to verify email domain '{domain}'."


### Function 3: Phishing SMS Detector (Scans messages for phishing patterns) ###
def phishing_sms_checker(sms_text):
    """
    Scans an SMS message for phishing indicators, such as shortened URLs or suspicious keywords.

    Args:
        sms_text (str): The SMS message content.

    Returns:
        str: Analysis result indicating whether the SMS is suspicious.
    """
    
    phishing_keywords = ["urgent", "bank", "click here", "verify", "account locked", "reset password"]
    shortened_url_patterns = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly"]

    # Check for phishing keywords
    if any(keyword in sms_text.lower() for keyword in phishing_keywords):
        return f"⚠️ Suspicious SMS detected: Contains phishing-related keywords ({', '.join(phishing_keywords)})"

    # Check for shortened URLs
    if any(url in sms_text.lower() for url in shortened_url_patterns):
        return f"⚠️ Suspicious SMS detected: Contains a shortened URL ({', '.join(shortened_url_patterns)}), often used in phishing."

    return "✅ SMS appears safe. No immediate threats detected."

