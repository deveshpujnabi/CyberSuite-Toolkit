import cv2
import numpy as np
import requests
import re
from urllib.parse import urlparse

def decode_and_audit(image, api_key=""):
    # Convert image to OpenCV format
    image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

    # Initialize QR Code detector
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(image)

    if not data:
        return "No QR code detected!", None, None, None, None

    # Analyze URL
    analysis_result, link_category, url_type = analyze_url(data)

    # Check with urlscan.io API
    if api_key:
        urlscan_check, urlscan_details = check_url_with_urlscan(api_key, data)
        analysis_result += f"\nurlscan.io: {urlscan_check}"
    else:
        urlscan_details = None

    return analysis_result, data, link_category, url_type, urlscan_details

def analyze_url(url):
    if not re.match(r'^https?://', url):
        return "Invalid QR code content. Not a URL.", "Invalid", "Invalid"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Categorize URL
    if "facebook.com" in domain or "twitter.com" in domain:
        category = "Social Media"
    elif parsed_url.path.endswith(('.pdf', '.docx', '.xlsx', '.zip')):
        category = "File Download"
    elif "youtube.com" in domain or "vimeo.com" in domain:
        category = "Video Streaming"
    else:
        category = "General Website"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return f"Safe URL: {url}\nCategory: {category}\nDomain: {domain}", category, "Safe"
        else:
            return f"Potential Issue Detected: {url} (HTTP {response.status_code})", category, "Potential Issue"
    except requests.exceptions.RequestException:
        return "Malicious or Unreachable URL.", "Malicious/Unreachable", "Malicious"

def check_url_with_urlscan(api_key, url):
    urlscan_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url}

    try:
        response = requests.post(urlscan_url, json=payload, headers=headers)
        response.raise_for_status()
        if response.status_code == 200:
            scan_result_url = response.json()["result"]
            return f"URL submitted. View report at: {scan_result_url}", scan_result_url
        else:
            return f"Error: {response.status_code}", None
    except Exception as e:
        return f"Error contacting urlscan.io: {str(e)}", None
