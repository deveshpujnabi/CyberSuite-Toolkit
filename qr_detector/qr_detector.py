# qr_detector/qr_detector.py
import cv2
import numpy as np
import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def qr_code_audit_app(image, api_key=None):
    """
    Decodes a QR code from an image and analyzes the URL.
    
    Args:
        image: The image containing the QR code.
        api_key (str, optional): API key for urlscan.io to check the URL.
    
    Returns:
        dict: Analysis results including decoded data, link category, and threat status.
    """
    try:
        image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image)
        
        if not data:
            return {"result": "No QR code detected!"}
        
        result, category, status = analyze_url(data)
        
        if api_key:
            urlscan_result = check_url_with_urlscan(api_key, data)
            result += f"\nurlscan.io: {urlscan_result}"
        
        return {"result": result, "decoded_data": data, "category": category, "status": status}
    
    except Exception as e:
        return {"result": f"Error processing image: {str(e)}"}


def analyze_url(url):
    if not re.match(r'^https?://', url):
        return "Invalid QR code content. Not a URL.", "Invalid", "Invalid"
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Basic URL categorization
    if "facebook.com" in domain or "twitter.com" in domain:
        category = "Social Media"
    elif parsed_url.path.endswith(('.pdf', '.zip')):
        category = "File Download"
    else:
        category = "General Website"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return f"Safe URL: {url}", category, "Safe"
        else:
            return f"Potential Issue: HTTP {response.status_code}", category, "Potential Issue"
    except requests.exceptions.RequestException:
        return "Malicious or Unreachable URL.", "Malicious/Unreachable", "Malicious"


def check_url_with_urlscan(api_key, url):
    urlscan_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url}
    
    try:
        response = requests.post(urlscan_url, json=payload, headers=headers)
        response.raise_for_status()
        result_url = response.json().get("result")
        return result_url if result_url else "Scan submitted, check urlscan.io for results."
    except requests.exceptions.RequestException as e:
        return f"Error contacting urlscan.io: {str(e)}"
