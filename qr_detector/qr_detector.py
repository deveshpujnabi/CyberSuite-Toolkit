import cv2
import numpy as np
import requests
import re
import matplotlib.pyplot as plt
from urllib.parse import urlparse

# Function to decode QR code and analyze the URL
def decode_and_audit(image, api_key):
    # Convert Gradio input image to OpenCV format
    image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

    # Initialize QR Code detector
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(image)

    if not data:
        return "No QR code detected!", None, None, None, None

    # Analyze the URL
    analysis_result, link_category, url_type = analyze_url(data)

    # Check with urlscan.io API (if API key is provided)
    if api_key:
        urlscan_check, urlscan_details = check_url_with_urlscan(api_key, data)
        analysis_result += f"\nurlscan.io: {urlscan_check}"
    else:
        urlscan_details = None

    return analysis_result, data, link_category, url_type, urlscan_details

# Function to analyze the URL and determine its category
def analyze_url(url):
    # Check if it's a valid URL
    if not re.match(r'^https?://', url):
        return "Invalid QR code content. Not a URL.", "Invalid", "Invalid"

    # Extract URL details
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Categorize URL based on domain or path
    if "facebook.com" in domain or "twitter.com" in domain or "instagram.com" in domain:
        category = "Social Media"
    elif parsed_url.path.endswith(('.pdf', '.docx', '.xlsx', '.zip')):
        category = "File Download"
    elif "youtube.com" in domain or "vimeo.com" in domain:
        category = "Video Streaming"
    else:
        category = "General Website"

    # Analyze URL by making a request
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return f"Safe URL: {url}\nCategory: {category}\nDomain: {domain}", category, "Safe"
        else:
            return f"Potential Issue Detected: {url} (HTTP {response.status_code})", category, "Potential Issue"
    except requests.exceptions.RequestException:
        return "Malicious or Unreachable URL.", "Malicious/Unreachable", "Malicious"

# Function to check URL with urlscan.io API
def check_url_with_urlscan(api_key, url):
    if not api_key:
        return "API key is missing or invalid.", None

    urlscan_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "87e80f29-7aea-48a4-bd02-85e2db1dc87e": api_key,  # Set your API key here dynamically
        "Content-Type": "application/json"
    }

    payload = {
        "url": url
    }

    try:
        # Make a POST request to submit the URL for analysis
        response = requests.post(urlscan_url, json=payload, headers=headers)
        response.raise_for_status()  # Will raise an exception for 4xx/5xx status codes

        if response.status_code == 200:
            # If the URL is successfully submitted for scanning, we check the scan result
            scan_result_url = response.json()["data"]["scan_id"]
            result_url = f"https://urlscan.io/result/{scan_result_url}/"

            # Retrieve scan results to check for known threats
            scan_details = requests.get(result_url).json()
            threat_details = check_for_threats(scan_details)

            if threat_details:
                return f"Potential Threat Detected: {threat_details}", result_url
            else:
                return f"URL submitted for scan. View detailed report at: {result_url}", None
        else:
            return f"Error contacting urlscan.io API. Status Code: {response.status_code}", None

    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}", None

# Function to check the scan result for known threats like phishing, malware, etc.
def check_for_threats(scan_details):
    # Example of checking if the scan details include threats
    threat_types = ["phishing", "malware", "spam", "fraudulent"]

    for entry in scan_details.get('data', {}).get('tags', []):
        if entry in threat_types:
            return f"Threat detected: {entry}"

    return None

# Function to generate a detailed report and chart
def generate_audit_report(results):
    if not results:
        return "No results to generate a report."

    # Aggregate the results
    categories = [r[2] for r in results if r[2] is not None]
    category_counts = {category: categories.count(category) for category in set(categories)}

    # Plot the results
    plt.figure(figsize=(8, 5))
    plt.bar(category_counts.keys(), category_counts.values(), color='skyblue')
    plt.title("QR Code Audit Report")
    plt.xlabel("QR Code Category")
    plt.ylabel("Count")
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.show()

# Gradio Interface Function
def qr_code_audit_app(image, api_key=""):
    analysis_result, qr_data, link_category, url_type, urlscan_details = decode_and_audit(image, api_key)

    # Collect results for generating the audit report later
    results = [(image, qr_data, link_category)]  # This would be extended to handle multiple scans

    # Generate the audit report after processing
    generate_audit_report(results)

    return analysis_result, qr_data, link_category, url_type, urlscan_details
