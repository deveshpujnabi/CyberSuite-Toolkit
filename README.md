# 🛡️ CyberSuite Toolkit

CyberSuite Toolkit is a powerful, all-in-one cybersecurity toolkit with a user-friendly interface powered by Gradio. It includes tools for SQL injection testing, QR code analysis, phishing detection, password management, vulnerability scanning, and encryption!

## 📂 Project Structure
```
CyberSuite-Toolkit/
├── app.py                  # Gradio UI and entry point
├── requirements.txt        # Python dependencies
├── sql_injection/          # SQL Injection testing tool
├── qr_detector/            # QR Code analysis tool
├── phishing_checker/      # Phishing detection tool
├── data_breach_checker/   # Password & breach management tool
├── vulnerability_scanner/ # Website vulnerability scanner
├── encryption_tool/       # Encryption & decryption tool
└── README.md              # Project documentation
```

## ⚡ Features
- **SQL Injection Testing** — Scan URLs for SQL injection vulnerabilities with SQLmap.
- **QR Code Detector** — Scan QR codes and analyze the URLs for potential threats.
- **Phishing Detection** — Check URLs, emails, and SMS for phishing indicators.
- **Password & Breach Management** — Check password strength, generate secure passwords, and check breaches with Have I Been Pwned.
- **Vulnerability Scanner** — Scan websites for misconfigurations, outdated software, and more.
- **Encryption Tool** — Encrypt, decrypt messages, and generate secure encryption keys.

## 🛠️ Setup & Installation

### 🚩 On Kali Linux / 🪟 On Windows (Both)

1. **Install Git and Clone SQLmap:**
```bash
# Install Git (if not already installed)
sudo apt-get install git   # For Kali Linux
```
Or on Windows (via Git Bash or WSL):
```bash
winget install --id Git.Git -e --source winget
```

2. **Clone SQLmap Repository:**
```bash
git clone --recursive https://github.com/sqlmapproject/sqlmap.git
```

3. **Clone the CyberSuite Repository:**
```bash
git clone https://github.com/your-repo/CyberSuite-Toolkit.git
cd CyberSuite-Toolkit
```

4. **Create a Virtual Environment:**
```bash
python3 -m venv venv
source venv/bin/activate   # On Linux
venv\Scripts\activate     # On Windows
```

5. **Install Dependencies:**
```bash
pip install -r requirements.txt
```

6. **Run the Application:**
```bash
python3 app.py   # On Linux
python app.py    # On Windows
```

7. **Access the Dashboard:**
Gradio will provide you with a local or public link to access the toolkit in your browser.

## 🚀 Tools Overview

### SQL Injection Tool
- Uses SQLmap to test URLs for SQL injection vulnerabilities.
- Automatically generates a report for download.

### QR Detector
- Scans uploaded images for QR codes.
- Audits decoded URLs for potential risks (file downloads, social media, etc.).

### Phishing Checker
- URL, email, and SMS phishing detection.
- Optionally integrates with urlscan.io for deep URL scans.

### Password & Breach Management
- Password strength checking and feedback.
- Secure password generator with customizable options.
- Password breach checking using the Have I Been Pwned API.

### Vulnerability Scanner
- Scans websites for outdated server versions, directory listing, and misconfigurations.
- Checks meta tags for outdated CMS versions.

### Encryption Tool
- Generate encryption keys.
- Encrypt and decrypt messages using Fernet (symmetric encryption).

## 🏁 Contributing
Contributions are welcome! If you find bugs or have feature suggestions, feel free to fork the repo and submit a pull request.

## 📜 License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

Happy hacking! 🚀

Let me know if you want me to tweak anything! ✨
