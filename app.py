# app.py
import gradio as gr
from sql_injection.sql_injection import run_sqlmap
from qr_detector.qr_detector import qr_code_audit_app
from phishing_checker.phishing_checker import phishing_url_checker, phishing_email_checker, phishing_sms_checker
from data_breach_checker.password_checker import gradio_password_strength, gradio_generate_password, gradio_breach_checker
from vulnerability_scanner.vulnerability_scanner import vulnerability_scanner
from encryption_tool.encryption_tool import generate_key, encrypt_message, decrypt_message

# Create the Gradio interface
with gr.Blocks() as demo:
    gr.Markdown("# 🛡️ CyberSuite Toolkit Dashboard")

    with gr.Tab("SQL Injection"):
        gr.Interface(
            fn=run_sqlmap,
            inputs=gr.Textbox(label="Enter URL to test for SQL Injection"),
            outputs="file",
            title="SQL Injection Testing with SQLmap",
            description="Test a URL for SQL Injection using SQLmap automation. Download the results after the scan."
        )

    with gr.Tab("QR Detector"):
        gr.Interface(
            fn=qr_code_audit_app,
            inputs=[gr.Image(label="Upload or Capture QR Code"), gr.Textbox(label="urlscan.io API Key (Optional)")],
            outputs=[
                gr.Textbox(label="Analysis Result"),
                gr.Textbox(label="Decoded QR Data"),
                gr.Textbox(label="Link Category"),
                gr.Textbox(label="URL Type (Safe, Potential Issue, Malicious)"),
                gr.Textbox(label="urlscan.io Report Link")
            ]
        )

    with gr.Tab("Phishing Detection"):
        with gr.Tab("URL Phishing Checker"):
            gr.Interface(fn=phishing_url_checker, inputs=[
                gr.Textbox(label="Enter URL", placeholder="https://example.com"),
                gr.Textbox(label="urlscan.io API Key (Optional)")
            ], outputs="text")
        with gr.Tab("Email Phishing Checker"):
            gr.Interface(fn=phishing_email_checker, inputs="text", outputs="text")
        with gr.Tab("SMS Phishing Checker"):
            gr.Interface(fn=phishing_sms_checker, inputs="text", outputs="text")

    with gr.Tab("Password & Data Breach Management"):
        with gr.Tab("Check Password Strength"):
            gr.Interface(fn=gradio_password_strength, inputs="text", outputs="text")
        with gr.Tab("Generate Password"):
            gr.Interface(fn=gradio_generate_password, inputs=[
                gr.Slider(label="Password Length", minimum=8, maximum=64, step=1, value=12),
                gr.Checkbox(label="Include Uppercase Letters", value=True),
                gr.Checkbox(label="Include Lowercase Letters", value=True),
                gr.Checkbox(label="Include Digits", value=True),
                gr.Checkbox(label="Include Special Characters", value=True)
            ], outputs="text")
        with gr.Tab("Check Password Breach"):
            gr.Interface(fn=gradio_breach_checker, inputs="text", outputs="text")
    
    with gr.Tab("Vulnerability Scanner"):
        gr.Interface(
            fn=vulnerability_scanner,
            inputs=gr.Textbox(label="Enter Website URL", placeholder="https://example.com"),
            outputs=gr.Textbox(label="Scan Results")
        )

    with gr.Tab("Encryption Tool"):
        with gr.Tab("Generate Key"):
            gr.Interface(fn=generate_key, inputs=None, outputs="text")
        with gr.Tab("Encrypt Message"):
            gr.Interface(fn=encrypt_message, inputs=[
                gr.Textbox(label="Enter message to encrypt"),
                gr.Textbox(label="Enter encryption key")
            ], outputs="text")
        with gr.Tab("Decrypt Message"):
            gr.Interface(fn=decrypt_message, inputs=[
                gr.Textbox(label="Enter encrypted message"),
                gr.Textbox(label="Enter decryption key")
            ], outputs="text")

# Run the app
if __name__ == "__main__":
    demo.launch()
