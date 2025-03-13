# app.py
import gradio as gr
from sql_injection.sql_injection import run_sqlmap
from qr_detector.qr_detector import qr_code_audit_app
from data_breach_checker.password_checker import gradio_password_strength, gradio_generate_password, gradio_breach_checker
from phishing_checker import scan_phishing
from vulnerability_scanner.vulnerability_scanner import scan_website
from encryption_tool.encryption_tool import generate_key, encrypt_message, decrypt_message

# Create the Gradio interface
with gr.Blocks() as demo:
    gr.Markdown("# 🛡️ CyberSuite Toolkit Dashboard")

    with gr.Tab("SQL Injection Test"):
        with gr.Row():
            with gr.Column(scale=7):
                gr.Markdown("### Enter URL to test for SQL Injection")
                url_input = gr.Textbox(placeholder="Enter target URL")
                
                with gr.Row():
                    submit_btn = gr.Button("Submit")
                    clear_btn = gr.Button("Clear")
                
                gr.Markdown("### Test Results")
                test_output = gr.Textbox(label="Results", lines=10)
            
            with gr.Column(scale=3):
                gr.Markdown("### Report")
                download_btn = gr.File(label="Download Full Report")
    
    submit_btn.click(run_sqlmap, inputs=url_input, outputs=[test_output, download_btn])
    clear_btn.click(lambda: ("", None), outputs=[test_output, download_btn])

    with gr.Tab("Phishing Detection Tool"):
        gr.Interface(
            fn=scan_phishing,
            inputs=gr.Textbox(label="Enter a URL"),
            outputs=gr.Textbox(label="Scan Result"),
            title="Phishing Detection Tool",
            description="Enter a URL to check if it contains suspicious elements like phishing keywords, unusual domain patterns, or is flagged by Google Safe Browsing."
        )

    with gr.Tab("QR Detector"):
        gr.Interface(
            fn=qr_code_audit_app,
            inputs=[
        gr.Image(label="Upload or Capture QR Code"),

    ],
    outputs=[
        gr.Textbox(label="Analysis Result"),
        gr.Textbox(label="Decoded QR Data"),
        gr.Textbox(label="Link Category"),
        gr.Textbox(label="URL Type (Safe, Potential Issue, Malicious)"),
        gr.Textbox(label="urlscan.io Report Link")
    ],
    title="QR Code Audit Detector",
    description="Scan, audit, and analyze QR codes for potential threats and link type categorization. Uses urlscan.io for URL analysis."
)

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
            fn=scan_website,
            inputs=gr.Textbox(label="Enter Website URL", placeholder="http://example.com", lines=1),
            outputs=gr.Textbox(label="Scan Report", interactive=False, lines=20),
            live=False,
            title="Website Vulnerability Scanner",
            description="Enter the website URL to scan for common vulnerabilities such as SSL, SQL Injection, XSS, and Security Headers."
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
