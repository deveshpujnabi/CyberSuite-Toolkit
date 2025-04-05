# app.py
import gradio as gr
from sql_injection.sql_injection import run_sqlmap
from qr_detector.qr_detector import qr_code_audit_app
from data_breach_checker.password_checker import (
    gradio_password_strength,
    gradio_generate_password,
    gradio_breach_checker,
)
from phishing_checker import scan_phishing
from vulnerability_scanner.vulnerability_scanner import scan_website
from encryption_tool.encryption_tool import generate_key, encrypt_message, decrypt_message

# Theme and CSS
css = """
.social-icons { display: flex; gap: 12px; margin-top: 8px; justify-content: center; }
.social-icons img { height: 30px; transition: 0.3s ease; opacity: 0.7; }
.social-icons img:hover { opacity: 1; transform: scale(1.1); }
.card { padding: 20px; border-radius: 12px; background-color: #f0f8ff; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); margin-bottom: 20px; }
.boxed-output { white-space: pre-wrap; font-family: monospace; background: #e6f7ff; padding: 15px; border-radius: 8px; border: 1px solid #add8e6; color: #2f4f4f; }
.submit-btn { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
.submit-btn:hover { background-color: #3e8e41; }
.tool-title { color: #007bff; font-size: 24px; margin-bottom: 15px; }
.tool-desc { color: #555; margin-bottom: 20px; }
.sidebar { width: 250px; background-color: #f0f0f0; padding: 20px; height: 100vh; position: fixed; left: 0; top: 0; overflow-y: auto; border-right: 1px solid #ccc; }
.main-content { margin-left: 270px; padding: 20px; }
.output-section { margin-top: 20px; }
.output-title { font-weight: bold; color: #007bff; }
"""

def create_app():
    with gr.Blocks(title="CyberSuite Toolkit", css=css) as demo:
        with gr.Row():
            with gr.Column(scale=1, elem_classes="sidebar"):
                gr.Markdown("# 🛡️ CyberSuite Toolkit")
                gr.Markdown("Select Tool:")
                tool_selector = gr.Radio(
                    choices=[
                        "SQL Injection Test",
                        "Phishing Detection Tool",
                        "QR Detector",
                        "Password & Data Breach Management",
                        "Vulnerability Scanner",
                        "Encryption Tool"
                    ],
                    label="Select Tool",
                    value="SQL Injection Test"
                )
                gr.HTML("""
                <div class='social-icons'>
                    <a href='https://github.com/your-username/cybersuite-toolkit' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/25/25231.png' alt='GitHub'>
                    </a>
                    <a href='https://huggingface.co/spaces/your-username/cybersuite-toolkit' target='_blank'>
                        <img src='https://huggingface.co/front/assets/huggingface_logo-noborder.svg' alt='HF'>
                    </a>
                </div>
                """)

            with gr.Column(scale=3, elem_classes="main-content"):
                tab_sql = gr.Column(visible=True)
                with tab_sql:
                    gr.Markdown("<h2 class='tool-title'>🛡️ SQL Injection Test</h2>")
                    gr.Markdown("<p class='tool-desc'>Enter URLs (one per line) to test for SQL Injection vulnerabilities.</p>")
                    url_input = gr.Textbox(lines=5, placeholder="Enter URLs (e.g., https://example.com\nhttps://testsite.com)", label="Target URLs")
                    with gr.Row():
                        submit_btn = gr.Button("Run SQL Injection Test", elem_classes="submit-btn")
                    output = gr.HTML(label="Results")

                    def handle_sql_submit(urls):
                        try:
                            result = run_sqlmap(urls)
                            if isinstance(result, tuple):
                                result_str = str(result[0])
                            else:
                                result_str = str(result)

                            if result_str:
                                lines = result_str.split('\n')
                                formatted_output = "<div class='output-section'><h3 class='output-title'>SQL Injection Test Results:</h3>"

                                payload_line = None
                                purpose_line = None
                                response_preview = None

                                for line in lines:
                                    if "Payload:" in line:
                                        payload_line = line.split("Payload:")[1].strip()
                                    elif "Purpose:" in line:
                                        purpose_line = line.split("Purpose:")[1].strip()
                                    elif "Response Preview:" in line:
                                        response_preview = "\n".join(lines[lines.index(line) + 1:])

                                if payload_line:
                                    formatted_output += f"<p><strong>Payload Tested:</strong> {payload_line}</p>"
                                if purpose_line:
                                    formatted_output += f"<p><strong>Purpose:</strong> {purpose_line}</p>"

                                if "vulnerability detected" in result_str.lower():
                                    formatted_output += "<p><strong>Result:</strong> Not Vulnerable</p>"
                                else:
                                    formatted_output += "<p><strong>Result:</strong> Vulnerable</p>"

                                if response_preview:
                                    response_preview = "\n".join(line.strip() for line in response_preview.split('\n') if line.strip())
                                    truncated_preview = response_preview[:500] + ("..." if len(response_preview) > 500 else "")
                                    formatted_output += f"<p><strong>Response Preview:</strong><pre>{truncated_preview}</pre></p>"

                                formatted_output += "</div>"
                                return formatted_output
                            else:
                                return "<div class='output-section'><h3 class='output-title'>SQL Injection Test Results:</h3><p>No vulnerabilities found or an issue occurred during the scan.</p></div>"
                        except Exception as e:
                            return f"<div class='output-section'><h3 class='output-title'>SQL Injection Test Error:</h3><p>An error occurred during the SQL injection test: {str(e)}</p></div>"

                    submit_btn.click(fn=handle_sql_submit, inputs=[url_input], outputs=[output])

                tab_phishing = gr.Column(visible=False)
                with tab_phishing:
                    gr.Markdown("<h2 class='tool-title'>🕵️ Phishing Detection Tool</h2>")
                    gr.Markdown("<p class='tool-desc'>Enter a URL to check for phishing risks.</p>")
                    phishing_input = gr.Textbox(label="Enter a URL", placeholder="https://example.com")
                    phishing_submit = gr.Button("Scan URL", elem_classes="submit-btn")
                    phishing_output = gr.HTML(label="Scan Result")

                    def handle_phishing_scan(url):
                        result = scan_phishing(url)
                        formatted_result = "<div class='output-section'><h3 class='output-title'>Phishing Scan Result:</h3><pre>" + result.replace("\n", "<br>") + "</pre></div>"
                        return formatted_result
                    phishing_submit.click(fn=handle_phishing_scan, inputs=[phishing_input], outputs=[phishing_output])

                tab_qr = gr.Column(visible=False)
                with tab_qr:
                    gr.Markdown("<h2 class='tool-title'>📷 QR Detector</h2>")
                    gr.Markdown("<p class='tool-desc'>Scan and audit QR codes for potential threats.</p>")
                    qr_image = gr.Image(label="Upload or Capture QR Code")
                    qr_submit = gr.Button("Analyze QR Code", elem_classes="submit-btn")
                    qr_output = gr.HTML(label="QR Code Analysis")

                    def handle_qr_scan(image):
                        results = qr_code_audit_app(image)
                        formatted_result = f"""
                        <div class='output-section'>
                            <h3 class='output-title'>QR Code Analysis:</h3>
                            <p><strong>Analysis Result:</strong> {results[0]}</p>
                            <p><strong>Decoded QR Data:</strong> {results[1]}</p>
                            <p><strong>Link Category:</strong> {results[2]}</p>
                            <p><strong>URL Type:</strong> {results[3]}</p>
                        </div>
                        """
                        return formatted_result
                    qr_submit.click(fn=handle_qr_scan, inputs=[qr_image], outputs=[qr_output])

                tab_password = gr.Column(visible=False)
                with tab_password:
                    gr.Markdown("<h2 class='tool-title'>🔑 Password & Data Breach Management</h2>")
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

                tab_vuln = gr.Column(visible=False)
                with tab_vuln:
                    gr.Markdown("<h2 class='tool-title'>🔍 Vulnerability Scanner</h2>")
                    gr.Markdown("<p class='tool-desc'>Scan a website for common vulnerabilities.</p>")
                    vuln_input = gr.Textbox(label="Enter Website URL", placeholder="http://example.com")
                    vuln_submit = gr.Button("Scan Website", elem_classes="submit-btn")
                    vuln_output = gr.HTML(label="Scan Report")

                    def handle_vuln_scan(url):
                        result = scan_website(url)
                        formatted_result = "<div class='output-section'><h3 class='output-title'>Vulnerability Scan Report:</h3><pre>" + result.replace("\n", "<br>") + "</pre></div>"
                        return formatted_result
                    vuln_submit.click(fn=handle_vuln_scan, inputs=[vuln_input], outputs=[vuln_output])

                tab_encrypt = gr.Column(visible=False)
                with tab_encrypt:
                    gr.Markdown("<h2 class='tool-title'>🔒 Encryption Tool</h2>")
                    with gr.Tab("Generate Key"):
                        key_gen_btn = gr.Button("Generate New Key", elem_classes="submit-btn")
                        key_output = gr.Textbox(label="Generated Key", elem_classes="boxed-output")
                        def handle_key_generation():
                            result = generate_key()
                            return result
                        key_gen_btn.click(fn=handle_key_generation, inputs=None, outputs=[key_output])

                    with gr.Tab("Encrypt Message"):
                        enc_msg = gr.Textbox(label="Enter message to encrypt")
                        enc_key = gr.Textbox(label="Enter encryption key")
                        enc_btn = gr.Button("Encrypt", elem_classes="submit-btn")
                        enc_output = gr.Textbox(label="Encrypted Message", elem_classes="boxed-output")
                        def handle_encryption(message, key):
                            result = encrypt_message(message, key)
                            return result
                        enc_btn.click(fn=handle_encryption, inputs=[enc_msg, enc_key], outputs=[enc_output])

                    with gr.Tab("Decrypt Message"):
                        dec_msg = gr.Textbox(label="Enter encrypted message")
                        dec_key = gr.Textbox(label="Enter decryption key")
                        dec_btn = gr.Button("Decrypt", elem_classes="submit-btn")
                        dec_output = gr.Textbox(label="Decrypted Message", elem_classes="boxed-output")
                        def handle_decryption(message, key):
                            result = decrypt_message(message, key)
                            return result
                        dec_btn.click(fn=handle_decryption, inputs=[dec_msg, dec_key], outputs=[dec_output])

        def switch_tabs(tool):
            return [
                gr.update(visible=tool == "SQL Injection Test"),
                gr.update(visible=tool == "Phishing Detection Tool"),
                gr.update(visible=tool == "QR Detector"),
                gr.update(visible=tool == "Password & Data Breach Management"),
                gr.update(visible=tool == "Vulnerability Scanner"),
                gr.update(visible=tool == "Encryption Tool")
            ]
        tool_selector.change(switch_tabs, inputs=tool_selector, outputs=[tab_sql, tab_phishing, tab_qr, tab_password, tab_vuln, tab_encrypt])

        return demo

if __name__ == "__main__":
    demo = create_app()
    demo.queue()
    demo.launch(share=False, debug=False, show_error=True, max_threads=16, favicon_path=None, quiet=True)
