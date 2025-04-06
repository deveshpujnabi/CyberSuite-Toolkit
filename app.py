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
body { font-family: 'Arial', sans-serif; background-color: #e6f7ff; color: #333; }
.tool-title { color: #2979ff; font-size: 32px; text-align: center; margin-bottom: 30px; font-weight: 600; }
.tool-desc { color: #666; text-align: center; margin-bottom: 35px; font-size: 18px; }
.card { padding: 40px; border-radius: 15px; background-color: rgba(255, 255, 255, 0.8); backdrop-filter: blur(10px); box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1); margin-bottom: 40px; }
.boxed-output { white-space: pre-wrap; font-family: monospace; background: #f0f8ff; padding: 25px; border-radius: 10px; border: 1px solid #b3e5fc; color: #2f4f4f; font-size: 16px; }
.submit-btn { background-color: #42a5f5; color: white; padding: 15px 30px; border: none; border-radius: 8px; cursor: pointer; display: block; margin: 40px auto; font-size: 18px; font-weight: 500; transition: background-color 0.3s ease, transform 0.2s ease; }
.submit-btn:hover { background-color: #1e88e5; transform: translateY(-3px); box-shadow: 0 5px 10px rgba(0, 0, 0, 0.15); }
.output-section { margin-top: 30px; }
.output-title { font-weight: 600; color: #2979ff; font-size: 22px; margin-bottom: 15px; }
.tool-select { margin: 40px auto; width: 400px; display: block; padding: 15px; border: 2px solid #90caf9; border-radius: 10px; font-size: 18px; color: #333; transition: border-color 0.3s ease, box-shadow 0.3s ease; }
.tool-select:focus { outline: none; border-color: #1e88e5; box-shadow: 0 0 10px rgba(30, 136, 229, 0.5); }
.tab-container { margin-top: 30px; }
.output-section table { width: 100%; border-collapse: collapse; margin-top: 20px; }
.output-section th, .output-section td { border: 1px solid #ddd; padding: 8px; text-align: left; }
.output-section th { background-color: #f2f2f2; }
.output-section pre { white-space: pre-wrap; font-family: monospace; background: #f9f9f9; padding: 10px; border-radius: 5px; }
"""

def create_app():
    with gr.Blocks(title="CyberSuite Toolkit", css=css) as demo:
        gr.Markdown("<h1 class='tool-title'>🛡️ CyberSuite Toolkit</h1>")

        tool_selector = gr.Dropdown(
            choices=[
                "SQL Injection Test",
                "Phishing Detection Tool",
                "QR Detector",
                "Password & Data Breach Management",
                "Vulnerability Scanner",
                "Encryption Tool"
            ],
            label="Select Tool",
            elem_classes="tool-select"
        )

        with gr.Column(elem_classes="tab-container"):
            tab_sql = gr.Column(visible=False)
            with tab_sql:
                gr.Markdown("<h2 class='tool-title'>🛡️ SQL Injection Test</h2>")
                gr.Markdown("<p class='tool-desc'>Enter URLs (one per line) to test for SQL Injection vulnerabilities.</p>")
                url_input = gr.Textbox(lines=5, placeholder="Enter URLs (e.g., https://example.com\nhttps://testsite.com)", label="Target URLs")
                with gr.Row():
                    submit_btn = gr.Button("Run SQL Injection Test", elem_classes="submit-btn")
                output = gr.HTML(label="Results")

                def handle_sql_submit(urls):
                    try:
                        print(f"URLs received: {urls}")  # Added print
                        result = run_sqlmap(urls)
                        print(f"run_sqlmap result: {result}")  # Added print
                        if isinstance(result, tuple):
                            result_str = str(result[0])
                        else:
                            result_str = str(result)
                        print(f"result_str: {result_str}")  # Added print

                        if result_str:
                            lines = result_str.split('\n')
                            results = []
                            unique_payloads = set()

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

                                if payload_line and payload_line not in unique_payloads:
                                    unique_payloads.add(payload_line)
                                    result_dict = {
                                        "payload": payload_line,
                                        "purpose": purpose_line,
                                        "vulnerable": "vulnerability detected" not in result_str.lower(),
                                        "response": response_preview
                                    }
                                    results.append(result_dict)
                                    payload_line = None
                                    purpose_line = None
                                    response_preview = None

                            formatted_output = "<div class='output-section'><h3 class='output-title'>SQL Injection Test Results:</h3>"
                            formatted_output += "<table style='width:100%; border-collapse: collapse;'>"
                            formatted_output += "<tr><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Payload Tested</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Purpose</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Result</th><th style='border: 1px solid #ddd; padding: 8px; text-align: left;'>Response Preview</th></tr>"

                            for result in results:
                                formatted_output += f"<tr><td style='border: 1px solid #ddd; padding: 8px;'>{result['payload']}</td>"
                                formatted_output += f"<td style='border: 1px solid #ddd; padding: 8px;'>{result['purpose']}</td>"
                                if result['vulnerable']:
                                    formatted_output += "<td style='border: 1px solid #ddd; padding: 8px; color: red;'>Vulnerable</td>"
                                else:
                                    formatted_output += "<td style='border: 1px solid #ddd; padding: 8px; color: green;'>Not Vulnerable</td>"
                                if result['response']:
                                    truncated_preview = result['response'][:500] + ("..." if len(result['response']) > 500 else "")
                                    formatted_output += f"<td style='border: 1px solid #ddd; padding: 8px;'><pre>{truncated_preview}</pre></td></tr>"
                                else:
                                    formatted_output += "<td style='border: 1px solid #ddd; padding: 8px;'></td></tr>"

                            formatted_output += "</table></div>"
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
                    lines = result.split('\n')
                    formatted_result = "<div class='output-section'><h3 class='output-title'>Vulnerability Scan Report:</h3>"
                    formatted_result += "<table style='width:100%; border-collapse: collapse;'>"

                    # Parse and structure the results
                    for line in lines:
                        if "SSL Status:" in line:
                            ssl_status = line.split("SSL Status:")[1].strip()
                            formatted_result += f"<tr><td><strong>SSL Status:</strong></td><td>{ssl_status}</td></tr>"
                        elif "XSS:" in line:
                            xss_status = line.split("XSS:")[1].strip()
                            formatted_result += f"<tr><td><strong>XSS:</strong></td><td>{xss_status}</td></tr>"
                        elif "Security Headers:" in line:
                            headers_status = line.split("Security Headers:")[1].strip()
                            formatted_result += f"<tr><td><strong>Security Headers:</strong></td><td>{headers_status}</td></tr>"
                        elif "Vulnerability Report Summary:" in line:
                            formatted_result += f"<tr><td colspan='2'><strong>{line.strip()}</strong></td></tr>"
                        elif "Detailed Vulnerability Report" in line:
                            formatted_result += f"<tr><td colspan='2'><strong>{line.strip()}</strong></td></tr>"
                        else:
                            if line.strip():  # Skip empty lines
                                formatted_result += f"<tr><td colspan='2'>{line.strip()}</td></tr>"

                    formatted_result += "</table></div>"
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
