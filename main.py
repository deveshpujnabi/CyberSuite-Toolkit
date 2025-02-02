import gradio as gr
from qr_detector import decode_and_audit
from phishing_checker import phishing_email_checker
from data_breach_checker import check_password_breach
from sql_injection import sql_injection_checker

# Define menu options
menu_options = ["Select a Tool", "📷 QR Code Detector", "🛑 Phishing Tool", "🔐 Password & Data Breach Manager", "💉 SQL Injection Checker"]

def display_tool(selected_tool):
    """
    Dynamically loads the selected cybersecurity tool UI.
    """
    if selected_tool == "📷 QR Code Detector":
        with gr.Blocks() as qr_detector_ui:
            gr.Markdown("## 📷 QR Code Phishing Detector")
            qr_input = gr.Image(label="Upload QR Code")
            api_key_input = gr.Textbox(label="urlscan.io API Key (Optional)")
            qr_output = gr.Textbox(label="Analysis Result", interactive=False)
            qr_button = gr.Button("Analyze QR Code")
            qr_button.click(decode_and_audit, inputs=[qr_input, api_key_input], outputs=qr_output)
        return qr_detector_ui

    elif selected_tool == "🛑 Phishing Tool":
        with gr.Blocks() as phishing_ui:
            gr.Markdown("# 🛑 Phishing Detection Tool")

            with gr.Tabs():
                with gr.Tab("🔗 URL Phishing Checker"):
                    url_input = gr.Textbox(label="Enter URL")
                    api_key_input = gr.Textbox(label="urlscan.io API Key (Optional)")
                    url_output = gr.Textbox(label="Analysis Result", interactive=False)
                    url_button = gr.Button("Check URL")
                    url_button.click(phishing_url_checker, inputs=[url_input, api_key_input], outputs=url_output)

                with gr.Tab("📧 Email Phishing Checker"):
                    email_input = gr.Textbox(label="Enter Email")
                    email_output = gr.Textbox(label="Analysis Result", interactive=False)
                    email_button = gr.Button("Check Email")
                    email_button.click(phishing_email_checker, inputs=[email_input], outputs=email_output)

                with gr.Tab("📩 SMS Phishing Checker"):
                    sms_input = gr.Textbox(label="Enter SMS Message")
                    sms_output = gr.Textbox(label="Analysis Result", interactive=False)
                    sms_button = gr.Button("Check SMS")
                    sms_button.click(phishing_sms_checker, inputs=[sms_input], outputs=sms_output)

        return phishing_ui

    elif selected_tool == "🔐 Password & Data Breach Manager":
        with gr.Blocks() as breach_checker_ui:
            gr.Markdown("## 🔐 Check if your password has been exposed in data breaches.")
            breach_input = gr.Textbox(label="Enter Password", type="password")
            breach_output = gr.Textbox(label="Breach Status")
            breach_button = gr.Button("Check Breach Status")
            breach_button.click(gradio_breach_checker, inputs=breach_input, outputs=breach_output)
        return breach_checker_ui

    elif selected_tool == "💉 SQL Injection Checker":
        with gr.Blocks() as sql_ui:
            gr.Markdown("## 💉 SQL Injection Scanner")
            sql_input = gr.Textbox(label="Enter Website URL")
            sql_output = gr.Textbox(label="Analysis Result", interactive=False)
            sql_button = gr.Button("Scan for SQL Injection")
            sql_button.click(sql_injection_checker, inputs=[sql_input], outputs=sql_output)
        return sql_ui

    else:
        return gr.Markdown("## 🔍 Select a cybersecurity tool from the menu.")

# Main Gradio App
with gr.Blocks() as cyber_suite:
    gr.Markdown("# 🛡️ CyberSuite Toolkit - Choose a Cybersecurity Tool")
    menu = gr.Dropdown(menu_options, label="Select a Tool", interactive=True)
    output_area = gr.State()
    menu.change(display_tool, inputs=menu, outputs=output_area)

cyber_suite.launch(share=True)
