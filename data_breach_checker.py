import re
import string
import random
import requests
import hashlib
import gradio as gr

# Dictionary of common weak passwords
weak_passwords = {"123456", "password", "12345678", "qwerty", "abc123", "111111", "123123"}

def check_password_strength(password):
    """
    Evaluates the strength of a password based on various criteria.
    """
    feedback = []

    # Length Check
    if len(password) < 8:
        feedback.append("Password must be at least 8 characters long.")

    # Check for character diversity
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    if not has_upper:
        feedback.append("Add at least one uppercase letter.")
    if not has_lower:
        feedback.append("Add at least one lowercase letter.")
    if not has_digit:
        feedback.append("Add at least one digit.")
    if not has_special:
        feedback.append("Add at least one special character (e.g., @, #, $).")

    # Pattern Check
    if re.search(r'(.)\1{2,}', password):  # Repeated characters
        feedback.append("Avoid repeating characters (e.g., aaa or 111).")
    if re.search(r'1234|abcd|qwerty', password, re.IGNORECASE):  # Common sequences
        feedback.append("Avoid using common patterns like '1234' or 'abcd'.")

    # Weak Password Check
    if password.lower() in weak_passwords:
        feedback.append("Avoid commonly used passwords like '123456' or 'password'.")

    # Final Evaluation
    if not feedback:
        return "Strong: Your password is secure!"
    else:
        return "Weak/Moderate:\n" + "\n".join(feedback)

def generate_password(length, include_upper, include_lower, include_digits, include_special):
    """
    Generates a strong, random password based on user-defined criteria.
    """
    if length < 8:
        return "Password length must be at least 8 characters."

    char_pool = ""
    if include_upper:
        char_pool += string.ascii_uppercase
    if include_lower:
        char_pool += string.ascii_lowercase
    if include_digits:
        char_pool += string.digits
    if include_special:
        char_pool += string.punctuation

    if not char_pool:
        return "Please select at least one character type."

    return "".join(random.choices(char_pool, k=length))

def check_password_breach(password):
    """
    Checks if the password has been exposed in data breaches using the Have I Been Pwned API.
    """
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        return "Error checking password breach status."

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"Your password has been breached {count} times. Avoid using it!"

    return "Good news! Your password has not been found in any breaches."

# Define the Gradio interface
def gradio_password_strength(password):
    return check_password_strength(password)

def gradio_generate_password(length, upper, lower, digits, special):
    return generate_password(length, upper, lower, digits, special)

def gradio_breach_checker(password):
    return check_password_breach(password)

# Build Gradio UI
with gr.Blocks() as password_checker_app:
    gr.Markdown("# Password Management Tool")

    # Password Strength Checker
    with gr.Tab("Check Password Strength"):
        gr.Markdown("Enter a password to evaluate its strength.")
        password_input = gr.Textbox(label="Enter Password", type="password")
        strength_output = gr.Textbox(label="Password Strength")
        check_button = gr.Button("Check Password Strength")
        check_button.click(gradio_password_strength, inputs=password_input, outputs=strength_output)

    # Password Generator
    with gr.Tab("Generate Password"):
        gr.Markdown("Generate a secure password based on your preferences.")
        length_input = gr.Slider(label="Password Length", minimum=8, maximum=64, step=1, value=12)
        upper_checkbox = gr.Checkbox(label="Include Uppercase Letters", value=True)
        lower_checkbox = gr.Checkbox(label="Include Lowercase Letters", value=True)
        digits_checkbox = gr.Checkbox(label="Include Digits", value=True)
        special_checkbox = gr.Checkbox(label="Include Special Characters", value=True)
        generate_output = gr.Textbox(label="Generated Password")
        generate_button = gr.Button("Generate Password")
        generate_button.click(
            gradio_generate_password,
            inputs=[length_input, upper_checkbox, lower_checkbox, digits_checkbox, special_checkbox],
            outputs=generate_output,
        )

  
