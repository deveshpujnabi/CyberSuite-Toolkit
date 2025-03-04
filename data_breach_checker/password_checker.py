# data_breach_checker/password_checker.py
import requests
import hashlib
import string
import random


def gradio_breach_checker(password):
    """
    Checks if a password has been exposed in data breaches using the Have I Been Pwned API.
    
    Args:
        password (str): The password to check.
    
    Returns:
        str: Breach status message.
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


def gradio_generate_password(length=12, include_upper=True, include_lower=True, include_digits=True, include_special=True):
    """
    Generates a random, secure password.
    
    Args:
        length (int): Length of the password.
        include_upper (bool): Include uppercase letters.
        include_lower (bool): Include lowercase letters.
        include_digits (bool): Include digits.
        include_special (bool): Include special characters.
    
    Returns:
        str: The generated password.
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


def gradio_password_strength(password):
    """
    Evaluates the strength of a password.
    
    Args:
        password (str): The password to evaluate.
    
    Returns:
        str: Strength feedback message.
    """
    feedback = []
    if len(password) < 8:
        feedback.append("Password must be at least 8 characters long.")

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

    if not feedback:
        return "Strong: Your password is secure!"
    else:
        return "Weak/Moderate:\n" + "\n".join(feedback)
