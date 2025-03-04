# encryption_tool/encryption_tool.py
from cryptography.fernet import Fernet


def generate_key():
    """
    Generates a secret key for encryption and decryption.
    
    Returns:
        str: The generated key.
    """
    key = Fernet.generate_key()
    return key.decode()


def encrypt_message(message, key):
    """
    Encrypts a message using the provided key.
    
    Args:
        message (str): The message to encrypt.
        key (str): The encryption key.
    
    Returns:
        str: The encrypted message.
    """
    try:
        fernet = Fernet(key.encode())
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message.decode()
    except Exception as e:
        return f"Encryption failed: {str(e)}"


def decrypt_message(encrypted_message, key):
    """
    Decrypts an encrypted message using the provided key.
    
    Args:
        encrypted_message (str): The encrypted message to decrypt.
        key (str): The encryption key.
    
    Returns:
        str: The decrypted message or an error message.
    """
    try:
        fernet = Fernet(key.encode())
        decrypted_message = fernet.decrypt(encrypted_message.encode()).decode()
        return decrypted_message
    except Exception as e:
        return f"Decryption failed: {str(e)}"
