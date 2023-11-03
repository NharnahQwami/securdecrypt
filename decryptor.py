import base64

# ROT13 decryption
def rot13_encrypt(text):
    encrypted_text = ""
    for char in text:
        if 'a' <= char <= 'z':
            offset = ord('a')
            encrypted_text += chr((ord(char) - offset + 13) % 26 + offset)
        elif 'A' <= char <= 'Z':
            offset = ord('A')
            encrypted_text += chr((ord(char) - offset + 13) % 26 + offset)
        else:
            encrypted_text += char
    return encrypted_text

def rot13_decrypt(text):
    return rot13_encrypt(text)  # ROT13 is its own decryption

# Base64 decoding
def base64_decode(text):
    try:
        decoded_bytes = base64.b64decode(text.encode())
        return decoded_bytes.decode()
    except:
        return "Decoding error. Ensure the input is valid Base64 encoded text."

# Caesar's cipher decryption
def caesar_cipher_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if 'a' <= char <= 'z':
            offset = ord('a')
            decrypted_text += chr((ord(char) - offset - shift) % 26 + offset)
        elif 'A' <= char <= 'Z':
            offset = ord('A')
            decrypted_text += chr((ord(char) - offset - shift) % 26 + offset)
        else:
            decrypted_text += char
    return decrypted_text

# Hexadecimal decoding
def hex_decode(text):
    try:
        decoded = bytes.fromhex(text).decode('utf-8')
        return decoded
    except:
        return "Decoding error. Ensure the input is valid hexadecimal text."

def display_menu():
    print("Decryption Methods:")
    print("1. ROT13")
    print("2. Base64")
    print("3. Caesar's Cipher")
    print("4. Hexadecimal")
    method = input("Select a decryption method (1/2/3/4): ")
    return method

def decrypt(method, key=None):
    input_text = input("Enter the text or the filename: ")
    if input_text.lower().endswith(".txt"):
        try:
            with open(input_text, "r") as file:
                input_text = file.read()
        except Exception as e:
            return f"Error reading file: {e}"

    if method == "1":
        return rot13_decrypt(input_text)
    elif method == "2":
        return base64_decode(input_text)
    elif method == "3":
        if key is None:
            return "Key required for Caesar's cipher decryption."
        return caesar_cipher_decrypt(input_text, key)
    elif method == "4":
        return hex_decode(input_text)
    else:
        return "Unsupported decryption method."

if __name__ == "__main__":
    method = display_menu()
    key = None
    if method == "3":
        key = int(input("Enter the Caesar's cipher key: "))
    
    result = decrypt(method, key)
    print("Decrypted text:")
    print(result)
