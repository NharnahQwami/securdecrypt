import base64

# ROT13 decryption
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

def decrypt(text, method, key=None):
    if method == "rot13":
        return rot13_decrypt(text)
    elif method == "base64":
        return base64_decode(text)
    elif method == "caesar":
        if key is None:
            return "Key required for Caesar's cipher decryption."
        return caesar_cipher_decrypt(text, key)
    elif method == "hex":
        return hex_decode(text)
    else:
        return "Unsupported decryption method."

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python decryptor.py <method> <key (for Caesar's cipher)> <text or filename>")
        sys.exit(1)

    method = sys.argv[1]
    key = int(sys.argv[2]) if method == "caesar" else None
    input_text = sys.argv[3]

    if input_text.lower().endswith(".txt"):
        try:
            with open(input_text, "r") as file:
                input_text = file.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)

    result = decrypt(input_text, method, key)
    print("Decrypted text:")
    print(result)
