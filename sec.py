import base64
import hashlib
import codecs

# Base85 decoding
def base85_decode(text):
    try:
        decoded_bytes = codecs.decode(text.encode(), 'base85')
        return decoded_bytes.decode()
    except:
        return "Decoding error. Ensure the input is valid Base85 encoded text."

# Vigenère cipher decryption
def vigenere_decrypt(text, key):
    decrypted_text = ""
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            key_char = key[i % key_len]
            shift = ord(key_char.lower()) - ord('a')
            if char.islower():
                decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            else:
                decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
        else:
            decrypted_char = char
        decrypted_text += decrypted_char
    return decrypted_text

# Example rainbow table (MD5 hash -> plaintext)
rainbow_table = {
    '098f6bcd4621d373cade4e832627b4f6': 'hello',
    '5eb63bbbe01eeed093cb22bb8f5acdc3': 'world',
    # Add more entries as needed
}

def md5_decrypt(md5_hash):
    if md5_hash in rainbow_table:
        return rainbow_table[md5_hash]
    else:
        return "Decryption not found in rainbow table."

def display_banner():
    banner = r"""
  ██████ ██░ ██ ▒█████ ▓█████▄ ▄▄▄      ███▄    █    ▓████▓██   ██▓█████
▒██    ▒▓██░ ██▒██▒  ██▒██▀ ██▒████▄    ██ ▀█   █    ▓█   ▀▒██  ██▓█   ▀
░ ▓██▄  ▒██▀▀██▒██░  ██░██   █▒██  ▀█▄ ▓██  ▀█ ██▒   ▒███   ▒██ ██▒███
  ▒   ██░▓█ ░██▒██   ██░▓█▄  █░██▄▄▄▄██▓██▒  ▐▌██▒   ▒▓█  ▄ ░ ▐██▓▒▓█  ▄
▒██████▒░▓█▒░██░ ████▓▒░▒████▓ ▓█   ▓██▒██░   ▓██░   ░▒████▒░ ██▒▓░▒████▒
▒ ▒▓▒ ▒ ░▒ ░░▒░░ ▒░▒░▒░ ▒▒▓  ▒ ▒▒   ▓▒█░ ▒░   ▒ ▒    ░░ ▒░ ░ ██▒▒▒░░ ▒░ ░
░ ░▒  ░ ░▒ ░▒░ ░ ░ ▒ ▒░ ░ ▒  ▒  ▒   ▒▒ ░ ░░   ░ ▒░    ░ ░  ▓██ ░▒░ ░ ░  ░
░  ░  ░  ░  ░░ ░ ░ ░ ▒  ░ ░  ░  ░   ▒     ░   ░ ░       ░  ▒ ▒ ░░    ░
      ░  ░  ░  ░   ░ ░    ░         ░  ░        ░       ░  ░ ░       ░  ░
                        ░                                  ░ ░  v1.3.0
"""
    print("\033[1;31m" + banner + "\033[0m")

def display_menu():
    print("Decryption Methods:")
    print("1. ROT13")
    print("2. Base64")
    print("3. Caesar's Cipher")
    print("4. Hexadecimal")
    print("5. Base16")
    print("6. Base85")
    print("7. Vigenère Cipher")
    print("8. MD5 Decryption")
    method = input("Select a decryption method (1/2/3/4/5/6/7/8): ")
    return method

def decrypt(method, key=None):
    if method == "1":
        # Rot13 decryption
        def rot13_decrypt(text):
            decrypted_text = ""
            for char in text:
                if char.isalpha():
                    if char.islower():
                        decrypted_char = chr(((ord(char) - ord('a') + 13) % 26) + ord('a'))
                    else:
                        decrypted_char = chr(((ord(char) - ord('A') + 13) % 26) + ord('A'))
                else:
                    decrypted_char = char
                decrypted_text += decrypted_char
            return decrypted_text
    elif method == "2":
        import base64
        decoded_bytes = base64.b64decode(text)
        return decoded_bytes.decode('utf-8')
        elif method == "4":
            return bytes.fromhex(text).decode('utf-8')
        elif method == "5":
            return base16_decode(text)
        elif method == "6":
            return base85_decode(text)
        elif method == "7":
            if key is None:
                return "Key required for Vigenère cipher decryption."
            return vigenere_decrypt(text, key)
        elif method == "8":
            md5_hash = input("Enter the MD5 hash to decrypt: ")
            return md5_decrypt(md5_hash)
        else:
            return "Unsupported decryption method."

    def caesar_cipher_decrypt(text, key):
        decrypted_text = ""
        key = int(key)
        for char in text:
            if char.isalpha():
                if char.islower():
                    decrypted_char = chr(((ord(char) - ord('a') - key) % 26) + ord('a'))
                else:
                    decrypted_char = chr(((ord(char) - ord('A') - key) % 26) + ord('A'))
            else:
                decrypted_char = char
            decrypted_text += decrypted_char
        return decrypted_text
            return vigenere_decrypt(text, key)
        elif method == "8":
            md5_hash = input("Enter the MD5 hash to decrypt: ")
            return md5_decrypt(md5_hash)
        else:
            return "Unsupported decryption method."
        if key is None:
            return "Key required for Vigenère cipher decryption."
        return vigenere_decrypt(text, key)
    elif method == "8":
        md5_hash = input("Enter the MD5 hash to decrypt: ")
        return md5_decrypt(md5_hash)
    else:
        return "Unsupported decryption method."
        if key is None:
            return "Key required for Vigenère cipher decryption."
        return vigenere_decrypt(text, key)
    elif method == "8":
        md5_hash = input("Enter the MD5 hash to decrypt: ")
        return md5_decrypt(md5_hash)
    else:
        return "Unsupported decryption method."

if __name__ == "__main__":
    display_banner()
    method = display_menu()
    if method not in ("5", "6", "7"):
        key = None
        if method in ("3", "7"):
            key = input("Enter the decryption key: ")
        text = input("Enter the text to decrypt: ")
    else:
        text = input("Enter the text to process: ")
    
    result = decrypt(method, key)
    print("Decrypted text:")
    print(result)
