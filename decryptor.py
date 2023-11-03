import random, time, base64, hashlib, codecs, binascii

banner1 = ("""

\033[1;31m
                   
  _____                             _        
 |  __ \                           | |            
 | |  | | ___  ___ _ __ _   _ _ __ | |_ ___  _ __ 
 | |  | |/ _ \/ __| '__| | | | '_ \| __/ _ \| '__|
 | |__| |  __/ (__| |  | |_| | |_) | || (_) | |   
 |_____/ \___|\___|_|   \__, | .__/ \__\___/|_|   
                         __/ | |                  
                        |___/|_|                  
\033[1;m
                                \033[1;31mSecurDecrypt v1.0\033[0m

    ✓ The author is not responsible for any damage, misuse of the information.
    ✓ SecurDecrypt shall only be used to expand knowledge and not for
      causing malicious or damaging attacks.
    ✓ Just remember, Performing any hacks without written permission is illegal ..!

            \033[1;31mHi there, Shall we play a game..?\033[0m 😃
        """)

banner2 = ("""

\033[1;31m
   ▄▄▄▄▄   ▄███▄   ▄█▄      ▄   █▄▄▄▄ ██▄   ▄███▄   ▄█▄    █▄▄▄▄ ▀▄    ▄ █ ▄▄     ▄▄▄▄▀ 
  █     ▀▄ █▀   ▀  █▀ ▀▄     █  █  ▄▀ █  █  █▀   ▀  █▀ ▀▄  █  ▄▀   █  █  █   █ ▀▀▀ █    
▄  ▀▀▀▀▄   ██▄▄    █   ▀  █   █ █▀▀▌  █   █ ██▄▄    █   ▀  █▀▀▌     ▀█   █▀▀▀      █    
 ▀▄▄▄▄▀    █▄   ▄▀ █▄  ▄▀ █   █ █  █  █  █  █▄   ▄▀ █▄  ▄▀ █  █     █    █        █     
           ▀███▀   ▀███▀  █▄ ▄█   █   ███▀  ▀███▀   ▀███▀    █    ▄▀      █      ▀      
                           ▀▀▀   ▀                          ▀              ▀            
\033[1;m
                                                    \033[1;31m v1.0\033[0m

    ✓ The author is not responsible for any damage, misuse of the information.
    ✓ SecurDecrypt shall only be used to expand knowledge and not for
      causing malicious or damaging attacks.
    ✓ Just remember, Performing any hacks without written permission is illegal ..!

            \033[1;31mHi there, Shall we play a game..?\033[0m 😃
        """)

choi = (banner1, banner2)
print (random.choice(choi))
time.sleep(0.3)

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

# MD5 decryption
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
    
# Base16 decoding
def base16_decode(text):
    try:
        decoded_bytes = binascii.unhexlify(text)
        return decoded_bytes.decode()
    except binascii.Error:
        return "Decoding error. Ensure the input is valid Base16 encoded text."
        
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
    method = input("Select a decryption method: ")
    return method

def decrypt(method, input_text, key=None):
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

if __name__ == "__main__":
    method = display_menu()
    if method not in ("5", "6", "7"):
        key = None
        if method in ("3", "7"):
            key = input("Enter the decryption key: ")
        text = input("Enter the text to decrypt: ")
    else:
        text = input("Enter the text to process: ")

    
    result = decrypt(method, key)
    print("Decrypted text: ")
    print(result)
