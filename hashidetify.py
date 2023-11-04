import hashlib

def identify_hash(hash_string):
    hash_length = len(hash_string)

    if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA-1"
    elif hash_length == 64:
        return "SHA-256"
    elif hash_length == 128:
        return "SHA-512"
    elif hash_length == 56 and hash_string.startswith("$pbkdf2-sha256$"):
        return "PBKDF2-SHA256"
    else:
        return "Unknown"

if __name__ == "__main__":
    input_hash = input("Enter a hash: ")
    hash_type = identify_hash(input_hash)
    print(f"The identified hash type is: {hash_type}")
