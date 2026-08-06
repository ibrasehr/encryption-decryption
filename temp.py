# -*- coding: utf-8 -*-
#Caesar Cypher
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_aes(plaintext: str, key: bytes):
    # AES requires a 16-byte initialization vector (IV)
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad plaintext to match AES block size (16 bytes)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return cipher.iv, ciphertext

def decrypt_aes(iv: bytes, ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    # Remove padding to get original string
    plaintext = unpad(decrypted_padded, AES.block_size).decode('utf-8')
    return plaintext

# --- Usage Example ---
if __name__ == "__main__":
    # Generate a random 256-bit (32-byte) key
    key = get_random_bytes(32)
    message = "ATTACK AT DAWN"

    # Encrypt
    iv, ciphertext = encrypt_aes(message, key)
    print(f"Original Message : {message}")
    print(f"Ciphertext (hex) : {ciphertext.hex()}")

    # Decrypt
    decrypted_message = decrypt_aes(iv, ciphertext, key)
    print(f"Decrypted Message: {decrypted_message}")
