#!/usr/bin/env python3
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt(ciphertext, iv, key):
    """
    Decrypt AES-CBC ciphertext using the given key and IV
    
    Args:
        ciphertext (bytes): The encrypted data
        iv (bytes): Initialization vector
        key (bytes): The AES key
        
    Returns:
        str or False: Decrypted plaintext if successful, False otherwise
    """
    # Create AES cipher in CBC mode
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Decrypt the ciphertext
        plaintext = cipher.decrypt(ciphertext)
        # Remove padding
        plaintext = unpad(plaintext, AES.block_size)
        
        # Check if plaintext is valid UTF-8
        try:
            decoded_text = plaintext.decode('utf-8')
            return decoded_text
        except UnicodeDecodeError:
            return False
    except Exception:
        return False

def main():
    # Load the ciphertext data from the JSON file
    with open('aes-cipher.json', 'r') as f:
        data = json.load(f)
    
    # Print some debug info about the JSON structure
    print("JSON keys:", list(data.keys()))
    for key in data:
        print(f"{key} type:", type(data[key]))
        if isinstance(data[key], str):
            print(f"{key} preview:", data[key][:30] + "..." if len(data[key]) > 30 else data[key])
    
    # Extract ciphertext and IV - handle different possible formats
    try:
        # Try hex format first
        ciphertext = bytes.fromhex(data['ciphertext'])
    except ValueError:
        # If that fails, try base64 format
        import base64
        try:
            ciphertext = base64.b64decode(data['ciphertext'])
        except Exception:
            # As a last resort, check if it's already in bytes or needs direct encoding
            if isinstance(data['ciphertext'], bytes):
                ciphertext = data['ciphertext']
            else:
                ciphertext = data['ciphertext'].encode('utf-8')
    
    # Similarly handle IV format
    try:
        iv = bytes.fromhex(data['iv'])
    except (ValueError, TypeError):
        # If that fails, try base64 format
        try:
            iv = base64.b64decode(data['iv'])
        except Exception:
            # As a last resort, check if it's already in bytes or needs direct encoding
            if isinstance(data['iv'], bytes):
                iv = data['iv']
            else:
                iv = data['iv'].encode('utf-8')
    
    # Load words from dictionary file
    with open('words.txt', 'r') as f:
        words = [line.strip() for line in f]
    
    # Brute force through all possible keys
    for word in words:
        # Test each substring of the word that's 16 characters or less
        for i in range(len(word)):
            for j in range(i + 1, min(i + 17, len(word) + 1)):
                potential_key = word[i:j]
                
                # Skip keys that are too short
                if len(potential_key) < 1:
                    continue
                
                # Pad key to 16, 24, or 32 bytes for AES
                if len(potential_key) <= 16:
                    # Use 128-bit key (pad to 16 bytes)
                    key_bytes = potential_key.encode('utf-8').ljust(16, b'\0')
                    
                    # Try to decrypt
                    result = decrypt(ciphertext, iv, key_bytes)
                    if result:
                        print(f"Key found: '{potential_key}'")
                        print(f"Plaintext: {result}")
                        
                        # Save the key and plaintext to the required files
                        with open('aes-key.txt', 'w') as key_file:
                            key_file.write(potential_key)
                        
                        with open('aes-plain.txt', 'w') as plain_file:
                            plain_file.write(result)
                        
                        return
    
    print("No valid key found")

if __name__ == "__main__":
    main()