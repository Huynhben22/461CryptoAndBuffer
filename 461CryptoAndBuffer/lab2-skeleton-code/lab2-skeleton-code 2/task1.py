#!/usr/bin/env python3
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def decrypt(ciphertext, iv, key):
    """
    Decrypt AES-CBC ciphertext using the given key and IV
    
    Args:
        ciphertext (bytes): The encrypted data
        iv (bytes): Initialization vector
        key (bytes): The AES key (as string)
        
    Returns:
        str or False: Decrypted plaintext if successful, False otherwise
    """
    # Convert key to bytes and pad according to check_key() in aes.py
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > 16:
        return False
    if len(key_bytes) < 16:
        key_bytes = pad(key_bytes, AES.block_size)
    
    try:
        # Create AES cipher in CBC mode
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
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
    except Exception as e:
        return False

def main():
    # Load the ciphertext data from the JSON file
    with open('aes-cipher.json', 'r') as f:
        data = json.load(f)
    
    # Extract iv and ciphertext - they are base64 encoded in the JSON
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext'])
    
    # Load words from dictionary file
    with open('words.txt', 'r') as f:
        words = [line.strip() for line in f]
    
    # Count for progress tracking
    count = 0
    total_words = len(words)
    
    print(f"Starting brute force with {total_words} words...")
    
    # Brute force through all possible keys
    for word in words:
        # For each word, try all possible substrings
        for i in range(len(word)):
            for j in range(i + 1, min(i + 17, len(word) + 1)):
                potential_key = word[i:j]
                
                # Skip keys that are too long
                if len(potential_key) > 16:
                    continue
                
                # Try to decrypt
                result = decrypt(ciphertext, iv, potential_key)
                if result:
                    print(f"Key found: '{potential_key}'")
                    print(f"Plaintext: {result}")
                    
                    # Save the key and plaintext to the required files
                    with open('aes-key.txt', 'w') as key_file:
                        key_file.write(potential_key)
                    
                    with open('aes-plain.txt', 'w') as plain_file:
                        plain_file.write(result)
                    
                    return
        
        # Print progress every 1000 words
        count += 1
        if count % 1000 == 0:
            print(f"Processed {count}/{total_words} words ({count/total_words*100:.2f}%)...")
    
    print("No valid key found")

if __name__ == "__main__":
    main()