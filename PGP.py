from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import hashlib

def generate_key_pair():
    # Generate a new RSA key pair
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)

    # Return the public and private key
    return key

def encrypt_message(message, recipient_public_key):
    # Create a cipher object using the recipient's public key
    cipher = PKCS1_OAEP.new(recipient_public_key)

    # Encrypt the message using the cipher object
    encrypted_message = cipher.encrypt(message.encode())

    # Return the encrypted message
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    # Create a cipher object using the private key
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the message using the cipher object
    decrypted_message = cipher.decrypt(encrypted_message)

    # Return the decrypted message
    return decrypted_message

# Generate a key pair
key_pair = generate_key_pair()

# Get the public and private keys
public_key = key_pair.publickey()
private_key = key_pair

# Define the message
message = "Hello, World!"

# Hash the message
hashed_message = hashlib.sha256(message.encode()).hexdigest()

# Encrypt the message
encrypted_message = encrypt_message(hashed_message, public_key)

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, private_key)

# Print the original message, hashed message, and the encryption/decryption results
print("Original Message:", message)
print("Hashed Message:", hashed_message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message.decode())
