import random
import hashlib


# Generate a prime number
def generate_prime():
    # Generate a random number
    prime = random.randint(100, 1000)
    while not is_prime(prime):
        prime += 1
    return prime


# Check if a number is prime
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


# Generate a random generator of a prime number
def generate_generator(prime):
    generators = []
    for i in range(2, prime):
        is_generator = True
        for j in range(1, prime - 1):
            if (i ** j) % prime == 1:
                is_generator = False
                break
        if is_generator:
            generators.append(i)
    return random.choice(generators)


# Generate public and private keys
def generate_keys():
    # Generate a prime number
    prime = generate_prime()
    # Generate a random generator of the prime number
    generator = generate_generator(prime)
    # Generate a private key
    private_key = random.randint(2, prime - 2)
    # Calculate the public key
    public_key = pow(generator, private_key, prime)
    return prime, generator, public_key, private_key


# Encrypt a message
def encrypt(message, prime, generator, public_key):
    # Generate a random value
    random_value = random.randint(2, prime - 2)
    # Calculate the shared secret
    shared_secret = pow(public_key, random_value, prime)
    # Hash the message
    hashed_message = hashlib.sha256(message).digest()
    # Convert the hashed message to an integer
    hashed_message_int = int.from_bytes(hashed_message, byteorder='big')
    # Calculate the ciphertext
    ciphertext = (pow(generator, random_value, prime), (hashed_message_int * shared_secret) % prime)
    return ciphertext


# Decrypt a ciphertext
def decrypt(ciphertext, prime, private_key):
    # Extract the ciphertext components
    ciphertext1, ciphertext2 = ciphertext
    # Calculate the shared secret
    shared_secret = pow(ciphertext1, private_key, prime)
    # Calculate the modular inverse of the shared secret
    shared_secret_inverse = pow(shared_secret, -1, prime)
    # Calculate the decrypted message
    decrypted_message = (ciphertext2 * shared_secret_inverse) % prime
    # Return the decrypted message as a byte sequence
    decrypted_message_bytes = decrypted_message.to_bytes((decrypted_message.bit_length() + 7) // 8, byteorder='big')
    return decrypted_message_bytes


# Example
prime, generator, public_key, private_key = generate_keys()
message = b"test string"
ciphertext = encrypt(message, prime, generator, public_key)
decrypted_message = decrypt(ciphertext, prime, private_key)

print("Message:", message)
print("Ciphertext:", ciphertext)
print("Decrypted Message:", decrypted_message)
