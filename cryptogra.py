from cryptography.fernet import Fernet
import hashlib
import secrets
import pyotp
import logging

# Function to generate and save a key for Fernet encryption
def generate_key():
    key = Fernet.generate_key()  # Generate a new key
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)  # Save the key to a file

# Function to load the encryption key from a file
def load_key():
    return open('secret.key', 'rb').read()

# Generate the encryption key and load it
generate_key()
key = load_key()
cipher_suite = Fernet(key)  # Create a Fernet cipher suite with the loaded key

# Function to encrypt data using Fernet
def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())  # Encrypt the data and return it

# Function to decrypt data using Fernet
def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()  # Decrypt the data and return it

# Function to hash data using SHA-256
def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()  # Hash the data and return the hash

# Function to generate a secure random number
def generate_secure_random():
    secure_random = secrets.SystemRandom()  # Create a secure random number generator
    return secure_random.randint(1, 100)  # Generate a random number between 1 and 100

# Function to generate a TOTP (Time-based One-Time Password) secret and provisioning URI
def generate_totp_secret():
    secret = pyotp.random_base32()  # Generate a random base32 secret
    totp = pyotp.TOTP(secret)  # Create a TOTP object with the secret
    print(totp.provisioning_uri("user@example.com", issuer_name="Secure Voting"))  # Print the provisioning URI
    return secret  # Return the secret

# Function to validate a TOTP using the secret and user-provided OTP
def validate_totp(secret, otp):
    totp = pyotp.TOTP(secret)  # Create a TOTP object with the secret
    return totp.verify(otp)  # Verify the OTP and return the result

# Setup logging for audit trail
logging.basicConfig(filename='audit.log', level=logging.INFO)

# Function to log events
def log_event(event):
    logging.info(event)  # Log the event with INFO level

# Example usage of the functions
if __name__ == "__main__":
    # Encrypting and decrypting data
    vote_data = "User vote: Candidate A"
    encrypted_vote = encrypt_data(vote_data)
    print(f"Encrypted vote: {encrypted_vote}")
    
    decrypted_vote = decrypt_data(encrypted_vote)
    print(f"Decrypted vote: {decrypted_vote}")

    # Hashing data
    hashed_data = hash_data(vote_data)
    print(f"Hashed data: {hashed_data}")

    # Secure random number generation
    random_number = generate_secure_random()
    print(f"Secure random number: {random_number}")

    # Two-factor authentication
    secret = generate_totp_secret()
    otp = input("Enter the OTP: ")
    if validate_totp(secret, otp):
        print("Authenticated!")
    else:
        print("Invalid OTP!")

    # Logging an event
    log_event("User cast a vote")
