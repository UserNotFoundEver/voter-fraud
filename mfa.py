import pyotp

# Generate a base32 secret
secret = pyotp.random_base32()
totp = pyotp.TOTP(secret)

# Generate a TOTP token
token = totp.now()

# Verify a token
if totp.verify(token):
    print("Token is valid")
else:
    print("Token is invalid")
