import jwt
from cryptography.hazmat.primitives import serialization

def create_jwt(payload, private_key):
    # Convert the private key to PEM format so pyjwt can use it
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return jwt.encode(payload, pem, algorithm="RS256")

def verify_jwt(token, public_key):
    # Convert public key to PEM for verification
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwt.decode(token, pem, algorithms=["RS256"])