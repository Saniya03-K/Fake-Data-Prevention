# I set this to 365 days so I don't have to regenerate it every time I test
import os
import datetime
import hashlib
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import config

def load_or_generate_certificate():
    if os.path.exists("private_key.pem") and os.path.exists("certificate.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=config.PRIVATE_KEY_PASSWORD,
                backend=default_backend()
            )
        with open("certificate.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        public_key = cert.public_key()
        print("Loaded existing certificate.")
        return private_key, public_key, cert

    print("Generating new certificate with password protection...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "University of Catania"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Sensor_01"),
    ])

    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend()))

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(config.PRIVATE_KEY_PASSWORD)
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(" New certificate and keys saved with password.")
    return private_key, public_key, cert

def get_public_key_fingerprint(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(public_bytes).digest()).decode()