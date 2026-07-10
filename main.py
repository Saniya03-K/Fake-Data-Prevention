# main.py
import datetime
import hashlib
import os
import config
from cert_manager import load_or_generate_certificate, get_public_key_fingerprint
from crypto_ops import sign_message, verify_signature, encrypt_aes, decrypt_aes
from jwt_ops import create_jwt, verify_jwt

def log_audit_chain(result, message):
    log_file = "audit_chain.log"
    previous_hash = "0" * 64
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                previous_hash = hashlib.sha256(last_line.encode()).hexdigest()
    
    timestamp = datetime.datetime.now().isoformat()
    entry = f"{timestamp} | Result: {result} | Msg: {message.decode() if isinstance(message, bytes) else message} | PrevHash: {previous_hash}"
    current_hash = hashlib.sha256(entry.encode()).hexdigest()
    
    with open(log_file, "a") as f:
        f.write(f"{entry} | Hash: {current_hash}\n")
    
    print("[INFO] Audit log updated.")

# Load certificate
private_key, public_key, cert = load_or_generate_certificate()

# Check certificate expiry
if datetime.datetime.now(datetime.timezone.utc) > cert.not_valid_after_utc:
    print("ERROR: Certificate has expired!")
    print("Valid until: " + str(cert.not_valid_after_utc))
    exit()
print("Certificate valid until: " + str(cert.not_valid_after_utc))

# Fingerprint
fingerprint = get_public_key_fingerprint(public_key)
print("\nPublic Key Fingerprint (SHA-256): " + fingerprint)

# ---------- SENDER ----------
print("--- SENDER ---")
message = config.MESSAGE.encode('utf-8')
print("Original Message: " + config.MESSAGE)

# Sign
signature = sign_message(private_key, message)
print("RSA Signature created.")

message = "Fake temperature: 99°C".encode('utf-8')

# Encrypt
key, nonce, encrypted, tag = encrypt_aes(message)
print("AES-GCM Encrypted.")

# JWT
payload = {
    "encrypted": encrypted.hex(),
    "signature": signature.hex(),
    "nonce": nonce.hex(),
    "tag": tag.hex(),
    "role": "sensor",
    "iat": datetime.datetime.now(datetime.timezone.utc).timestamp(),
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=config.JWT_EXPIRY_MINUTES)
}
jwt_token = create_jwt(payload, private_key)
print("JWT (RS256) Created.\n")

# ---------- RECEIVER ----------
print("--- RECEIVER ---")
result = "UNKNOWN"

try:
    decoded = verify_jwt(jwt_token, public_key)
    print("JWT Signature verified.")

    # RBAC
    if decoded.get("role") != "sensor":
        print("ACCESS DENIED: Invalid role - " + str(decoded.get("role")))
        raise Exception("Invalid role: " + str(decoded.get("role")))
    print("Role verified: " + decoded.get("role"))

    # Replay check
    issued_at = datetime.datetime.fromtimestamp(decoded["iat"], tz=datetime.timezone.utc)
    age = (datetime.datetime.now(datetime.timezone.utc) - issued_at).total_seconds()
    if age > config.MAX_MESSAGE_AGE_SECONDS:
        print("REPLAY ATTACK DETECTED! Age: " + str(round(age, 1)) + "s")
        raise Exception("Replay attack detected. Age: " + str(round(age, 1)) + "s")
    print("Replay check passed. Age: " + str(round(age, 1)) + "s")

    # Decrypt
    decrypted = decrypt_aes(
        key,
        bytes.fromhex(decoded["nonce"]),
        bytes.fromhex(decoded["encrypted"]),
        bytes.fromhex(decoded["tag"])
    )
    print("Decrypted: " + decrypted.decode())

    # Verify signature
    if verify_signature(public_key, decrypted, bytes.fromhex(decoded["signature"])):
        if decrypted == message:
            print("\nRESULT: ALL GOOD")
            result = "ALL_GOOD"
        else:
            print("\nRESULT: FAKE DETECTED (Mismatch)")
            result = "FAKE_DETECTED_MISMATCH"
    else:
        print("\nRESULT: FAKE DETECTED (Signature invalid)")
        result = "FAKE_DETECTED_SIG"

except Exception as e:
    print("\nRESULT: FAKE DETECTED - " + str(e))
    result = "FAKE_DETECTED_EXCEPTION"

# Audit log
log_audit_chain(result, message)