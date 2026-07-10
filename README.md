# SEC-PRJ-7E_25: Fake Data Prevention with Conventional Cryptotools

Name: Saniya Khanam  
Date: July 2026

## Description
This project implements a cryptographic tool to prevent fake data injection in sensor systems. It integrates X.509 certificates, RSA digital signatures, AES-GCM authenticated encryption, and JWT with the RS256 algorithm. Additional security layers include password-protected private keys, public key fingerprinting, replay attack prevention, Role-Based Access Control (RBAC), certificate expiry validation, and an immutable hash-chain audit log.

## Requirements
- Python 3.11+
- Install dependencies:
  ```bash
  pip install cryptography pyjwt