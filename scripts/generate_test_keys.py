#!/usr/bin/env python3
"""
Generate RSA keypair for JWT testing
Usage: python generate_test_keys.py
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

def generate_keys():
    """Generate RSA keypair for testing"""
    os.makedirs("keys", exist_ok=True)
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write to files
    with open("keys/server_private.pem", "wb") as f:
        f.write(pem_private)
    
    with open("keys/server_public.pem", "wb") as f:
        f.write(pem_public)
    
    # Generate attacker key for mismatched RS256 test
    attacker_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    pem_attacker = attacker_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open("keys/attacker_private.pem", "wb") as f:
        f.write(pem_attacker)
    
    print("✓ Keys generated:")
    print("  - keys/server_public.pem")
    print("  - keys/server_private.pem")
    print("  - keys/attacker_private.pem")

if __name__ == "__main__":
    generate_keys()
