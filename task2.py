from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, json

# Key Distribution Center (KDC)
class KDC:
    def __init__(self):
        self.symmetric_keys = {}

    def generate_symmetric_key(self, user_id):
        key = os.urandom(32)  # Generate AES key
        self.symmetric_keys[user_id] = key
        return key

    def get_symmetric_key(self, user_id):
        return self.symmetric_keys.get(user_id, None)

# Certificate Authority (CA)
class CA:
    def __init__(self):
        self.certificates = {}
        self.revoked_certificates = set()

    def issue_certificate(self, user_id, public_key):
        cert = {
            "user_id": user_id,
            "public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }
        self.certificates[user_id] = cert
        return cert

    def revoke_certificate(self, user_id):
        if user_id in self.certificates:
            self.revoked_certificates.add(user_id)
            del self.certificates[user_id]
            print(f"Certificate for {user_id} revoked.")

    def verify_certificate(self, user_id):
        return user_id in self.certificates and user_id not in self.revoked_certificates

# Secure Key Exchange using Diffie-Hellman
def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_key_pair(parameters):
    return parameters.generate_private_key()

def derive_shared_secret(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)

# AES Encryption for Symmetric Key Storage
def encrypt_symmetric_key(symmetric_key, rsa_public_key):
    return rsa_public_key.encrypt(
        symmetric_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_symmetric_key(encrypted_key, rsa_private_key):
    return rsa_private_key.decrypt(
        encrypted_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Demonstration
def main():
    kdc = KDC()
    ca = CA()

    # Generate RSA Keys for Alice and Bob
    alice_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    bob_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    # Issue certificates
    alice_cert = ca.issue_certificate("alice", alice_public)
    bob_cert = ca.issue_certificate("bob", bob_public)

    # Diffie-Hellman Key Exchange
    dh_parameters = generate_dh_parameters()
    alice_dh_key = generate_dh_key_pair(dh_parameters)
    bob_dh_key = generate_dh_key_pair(dh_parameters)

    # Derive shared secret
    alice_shared_secret = derive_shared_secret(alice_dh_key, bob_dh_key.public_key())
    bob_shared_secret = derive_shared_secret(bob_dh_key, alice_dh_key.public_key())

    print("Shared Secret Match:", alice_shared_secret == bob_shared_secret)

    # KDC issues symmetric key
    if ca.verify_certificate("bob"):
        aes_key = kdc.generate_symmetric_key("bob")
        encrypted_aes_key = encrypt_symmetric_key(aes_key, bob_public)
        decrypted_aes_key = decrypt_symmetric_key(encrypted_aes_key, bob_private)
        print("AES Key Exchange Successful:", aes_key == decrypted_aes_key)

    # Revoke Bob's certificate
    ca.revoke_certificate("bob")
    print("Bob's certificate revoked.")

if __name__ == "__main__":
    main()