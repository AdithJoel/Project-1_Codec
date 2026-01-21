"""
Cryptography Algorithms Implementation
Demonstrates AES, RSA, and SHA algorithms for encryption, decryption, and hashing
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os
import base64


class AESCrypto:
    """AES (Advanced Encryption Standard) - Symmetric encryption"""
    
    def __init__(self, key_size=256):
        """Initialize AES with specified key size (128, 192, or 256 bits)"""
        self.key_size = key_size // 8  # Convert bits to bytes
        self.key = os.urandom(self.key_size)
    
    def encrypt(self, plaintext):
        """Encrypt plaintext using AES-CBC mode"""
        # Generate random IV (Initialization Vector)
        iv = os.urandom(16)  # AES block size is 128 bits (16 bytes)
        
        # Pad plaintext to multiple of 16 bytes
        padded_text = self._pad(plaintext.encode())
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        # Return IV + ciphertext (IV needed for decryption)
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt ciphertext"""
        # Decode from base64
        data = base64.b64decode(encrypted_data)
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        return self._unpad(padded_plaintext).decode()
    
    def _pad(self, data):
        """PKCS7 padding"""
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length] * padding_length)
    
    def _unpad(self, data):
        """Remove PKCS7 padding"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    def get_key_hex(self):
        """Get key as hex string for sharing/storage"""
        return self.key.hex()


class RSACrypto:
    """RSA (Rivest-Shamir-Adleman) - Asymmetric encryption"""
    
    def __init__(self, key_size=2048):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt(self, plaintext):
        """Encrypt with public key"""
        ciphertext = self.public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt with private key"""
        ciphertext = base64.b64decode(encrypted_data)
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    
    def sign(self, message):
        """Create digital signature"""
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify(self, message, signature):
        """Verify digital signature"""
        try:
            self.public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def export_public_key(self):
        """Export public key as PEM string"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()


class SHAHash:
    """SHA (Secure Hash Algorithm) - Cryptographic hashing"""
    
    @staticmethod
    def sha256(data):
        """Compute SHA-256 hash"""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode())
        return digest.finalize().hex()
    
    @staticmethod
    def sha512(data):
        """Compute SHA-512 hash"""
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(data.encode())
        return digest.finalize().hex()
    
    @staticmethod
    def verify_integrity(data, expected_hash, algorithm='sha256'):
        """Verify data integrity by comparing hashes"""
        if algorithm == 'sha256':
            actual_hash = SHAHash.sha256(data)
        elif algorithm == 'sha512':
            actual_hash = SHAHash.sha512(data)
        else:
            raise ValueError("Unsupported algorithm")
        
        return actual_hash == expected_hash


def demonstrate_cryptography():
    """Demonstrate all cryptography algorithms"""
    
    print("=" * 70)
    print("CRYPTOGRAPHY ALGORITHMS DEMONSTRATION")
    print("=" * 70)
    
    # AES Demonstration
    print("\n1. AES (SYMMETRIC ENCRYPTION)")
    print("-" * 70)
    aes = AESCrypto(key_size=256)
    message = "This is a secret message for AES encryption!"
    print(f"Original message: {message}")
    print(f"AES Key (hex): {aes.get_key_hex()[:32]}...")
    
    encrypted = aes.encrypt(message)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = aes.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")
    
    # RSA Demonstration
    print("\n2. RSA (ASYMMETRIC ENCRYPTION)")
    print("-" * 70)
    rsa_crypto = RSACrypto(key_size=2048)
    message = "This is a secret message for RSA!"
    print(f"Original message: {message}")
    
    encrypted = rsa_crypto.encrypt(message)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = rsa_crypto.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {message == decrypted}")
    
    # Digital Signature
    print("\n3. RSA DIGITAL SIGNATURE")
    print("-" * 70)
    message = "Important document to be signed"
    print(f"Message: {message}")
    
    signature = rsa_crypto.sign(message)
    print(f"Signature: {signature[:50]}...")
    
    is_valid = rsa_crypto.verify(message, signature)
    print(f"Signature valid: {is_valid}")
    
    # Tamper detection
    tampered = "Important document to be signed (MODIFIED)"
    is_valid_tampered = rsa_crypto.verify(tampered, signature)
    print(f"Tampered message valid: {is_valid_tampered}")
    
    # SHA Demonstration
    print("\n4. SHA HASHING")
    print("-" * 70)
    data = "Hash this important data"
    print(f"Original data: {data}")
    
    sha256_hash = SHAHash.sha256(data)
    print(f"SHA-256 hash: {sha256_hash}")
    
    sha512_hash = SHAHash.sha512(data)
    print(f"SHA-512 hash: {sha512_hash}")
    
    # Integrity verification
    print("\n5. DATA INTEGRITY VERIFICATION")
    print("-" * 70)
    is_valid = SHAHash.verify_integrity(data, sha256_hash, 'sha256')
    print(f"Data integrity verified: {is_valid}")
    
    modified_data = "Hash this important data (modified)"
    is_valid_modified = SHAHash.verify_integrity(modified_data, sha256_hash, 'sha256')
    print(f"Modified data integrity: {is_valid_modified}")
    
    # Hybrid Encryption (AES + RSA)
    print("\n6. HYBRID ENCRYPTION (AES + RSA)")
    print("-" * 70)
    print("Scenario: Encrypting large data efficiently")
    large_message = "This is a large message that would be inefficient to encrypt with RSA alone. " * 10
    
    # Step 1: Generate AES key and encrypt data
    aes_hybrid = AESCrypto(key_size=256)
    encrypted_data = aes_hybrid.encrypt(large_message[:100] + "...")
    print(f"1. Data encrypted with AES: {encrypted_data[:50]}...")
    
    # Step 2: Encrypt AES key with RSA
    aes_key_encrypted = rsa_crypto.encrypt(aes_hybrid.get_key_hex())
    print(f"2. AES key encrypted with RSA: {aes_key_encrypted[:50]}...")
    
    print("3. Both can be sent securely!")
    print("   - Receiver decrypts AES key using their RSA private key")
    print("   - Then decrypts data using the AES key")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    demonstrate_cryptography()