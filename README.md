# Project-1_Codec
# Cryptography Algorithms Implementation

A comprehensive Python implementation of popular cryptography algorithms including AES, RSA, and SHA for understanding encryption, decryption, and hashing processes.

## 🔐 Features

- **AES Encryption** - Symmetric encryption with CBC mode and PKCS7 padding
- **RSA Encryption** - Asymmetric encryption with digital signatures
- **SHA Hashing** - Cryptographic hashing with integrity verification
- **Hybrid Encryption** - Demonstrates real-world combination of AES + RSA

## 📋 Prerequisites

- Python 3.7+
- `cryptography` library

## 🚀 Installation

```bash
pip install cryptography
```

## 💻 Usage

Run the demonstration script:

```bash
python crypto_implementation.py
```

### Using Individual Classes

```python
from crypto_implementation import AESCrypto, RSACrypto, SHAHash

# AES Symmetric Encryption
aes = AESCrypto(key_size=256)
encrypted = aes.encrypt("Secret message")
decrypted = aes.decrypt(encrypted)

# RSA Asymmetric Encryption
rsa = RSACrypto(key_size=2048)
encrypted = rsa.encrypt("Secret message")
decrypted = rsa.decrypt(encrypted)

# Digital Signature
signature = rsa.sign("Important document")
is_valid = rsa.verify("Important document", signature)

# SHA Hashing
hash_value = SHAHash.sha256("Data to hash")
is_valid = SHAHash.verify_integrity("Data to hash", hash_value)
```

## 🧪 What's Demonstrated

### 1. AES (Advanced Encryption Standard)
- **Type**: Symmetric encryption
- **Key Size**: 256-bit
- **Mode**: CBC (Cipher Block Chaining)
- **Use Case**: Fast encryption for bulk data

### 2. RSA (Rivest-Shamir-Adleman)
- **Type**: Asymmetric encryption
- **Key Size**: 2048-bit
- **Padding**: OAEP with SHA-256
- **Use Cases**: 
  - Secure key exchange
  - Digital signatures
  - Authentication

### 3. SHA (Secure Hash Algorithm)
- **Algorithms**: SHA-256, SHA-512
- **Type**: One-way cryptographic hash
- **Use Cases**:
  - Password storage
  - Data integrity verification
  - Blockchain applications

### 4. Hybrid Encryption
- Combines AES speed with RSA security
- Industry-standard approach for secure communication
- Efficient for large data transmission

## 📊 Example Output

```
CRYPTOGRAPHY ALGORITHMS DEMONSTRATION
======================================================================

1. AES (SYMMETRIC ENCRYPTION)
----------------------------------------------------------------------
Original message: This is a secret message for AES encryption!
AES Key (hex): 3a7f2b8c9d1e4f5a...
Encrypted: aGVsbG8gd29ybGQ=...
Decrypted: This is a secret message for AES encryption!
Match: True

2. RSA (ASYMMETRIC ENCRYPTION)
----------------------------------------------------------------------
Original message: This is a secret message for RSA!
Encrypted: SGVsbG8gV29ybGQ=...
Decrypted: This is a secret message for RSA!
Match: True
```

## 🔑 Key Concepts Learned

- **Symmetric vs Asymmetric Encryption** - When to use each approach
- **Key Management** - Secure generation and storage
- **Digital Signatures** - Authentication and non-repudiation
- **Hash Functions** - One-way cryptographic operations
- **Padding Schemes** - PKCS7 and OAEP for security
- **Hybrid Systems** - Combining algorithms for optimal security

