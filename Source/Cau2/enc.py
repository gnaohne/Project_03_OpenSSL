import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def encryption(plaintext_file, cipher_file, public_key_path):
    # Read the public key content from the file
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Read the data from the plaintext file
    with open(plaintext_file, 'rb') as file:
        plain_text = file.read()

    # Encrypt using public key and PKCS#1 v1.5 padding
    # because OpenSSL uses this padding by default
    cipher = public_key.encrypt(
        plain_text,
        padding.PKCS1v15()
    )

    # Write the encrypted data to the cipher file
    with open(cipher_file, 'wb') as file:
        file.write(cipher)

    print('Encryption done!')

# Paths to the PEM files and plaintext file and cipher file
script_dir = os.path.dirname(os.path.abspath(__file__))
public_key_path = os.path.join(script_dir, '..', 'pub.pem')
plaintext_file = os.path.join(script_dir, '..', 'plain')
cipher_file = os.path.join(script_dir, 'cipher_file.enc')

# Encrypt the data
encryption(plaintext_file, cipher_file, public_key_path)