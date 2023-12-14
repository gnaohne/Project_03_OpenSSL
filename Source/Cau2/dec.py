import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def decryption(cipher_file, plain_file, private_key_path):
    # Read the private key content from the file
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, 
            backend=default_backend()
        )

    # read data from cipher file
    with open(cipher_file, 'rb') as file:
        cipher = file.read()

    # decrypt using private key and PKCS#1 v1.5 padding 
    # because OpenSSL uses this padding by default
    plain_text = private_key.decrypt(
        cipher,
        padding.PKCS1v15()
    )

    # write the decrypted data to the plain file
    with open(plain_file, 'wb') as file:
        file.write(plain_text)

    print('Decryption done!')

# Paths to the PEM files and plaintext file and cipher file
script_dir = os.path.dirname(os.path.abspath(__file__))
private_key_path = os.path.join(script_dir, '..', 'priv.pem')
plaintext_file = os.path.join(script_dir, 'plain_file.txt')
cipher_file = os.path.join(script_dir, '..', 'cipher')

# Decrypt the data
decryption(cipher_file, plaintext_file, private_key_path)