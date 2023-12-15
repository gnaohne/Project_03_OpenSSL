import os
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

def read_private_key(file_name):
    with open(file_name, 'r') as file:
        key = RSA.import_key(file.read())
    return key

def read_message(file_name):
    with open(file_name, 'rb') as file:
        message = file.read()
    return message

def pkcs1_v1_5_encode(message, key_size):
    # Determine the length of the key in bytes
    k = key_size // 8

    # Check if the message is not too long
    if len(message) > k - 11:
        raise ValueError("Message too long")

    # The padding string PS, consisting of FF bytes
    PS = b'\xFF' * (k - len(message) - 3)

    # Construct the encoded message EM
    EM = b'\x00\x01' + PS + b'\x00' + message
    return EM

def sign_message_without_hash(private_key, message):
    # Encode the message with PKCS#1 v1.5 padding
    encoded_message = pkcs1_v1_5_encode(message, private_key.size_in_bits())

    # Convert encoded message to an integer
    m = bytes_to_long(encoded_message)

    # Sign the message (compute m^d mod n)
    s = pow(m, private_key.d, private_key.n)

    # Convert the signature to a byte sequence
    signature = long_to_bytes(s)
    return signature

def write_signature(file_name, signature):
    with open(file_name, 'wb') as file:
        file.write(signature)

try:
    # Paths to the files
    script_dir = os.path.dirname(os.path.abspath(__file__))
    private_key_file = os.path.join(script_dir, '..', 'priv.pem')
    message_file = os.path.join(script_dir, '..', 'mess')
    signature_file = os.path.join(script_dir , 'signature')

    private_key = read_private_key(private_key_file)
    message = read_message(message_file)
    signature = sign_message_without_hash(private_key, message)
    write_signature(signature_file, signature)
except Exception as e:
    print(f"An error occurred: {e}")
