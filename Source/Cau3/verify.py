from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

def read_public_key(file_name):
    with open(file_name, 'r') as file:
        key = RSA.import_key(file.read())
    return key

def read_message(file_name):
    with open(file_name, 'rb') as file:
        message = file.read()
    return message

def read_signature(file_name):
    with open(file_name, 'rb') as file:
        signature = file.read()
    return signature

def pkcs1_v1_5_decode(encoded_message, key_size):
    k = key_size // 8
    if len(encoded_message) != k or not (encoded_message.startswith(b'\x00\x01') and b'\x00' in encoded_message[2:]):
        raise ValueError("Invalid encoded message")
    index = encoded_message.find(b'\x00', 2)
    return encoded_message[index + 1:]

def verify_message_without_hash(public_key, message, signature):
    s = bytes_to_long(signature)
    m = pow(s, public_key.e, public_key.n)
    encoded_message = long_to_bytes(m, public_key.size_in_bytes())
    try:
        decoded_message = pkcs1_v1_5_decode(encoded_message, public_key.size_in_bits())
        return decoded_message == message
    except ValueError:
        return False

# Example usage
try:
    public_key = read_public_key("../pub.pem")
    message = read_message("../mess")
    signature = read_signature("../sign")
    is_valid = verify_message_without_hash(public_key, message, signature)
    print("Signature valid." if is_valid else "Signature invalid.")
except Exception as e:
    print(f"An error occurred: {e}")
