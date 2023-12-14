from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def read_pem_file(file_path):
    with open(file_path, 'rb') as file:
        pem_data = file.read()
    return pem_data

def parse_private_key(private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    if isinstance(private_key, rsa.RSAPrivateKey):
        private_numbers = private_key.private_numbers()
        return {
            'p': private_numbers.p,
            'q': private_numbers.q,
            'd': private_numbers.d,
            'dmp1': private_numbers.dmp1,
            'dmq1': private_numbers.dmq1,
            'iqmp': private_numbers.iqmp,
            'public_exponent': private_key.public_key().public_numbers().e,
            'modulus': private_key.public_key().public_numbers().n,
            'key_size': private_key.key_size
        }
    else:
        return 'Unknown private key type'

def parse_public_key(public_key_pem):
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    if isinstance(public_key, rsa.RSAPublicKey):
        public_numbers = public_key.public_numbers()
        return {
            'public_exponent': public_numbers.e,
            'modulus': public_numbers.n,
            'key_size': public_key.key_size
        }
    else:
        return 'Unknown public key type'

# Paths to the PEM files
private_key_path = '../priv.pem'
public_key_path = '../pub.pem'

# Read and parse the keys
try:
    private_key_pem = read_pem_file(private_key_path)
    public_key_pem = read_pem_file(public_key_path)

    private_key_info = parse_private_key(private_key_pem)
    public_key_info = parse_public_key(public_key_pem)
except Exception as e:
    private_key_info = f"Error reading private key: {str(e)}"
    public_key_info = f"Error reading public key: {str(e)}"

# Printing the details of the private and public keys to the console
print("Private Key Information:")
print(f"RSA Private Key: ({private_key_info['key_size']} bit, 2 primes)")
print(f"- Modulus (n): {private_key_info['modulus']}")
print(f"- Public Exponent (e): {private_key_info['public_exponent']}")
print(f"- Private Exponent (d): {private_key_info['d']}")
print(f"- Prime1 (p): {private_key_info['p']}")
print(f"- Prime2 (q): {private_key_info['q']}")
print(f"- Exponent1 (d mod (p-1)): {private_key_info['dmp1']}")
print(f"- Exponent2 (d mod (q-1)): {private_key_info['dmq1']}")
print(f"- Coefficient (inverse of q mod p): {private_key_info['iqmp']}")

print("\nPublic Key Information:")
print(f"Public Key: ({public_key_info['key_size']} bit)")
print(f"- Public Exponent (e): {public_key_info['public_exponent']}")
print(f"- Modulus (n): {public_key_info['modulus']}")
