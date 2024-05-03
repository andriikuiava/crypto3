from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

public_key_pem = """
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAITRpRf+PNWruknCVkz+bCvD+09P84Gf
CBSO7oyM87qHAgMBAAE=
-----END PUBLIC KEY-----
"""

public_key_str = public_key_pem.strip().split('\n')[1:-1]
public_key_b64 = ''.join(public_key_str).encode()

public_key_der = base64.b64decode(public_key_b64)

public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())

modulus = public_key.public_numbers().n
print("Modulus (n):", modulus)
