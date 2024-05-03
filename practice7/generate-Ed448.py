from Crypto. PublicKey import ECC
from Crypto. Signature import eddsa

key = ECC.generate(curve="ed448")
with open("ankuia", "w") as f:
    data = key.public_key().export_key(format="PEM")
    f.write(data)

message = b"If two witches were to watch twe watches. then which witch would watch which watch?\n"

with open("message.txt", "wb") as f:
    f.write(message)

signer = eddsa.new(key, mode='rfc8032')
signature = signer.sign(message)

with open("message.sig", "wb") as f:
    f.write(signature)