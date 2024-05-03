"""
USAGE:
1. Generate a private key using OpenSSL:
    python interop.py genpkey -o private_key.pem -p <password>
2. Derive RSA Public Key from Private Key using OpenSSL:
    python interop.py pkey -i private_key.pem -o public_key.pem -p <password>
3. Encrypt a file using OpenSSL:
    python interop.py pkeyutl -k public_key.pem -i plaintext.txt -o ciphertext.bin -e -p <password>
4. Decrypt a file using OpenSSL:
    python interop.py pkeyutl -k private_key.pem -i ciphertext.bin -o decrypted.txt -d -p <password>
"""

import argparse
import subprocess
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

FAIL_CODE = 1


def generate_private_key_openssl(outfile: str, password: str) -> None:
    try:
        subprocess.run([
            "openssl", "genpkey", "-algorithm", "RSA", "-out", outfile,
            "-aes-256-cbc", "-pass", "pass:{}".format(password)
        ], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Failed to generate the private key with OpenSSL")
        sys.exit(FAIL_CODE)


def derive_public_key_openssl(infile: str, outfile: str, password: str) -> None:
    try:
        subprocess.run([
            "openssl", "rsa", "-in", infile, "-pubout", "-out", outfile,
            "-passin", "pass:{}".format(password)
        ], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Failed to generate the public key with OpenSSL")
        sys.exit(FAIL_CODE)


def generate_private_key_pycryptodome(outfile: str, password: str) -> None:
    key = RSA.generate(3072)
    private_key_pem = key.export_key(passphrase=password, pkcs=8, protection="PBKDF2WithHMAC-SHA1AndAES256-CBC")
    with open(outfile, 'wb') as f:
        f.write(private_key_pem)


def derive_public_key_pycryptodome(infile: str, outfile: str, password: str) -> None:
    with open(infile, 'rb') as f:
        encrypted_private_key = f.read()
    key = RSA.import_key(encrypted_private_key, passphrase=password)
    public_key = key.publickey().export_key()
    with open(outfile, 'wb') as f:
        f.write(public_key)


def encrypt_openssl(key_file: str, infile: str, outfile: str) -> None:
    try:
        subprocess.run([
            "openssl", "rsautl", "-encrypt", "-pubin", "-inkey", key_file,
            "-oaep", "-in", infile, "-out", outfile
        ], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Failed to encrypt the file with OpenSSL")
        sys.exit(FAIL_CODE)


def decrypt_openssl(key_file: str, infile: str, outfile: str, password: str) -> None:
    try:
        subprocess.run([
            "openssl", "rsautl", "-decrypt", "-inkey", key_file,
            "-oaep", "-in", infile, "-out", outfile, "-passin", "pass:{}".format(password)
        ], check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("Failed to decrypt the file with OpenSSL")
        sys.exit(FAIL_CODE)


def encrypt_pycryptodome(key_file: str, infile: str, outfile: str) -> None:
    public_key = RSA.import_key(open(key_file).read())
    with open(infile, 'rb') as file:
        plaintext = file.read()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    with open(outfile, 'wb') as file:
        file.write(ciphertext)


def decrypt_pycryptodome(key_file: str, infile: str, outfile: str, password: str) -> None:
    private_key = RSA.import_key(open(key_file).read(), passphrase=password)
    with open(infile, 'rb') as file:
        ciphertext = file.read()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    with open(outfile, 'wb') as file:
        file.write(plaintext)


def main(args):
    use_openssl = args.openssl
    action = args.action

    if action == "genpkey":
        if use_openssl:
            generate_private_key_openssl(args.outfile, args.pwd)
        else:
            generate_private_key_pycryptodome(args.outfile, args.pwd)
    elif action == "pkey":
        if use_openssl:
            derive_public_key_openssl(args.infile, args.outfile, args.pwd)
        else:
            derive_public_key_pycryptodome(args.infile, args.outfile, args.pwd)
    elif action == "pkeyutl":
        if args.encrypt:
            if use_openssl:
                encrypt_openssl(args.inkey, args.infile, args.outfile)
            else:
                encrypt_pycryptodome(args.inkey, args.infile, args.outfile)
        else:
            if use_openssl:
                decrypt_openssl(args.inkey, args.infile, args.outfile, args.pwd)
            else:
                decrypt_pycryptodome(args.inkey, args.infile, args.outfile, args.pwd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest="action", help="the task to perform")

    sp_genpkey = subparsers.add_parser("genpkey")
    sp_genpkey.add_argument("-x", "--openssl", help="whether to use OpenSSL for the action", action="store_true")
    sp_genpkey.add_argument("-o", "--out", help="the output file name", dest="outfile", required=True)
    sp_genpkey.add_argument("-p", "--pass", help="the private key password", dest="pwd", required=True)

    sp_pkey = subparsers.add_parser("pkey")
    sp_pkey.add_argument("-x", "--openssl", help="whether to use OpenSSL for the action", action="store_true")
    sp_pkey.add_argument("-i", "--in", help="the input file name", dest="infile", required=True)
    sp_pkey.add_argument("-o", "--out", help="the output file name", dest="outfile", required=True)
    sp_pkey.add_argument("-p", "--pass", help="the private key password", dest="pwd", required=True)

    sp_pkeyutl = subparsers.add_parser("pkeyutl")
    sp_pkeyutl.add_argument("-x", "--openssl", help="whether to use OpenSSL for the action", action="store_true")
    sp_pkeyutl.add_argument("-k", "--inkey", help="the input key", required=True)
    sp_pkeyutl.add_argument("-i", "--in", help="the input file name", dest="infile", required=True)
    sp_pkeyutl.add_argument("-o", "--out", help="the output file name", dest="outfile", required=True)
    sp_pkeyutl.add_argument("-p", "--pass", help="the private key password", dest="pwd")
    sp_pkeyutl.add_argument("-e", "--encrypt", help="whether to encrypt instead of decrypting", action="store_true")
    sp_pkeyutl.add_argument("-d", "--decrypt", help="whether to decrypt instead of encrypting", action="store_true")

    args = parser.parse_args()
    main(args)