import argparse
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kid", default="k1")
    ap.add_argument("--print-env", action="store_true")
    args = ap.parse_args()

    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()

    pem = sk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    private_b64 = base64.b64encode(pem).decode("ascii")
    public_b64 = base64.b64encode(pk).decode("ascii")

    print("KID:", args.kid)
    print("PUBLIC_KEY_B64:", public_b64)
    print("PRIVATE_PEM_B64:", private_b64)

    if args.print_env:
        print("\n--- Render ENV ---")
        print(f"LICENSE_KID={args.kid}")
        print(f"LICENSE_SIGNING_PRIVATE_PEM_B64={private_b64}")

if __name__ == "__main__":
    main()
