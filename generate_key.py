"""
generate_key.py — Utility to generate a new 256-bit AES-256-GCM encryption key.
"""

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    raw_key_bytes = AESGCM.generate_key(bit_length=256)
    key = base64.urlsafe_b64encode(raw_key_bytes).decode("utf-8")
    print("\n" + "=" * 60)
    print(" [KEY] NEW AES-256-GCM ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print(f"\nENCRYPTION_KEY={key}\n")
    print("Instructions:")
    print("1. Add this key to your .env or bot.env file: ENCRYPTION_KEY=<key>")
    print("2. Or save it in 'secret.key' in the project root.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
