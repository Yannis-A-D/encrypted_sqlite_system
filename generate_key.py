"""
generate_key.py — Utility to generate a new 256-bit AES Fernet encryption key.
"""

from cryptography.fernet import Fernet


def main():
    key = Fernet.generate_key().decode()
    print("\n" + "=" * 60)
    print(" [KEY] NEW ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print(f"\nENCRYPTION_KEY={key}\n")
    print("Instructions:")
    print("1. Add this key to your .env file: ENCRYPTION_KEY=<key>")
    print("2. Or save it in 'secret.key' in the project root.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
