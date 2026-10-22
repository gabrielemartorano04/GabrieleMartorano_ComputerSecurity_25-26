"""
setup.py
Run ONCE before using the system.
Generates RSA-2048 key pairs for all three roles and writes them to keys/.
"""

from crypto_utils import generate_rsa_keypair, serialize_private_key, serialize_public_key
from config import (
    PURCHASER_PRIVATE,  PURCHASER_PUBLIC,
    SUPERVISOR_PRIVATE, SUPERVISOR_PUBLIC,
    DEPT_PRIVATE,       DEPT_PUBLIC,
)

ROLES = [
    ("Purchaser",   PURCHASER_PRIVATE,  PURCHASER_PUBLIC),
    ("Supervisor",  SUPERVISOR_PRIVATE, SUPERVISOR_PUBLIC),
    ("Department",  DEPT_PRIVATE,       DEPT_PUBLIC),
]


def main():
    W = 52
    print("\n" + "=" * W)
    print(f"{'Secure Purchase Order System':^{W}}")
    print(f"{'RSA-2048 Key Generation':^{W}}")
    print("=" * W + "\n")

    for role, priv_path, pub_path in ROLES:
        print(f"  Generating RSA-2048 key pair for {role}...")
        private_key, public_key = generate_rsa_keypair()
        priv_path.write_bytes(serialize_private_key(private_key))
        pub_path.write_bytes(serialize_public_key(public_key))
        print(f"    [OK] {priv_path.name}")
        print(f"    [OK] {pub_path.name}\n")

    print("-" * W)
    print("  6 PEM files written to keys/")
    print("  Setup complete. You may now run the system.\n")
    print("  Terminal 1 → python purchaser.py")
    print("  Terminal 2 → python supervisor.py")
    print("  Terminal 3 → python department.py")
    print("=" * W + "\n")


if __name__ == "__main__":
    main()
