"""
purchaser.py  —  Terminal 1
The Purchaser creates and submits a signed, encrypted purchase order.

Steps performed:
  1. Collect order details from CLI
  2. Generate a unique Order ID (UUID) and UTC timestamp
  3. SHA-256 hash the order JSON
  4. RSA-PSS sign the hash with the Purchaser's private key
  5. AES-256-CBC encrypt the payload (random session key)
  6. RSA-OAEP encrypt the session key with the Supervisor's public key
  7. Write the encrypted message to messages/purchaser_to_supervisor.json
  8. Log the action to audit.db
"""

import json
import uuid
from datetime import datetime, timezone

from config import PURCHASER_PRIVATE, SUPERVISOR_PUBLIC, MSG_P2S
from crypto_utils import load_private_key, load_public_key, build_message
from db_logger import log_action


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _banner():
    W = 60
    print("\n" + "=" * W)
    print(f"{'SECURE PURCHASE ORDER SYSTEM':^{W}}")
    print(f"{'Role: Purchaser  (Terminal 1)':^{W}}")
    print("=" * W + "\n")


def _prompt(label: str, validator=None, err="Invalid input, please try again.") -> str:
    while True:
        val = input(f"  {label:<22}: ").strip()
        if not val:
            print("    [!] This field cannot be empty.\n")
            continue
        if validator and not validator(val):
            print(f"    [!] {err}\n")
            continue
        return val


def _is_positive_int(v: str) -> bool:
    return v.isdigit() and int(v) > 0


def _is_positive_float(v: str) -> bool:
    try:
        return float(v) > 0
    except ValueError:
        return False


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    _banner()

    # 1. Load keys
    try:
        purchaser_private = load_private_key(PURCHASER_PRIVATE)
        supervisor_public = load_public_key(SUPERVISOR_PUBLIC)
    except FileNotFoundError:
        print("  [ERROR] Key files not found.")
        print("          Run  python setup.py  first.\n")
        return

    # 2. Collect order details
    print("  Enter purchase order details:\n")
    purchaser_name = _prompt("Your full name")
    item           = _prompt("Item / description")
    quantity       = _prompt("Quantity",
                             validator=_is_positive_int,
                             err="Enter a whole number greater than 0.")
    unit_price     = _prompt("Unit price (CAD)",
                             validator=_is_positive_float,
                             err="Enter a valid price, e.g. 49.99.")
    supplier       = _prompt("Supplier name")
    notes          = input("  Notes (optional)       : ").strip()

    # 3. Build order dict
    order_id   = str(uuid.uuid4())
    timestamp  = datetime.now(timezone.utc).isoformat(timespec="seconds")
    qty        = int(quantity)
    price      = round(float(unit_price), 2)
    total      = round(qty * price, 2)

    order = {
        "order_id":       order_id,
        "timestamp":      timestamp,
        "purchaser_name": purchaser_name,
        "item":           item,
        "quantity":       qty,
        "unit_price":     price,
        "total_price":    total,
        "supplier":       supplier,
        "notes":          notes,
    }

    # 4. Display summary
    W = 60
    print("\n" + "-" * W)
    print(f"  {'ORDER SUMMARY':^{W-4}}")
    print("-" * W)
    print(f"  Order ID   : {order_id}")
    print(f"  Timestamp  : {timestamp}")
    print(f"  Item       : {item}  ×{qty}  @  CAD ${price:.2f} each")
    print(f"  Total      : CAD ${total:.2f}")
    print(f"  Supplier   : {supplier}")
    if notes:
        print(f"  Notes      : {notes}")
    print("-" * W)

    confirm = input("\n  Sign and send this order? [y/N]: ").strip().lower()
    if confirm != "y":
        print("\n  Order cancelled. Nothing was sent.\n")
        return

    # 5. Cryptographic operations
    print()
    print("  [1/4] SHA-256 hashing the order JSON...")
    print("  [2/4] RSA-PSS signing with purchaser private key...")
    print("  [3/4] AES-256-CBC encrypting the payload...")
    print("  [4/4] RSA-OAEP wrapping session key for supervisor...")

    message = build_message(order, purchaser_private, supervisor_public)

    # 6. Write message file
    MSG_P2S.write_text(json.dumps(message, indent=2))

    # 7. Audit log
    log_action(
        actor="Purchaser",
        action="ORDER_SUBMITTED",
        order_id=order_id,
        details=f"Item: {item}, Qty: {qty}, Total: CAD ${total:.2f}, Supplier: {supplier}"
    )

    print()
    print(f"  [OK] Encrypted message written to:")
    print(f"       {MSG_P2S.relative_to(MSG_P2S.parent.parent)}")
    print(f"  [OK] Action logged to audit database.")
    print()
    print("  " + "─" * 56)
    print("  Next step → open Terminal 2 and run:  python supervisor.py")
    print("  " + "─" * 56 + "\n")


if __name__ == "__main__":
    main()
