"""
supervisor.py  —  Terminal 2
The Supervisor decrypts the purchaser's order, verifies it, then approves
or rejects it before forwarding a signed, re-encrypted message to the Dept.

Steps performed:
  1. Read messages/purchaser_to_supervisor.json
  2. RSA-OAEP decrypt the AES session key using supervisor's private key
  3. AES-256-CBC decrypt the payload
  4. Verify SHA-256 hash (tamper detection)
  5. Verify RSA-PSS purchaser signature (authentication)
  6. Replay-attack check: reject orders older than 5 minutes
  7. Display order and prompt for approve/reject decision
  8. Build inner payload containing the original order + purchaser signature
  9. RSA-PSS sign the inner payload with supervisor's private key
 10. AES-256-CBC + RSA-OAEP encrypt for the Department
 11. Write messages/supervisor_to_dept.json
 12. Log the decision to audit.db
"""

import json
from datetime import datetime, timezone, timedelta

from config import (
    SUPERVISOR_PRIVATE, SUPERVISOR_PUBLIC,
    PURCHASER_PUBLIC,
    DEPT_PUBLIC,
    MSG_P2S, MSG_S2D,
    REPLAY_WINDOW,
)
from crypto_utils import load_private_key, load_public_key, open_message, build_message
from db_logger import log_action


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _banner():
    W = 60
    print("\n" + "=" * W)
    print(f"{'SECURE PURCHASE ORDER SYSTEM':^{W}}")
    print(f"{'Role: Supervisor  (Terminal 2)':^{W}}")
    print("=" * W + "\n")


def _check_timestamp_freshness(ts_str: str) -> bool:
    """Return True if the order timestamp is within the replay window."""
    try:
        ts  = datetime.fromisoformat(ts_str)
        now = datetime.now(timezone.utc)
        # Make ts timezone-aware if it isn't (handles both formats)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = abs((now - ts).total_seconds())
        return age <= REPLAY_WINDOW
    except Exception:
        return False


def _sig_badge(valid: bool) -> str:
    return "[VERIFIED ✓]" if valid else "[INVALID  ✗]"


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    _banner()

    # 1. Load keys
    try:
        supervisor_private = load_private_key(SUPERVISOR_PRIVATE)
        supervisor_public  = load_public_key(SUPERVISOR_PUBLIC)
        purchaser_public   = load_public_key(PURCHASER_PUBLIC)
        dept_public        = load_public_key(DEPT_PUBLIC)
    except FileNotFoundError:
        print("  [ERROR] Key files not found.")
        print("          Run  python setup.py  first.\n")
        return

    # 2. Check message file exists
    if not MSG_P2S.exists():
        print("  [ERROR] No message found from Purchaser.")
        print("          Run  python purchaser.py  in Terminal 1 first.\n")
        return

    # 3. Decrypt and verify
    print("  [1/4] Reading encrypted message from Purchaser...")
    raw = json.loads(MSG_P2S.read_text())

    print("  [2/4] RSA-OAEP decrypting session key with supervisor private key...")
    print("  [3/4] AES-256-CBC decrypting payload...")
    print("  [4/4] Verifying SHA-256 hash and RSA-PSS purchaser signature...\n")

    try:
        order, sig_valid = open_message(raw, supervisor_private, purchaser_public)
    except ValueError as e:
        print(f"  [SECURITY ALERT] {e}")
        print("  Payload integrity check FAILED — message may have been tampered with.")
        log_action("Supervisor", "TAMPER_DETECTED", details=str(e))
        return
    except Exception as e:
        print(f"  [ERROR] Decryption failed: {e}")
        log_action("Supervisor", "DECRYPTION_FAILED", details=str(e))
        return

    order_id = order["order_id"]

    # 4. Replay / freshness check
    if not _check_timestamp_freshness(order["timestamp"]):
        print(f"  [SECURITY ALERT] Order timestamp is outside the {REPLAY_WINDOW // 60}-minute")
        print("                   acceptance window. Possible REPLAY ATTACK.")
        print("  Order REJECTED.\n")
        log_action("Supervisor", "REPLAY_REJECTED", order_id,
                   f"Timestamp: {order['timestamp']}")
        return

    # 5. Display order
    W = 60
    print("=" * W)
    print(f"  {'INCOMING PURCHASE ORDER':^{W-4}}")
    print("=" * W)
    print(f"  Order ID   : {order_id}")
    print(f"  Timestamp  : {order['timestamp']}")
    print(f"  Purchaser  : {order['purchaser_name']}")
    print(f"  Item       : {order['item']}")
    print(f"  Quantity   : {order['quantity']}")
    print(f"  Unit Price : CAD ${order['unit_price']:.2f}")
    print(f"  Total      : CAD ${order['total_price']:.2f}")
    print(f"  Supplier   : {order['supplier']}")
    if order.get("notes"):
        print(f"  Notes      : {order['notes']}")
    print("-" * W)
    print(f"  Purchaser signature : {_sig_badge(sig_valid)}")
    print("=" * W)

    if not sig_valid:
        print("\n  [SECURITY ALERT] Purchaser signature is INVALID.")
        print("                   This order may be a FORGERY.")
        proceed = input("\n  Signature is invalid. Proceed anyway? [y/N]: ").strip().lower()
        if proceed != "y":
            log_action("Supervisor", "SIGNATURE_REJECTED", order_id)
            print("\n  Order rejected due to invalid signature.\n")
            return
        log_action("Supervisor", "SIGNATURE_OVERRIDE", order_id,
                   "Supervisor chose to proceed despite invalid purchaser signature")

    # 6. Decision
    print("\n  Approve or reject this order?\n")
    while True:
        decision = input("  Enter decision  [A = Approve / R = Reject]: ").strip().upper()
        if decision in ("A", "R"):
            break
        print("    [!] Please enter A or R.\n")

    sv_notes     = input("  Supervisor notes (optional): ").strip()
    sv_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    decision_str = "APPROVED" if decision == "A" else "REJECTED"

    # 7. Build inner payload for Department
    #    Includes the original order dict + the purchaser's original signature
    #    so the Department can independently re-verify the purchaser's signature.
    inner = {
        "order":                  order,
        "purchaser_signature":    raw["signature"],       # RSA-PSS sig over order JSON
        "purchaser_payload_hash": raw["payload_hash"],    # SHA-256 of order JSON
        "supervisor_decision":    decision_str,
        "supervisor_notes":       sv_notes,
        "supervisor_timestamp":   sv_timestamp,
    }

    # 8. Sign + encrypt for Department
    print()
    print(f"  [1/3] RSA-PSS signing decision with supervisor private key...")
    print(f"  [2/3] AES-256-CBC encrypting payload for Department...")
    print(f"  [3/3] RSA-OAEP wrapping session key with department public key...")

    sv_message = build_message(inner, supervisor_private, dept_public)
    MSG_S2D.write_text(json.dumps(sv_message, indent=2))

    # 9. Audit log
    log_action(
        actor="Supervisor",
        action=f"ORDER_{decision_str}",
        order_id=order_id,
        details=f"Purchaser: {order['purchaser_name']}, "
                f"Total: CAD ${order['total_price']:.2f}, Notes: {sv_notes or 'none'}"
    )

    print()
    print(f"  [OK] Decision ({decision_str}) encrypted and written to:")
    print(f"       {MSG_S2D.relative_to(MSG_S2D.parent.parent)}")
    print(f"  [OK] Action logged to audit database.")
    print()
    print("  " + "─" * 56)
    print("  Next step → open Terminal 3 and run:  python department.py")
    print("  " + "─" * 56 + "\n")


if __name__ == "__main__":
    main()
