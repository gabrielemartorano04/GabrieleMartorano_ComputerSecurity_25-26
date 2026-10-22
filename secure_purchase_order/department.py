"""
department.py  —  Terminal 3
The Purchasing Department decrypts the supervisor's message, independently
verifies BOTH digital signatures, performs a replay check, then processes
(or rejects) the order and prints the full audit log.

Steps performed:
  1. Read messages/supervisor_to_dept.json
  2. RSA-OAEP decrypt the AES session key using dept's private key
  3. AES-256-CBC decrypt the inner payload
  4. Verify SHA-256 hash (tamper detection)
  5. Verify RSA-PSS supervisor signature over the full inner payload
  6. Re-verify RSA-PSS purchaser signature over the original order JSON
  7. Replay-attack check: reject if order_id was already processed
  8. Display full order + both signature statuses
  9. Process the order (if approved and both sigs valid)
 10. Mark order_id as processed in audit.db (prevents future replays)
 11. Print complete audit log
"""

import json

from config import DEPT_PRIVATE, SUPERVISOR_PUBLIC, PURCHASER_PUBLIC, MSG_S2D
from crypto_utils import load_private_key, load_public_key, open_message, verify_signature
from db_logger import log_action, is_replay, mark_order_processed, print_audit_log


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _banner():
    W = 60
    print("\n" + "=" * W)
    print(f"{'SECURE PURCHASE ORDER SYSTEM':^{W}}")
    print(f"{'Role: Purchasing Department  (Terminal 3)':^{W}}")
    print("=" * W + "\n")


def _sig_badge(valid: bool) -> str:
    return "[VERIFIED ✓]" if valid else "[INVALID  ✗]"


def _reserialize_order(order: dict) -> bytes:
    """
    Recreate the exact bytes the purchaser originally signed.
    sort_keys=True must match what build_message() uses in crypto_utils.
    """
    return json.dumps(order, sort_keys=True).encode()


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    _banner()

    # 1. Load keys
    try:
        dept_private      = load_private_key(DEPT_PRIVATE)
        supervisor_public = load_public_key(SUPERVISOR_PUBLIC)
        purchaser_public  = load_public_key(PURCHASER_PUBLIC)
    except FileNotFoundError:
        print("  [ERROR] Key files not found.")
        print("          Run  python setup.py  first.\n")
        return

    # 2. Check message file exists
    if not MSG_S2D.exists():
        print("  [ERROR] No message found from Supervisor.")
        print("          Run  python supervisor.py  in Terminal 2 first.\n")
        return

    # 3. Decrypt and verify supervisor message
    print("  [1/5] Reading encrypted message from Supervisor...")
    raw = json.loads(MSG_S2D.read_text())

    print("  [2/5] RSA-OAEP decrypting session key with department private key...")
    print("  [3/5] AES-256-CBC decrypting payload...")
    print("  [4/5] Verifying SHA-256 hash integrity...")
    print("  [5/5] Verifying RSA-PSS signatures (supervisor + purchaser)...\n")

    try:
        inner, sv_sig_valid = open_message(raw, dept_private, supervisor_public)
    except ValueError as e:
        print(f"  [SECURITY ALERT] {e}")
        print("  Message integrity check FAILED — payload may have been TAMPERED WITH.")
        log_action("Department", "TAMPER_DETECTED", details=str(e))
        return
    except Exception as e:
        print(f"  [ERROR] Decryption failed: {e}")
        log_action("Department", "DECRYPTION_FAILED", details=str(e))
        return

    order    = inner["order"]
    order_id = order["order_id"]

    # 4. Replay check
    if is_replay(order_id):
        print(f"  [SECURITY ALERT] Order ID has already been processed.")
        print(f"  Order ID : {order_id}")
        print("  This appears to be a REPLAY ATTACK. Order REJECTED.\n")
        log_action("Department", "REPLAY_REJECTED", order_id)
        return

    # 5. Re-verify purchaser signature independently
    #    The purchaser signed: json.dumps(order, sort_keys=True).encode()
    order_bytes           = _reserialize_order(order)
    purchaser_sig_valid   = verify_signature(
        order_bytes,
        inner["purchaser_signature"],
        purchaser_public
    )

    # 6. Display everything
    W = 64
    print("=" * W)
    print(f"  {'PURCHASE ORDER — DEPARTMENT REVIEW':^{W-4}}")
    print("=" * W)
    print(f"  Order ID          : {order_id}")
    print(f"  Submitted         : {order['timestamp']}")
    print(f"  Purchaser         : {order['purchaser_name']}")
    print("-" * W)
    print(f"  Item              : {order['item']}")
    print(f"  Quantity          : {order['quantity']}")
    print(f"  Unit Price        : CAD ${order['unit_price']:.2f}")
    print(f"  Total             : CAD ${order['total_price']:.2f}")
    print(f"  Supplier          : {order['supplier']}")
    if order.get("notes"):
        print(f"  Purchaser notes   : {order['notes']}")
    print("-" * W)
    print(f"  Supervisor verdict: {inner['supervisor_decision']}")
    print(f"  Reviewed at       : {inner['supervisor_timestamp']}")
    if inner.get("supervisor_notes"):
        print(f"  Supervisor notes  : {inner['supervisor_notes']}")
    print("-" * W)
    print(f"  Supervisor sig    : {_sig_badge(sv_sig_valid)}")
    print(f"  Purchaser sig     : {_sig_badge(purchaser_sig_valid)}")
    print("=" * W)

    # 7. Determine whether to process
    sigs_ok     = sv_sig_valid and purchaser_sig_valid
    approved    = inner["supervisor_decision"] == "APPROVED"

    if not approved:
        print("\n  This order was REJECTED by the Supervisor.")
        print("  No further action will be taken.\n")
        mark_order_processed(order_id)
        log_action("Department", "RECEIVED_REJECTED_ORDER", order_id,
                   f"Supervisor decision: {inner['supervisor_decision']}")
        print_audit_log()
        return

    if not sigs_ok:
        print("\n  [SECURITY ALERT] One or more digital signatures are INVALID.")
        print("  The order cannot be processed — possible forgery or tampering.\n")
        mark_order_processed(order_id)
        log_action("Department", "PROCESS_BLOCKED_INVALID_SIG", order_id)
        print_audit_log()
        return

    # 8. Both sigs valid, order approved — confirm processing
    print()
    confirm = input("  Both signatures valid. Process this order? [y/N]: ").strip().lower()
    if confirm != "y":
        print("\n  Order not processed (user cancelled).\n")
        return

    # 9. Mark processed + log
    mark_order_processed(order_id)
    log_action(
        actor="Department",
        action="ORDER_PROCESSED",
        order_id=order_id,
        details=f"Item: {order['item']}, Qty: {order['quantity']}, "
                f"Total: CAD ${order['total_price']:.2f}, Supplier: {order['supplier']}"
    )

    print()
    print(f"  [OK] Order {order_id[:18]}... PROCESSED successfully.")
    print("  [OK] Order ID registered — replay attacks will be blocked.")
    print("  [OK] Action logged to audit database.\n")

    # 10. Print full audit trail
    print_audit_log()


if __name__ == "__main__":
    main()
