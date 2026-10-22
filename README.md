# Secure Purchase Order System
SOFE4840U – Group 12 | Emmanuel Eme · Victor Oladeinde · Gabriele Martorano

---

## What this project does

Simulates a three-role secure purchase order workflow using:

| Protocol        | Purpose                                    |
|-----------------|--------------------------------------------|
| RSA-2048        | Key pairs for each role                    |
| SHA-256         | Payload hashing (tamper detection)         |
| RSA-PSS         | Digital signatures (auth + non-repudiation)|
| AES-256-CBC     | Symmetric encryption of payloads           |
| RSA-OAEP        | Wrapping the AES session key               |
| UUID + timestamp| Replay-attack prevention                   |
| SQLite          | Audit log                                  |

---

## Project structure

```
secure_purchase_order/
├── setup.py              ← Run ONCE to generate keys
├── purchaser.py          ← Terminal 1
├── supervisor.py         ← Terminal 2
├── department.py         ← Terminal 3
├── crypto_utils.py       ← All cryptographic operations
├── db_logger.py          ← SQLite audit log + replay protection
├── config.py             ← Paths and constants
├── requirements.txt
├── keys/                 ← Created by setup.py  (6 PEM files)
├── messages/             ← Simulated transmission  (JSON files)
└── audit.db              ← Created on first run
```

---

## Setup (do this once)

### 1. Make sure you have Python 3.10+

```bash
python --version
```

### 2. Create a virtual environment (recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install the only dependency

```bash
pip install -r requirements.txt
```

### 4. Generate RSA key pairs

```bash
python setup.py
```

You should see 6 `.pem` files written to `keys/`.  
**Do this only once.**  Re-running it replaces all keys.

---

## Running the demo  (3 terminals, same machine)

Open three terminal windows, all `cd`'d into the project folder.

### Terminal 1 — Purchaser

```bash
python purchaser.py
```

- Enter the order details when prompted
- Confirm with `y` to sign and encrypt
- The encrypted file is written to `messages/purchaser_to_supervisor.json`

### Terminal 2 — Supervisor

```bash
python supervisor.py
```

- Reads and decrypts the purchaser's message
- Shows you the full order + signature status
- Enter `A` (Approve) or `R` (Reject)
- Adds supervisor signature and re-encrypts for the Department
- Output: `messages/supervisor_to_dept.json`

### Terminal 3 — Department

```bash
python department.py
```

- Reads and decrypts the supervisor's message
- Independently re-verifies BOTH signatures
- Performs replay-attack check
- Shows the full order and both signature statuses
- Confirm with `y` to process
- Prints the complete audit log

---

## Demo scenarios for the presentation

### Normal happy path
Run all three terminals in order. Both signatures verify. Order processes.

### Tamper attack
After running `purchaser.py`, open `messages/purchaser_to_supervisor.json`
in a text editor and change one character in `encrypted_payload`.
Then run `supervisor.py` — it will catch the SHA-256 hash mismatch.

### Forgery attempt
Comment out the signing line in `purchaser.py` and replace the signature
with a random base64 string. The supervisor will display `[INVALID ✗]`.

### Replay attack
Run the full flow once (all three terminals).
Then run `department.py` again without running the purchaser or supervisor.
The Department will detect the already-processed order_id and block it.

### Rejection flow
At the Supervisor prompt, enter `R` instead of `A`.
The Department receives the message, sees `REJECTED`, and takes no action.

---

## Security protocols — quick reference

```
Purchaser                         Supervisor                   Department
─────────                         ──────────                   ──────────
order JSON
  │
  ├─ SHA-256 hash ─────────────────────────────────────────────────────► verify hash
  │
  ├─ RSA-PSS sign (purchaser key) ─────────────────────────────────────► verify sig
  │
  ├─ AES-256-CBC encrypt ──────────────────────► AES decrypt
  │
  └─ RSA-OAEP wrap key (supervisor pubkey) ────► RSA-OAEP unwrap
                                                       │
                                               (approve / reject)
                                                       │
                                               ┌───────┴──────────┐
                                               │ inner payload:   │
                                               │  • original order│
                                               │  • purchaser sig │
                                               │  • sv decision   │
                                               └───────┬──────────┘
                                                       │
                                               RSA-PSS sign (sv key) ──► verify sv sig
                                               AES-256-CBC encrypt ─────► AES decrypt
                                               RSA-OAEP wrap (dept key) ► RSA unwrap
                                                                          re-verify purchaser sig
                                                                          replay check (UUID)
                                                                          audit log
```

---

## Report section mapping

| Report Section                | Files                                      |
|-------------------------------|--------------------------------------------|
| Introduction / background     | This README                                |
| Architecture diagram          | Diagram in the report (module descriptions)|
| Security protocols used       | `crypto_utils.py` + table above            |
| Threat model                  | Phase 1 document (Section 7)               |
| Results / screenshots         | Run the demo and screenshot each terminal  |
| Source code appendix          | All `.py` files                            |

---

## Troubleshooting

| Problem                              | Fix                                              |
|--------------------------------------|--------------------------------------------------|
| `ModuleNotFoundError: cryptography`  | `pip install -r requirements.txt`                |
| `Key files not found`                | `python setup.py`                                |
| `No message found from Purchaser`    | Run `purchaser.py` first                         |
| `No message found from Supervisor`   | Run `supervisor.py` first                        |
| Timestamp replay rejection           | Order is >5 min old — re-run `purchaser.py`      |
| Replay blocked at Department         | Same order already processed — re-run purchaser  |
