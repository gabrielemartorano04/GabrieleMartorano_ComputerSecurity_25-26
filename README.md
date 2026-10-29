# 🔐 Secure Purchase Order System

This project implements a Secure Purchase Order System in Python to safely process and manage commercial transactions, ensuring the core tenets of information security: **Confidentiality**, **Integrity**, and **Authenticity**. 

The project was developed for the *Software Security (SOFE4840U)* course, demonstrating the practical application of a hybrid cryptographic architecture that combines AES-256-CBC for symmetric encryption, RSA-2048 for key exchange, and digital signatures.

* **University:** Ontario Tech University — Canada
* **Course:** Software Security (SOFE4840U)
* **Professor:** Prof. Khalid Abdel Hafeez
* **Authors:** Emmanuel Eme, Gabriele Martorano and Victor Oladeinde 

---

## 🎯 What this project does

This system simulates a secure, three-role workflow (Purchaser, Supervisor, and Department) where data is safely transmitted between parties. To achieve this, it relies on a robust set of cryptographic primitives:

| Protocol        | Purpose                                    |
|-----------------|--------------------------------------------|
| **RSA-2048**    | Key pairs generation for each role         |
| **SHA-256**     | Payload hashing (tamper detection)         |
| **RSA-PSS**     | Digital signatures (auth + non-repudiation)|
| **AES-256-CBC** | Symmetric encryption of payloads           |
| **RSA-OAEP**    | Wrapping the AES session key               |
| **UUID + Time** | Replay-attack prevention                   |
| **SQLite**      | Immutable audit logging                    |

---

## 📂 Project Structure

The repository is built with a modular architecture, separating cryptographic operations and database management from the user interface scripts.

```text
secure_purchase_order/
├── setup.py              ← Run ONCE to generate keys
├── purchaser.py          ← Terminal 1 (Initiates order)
├── supervisor.py         ← Terminal 2 (Approves/Rejects)
├── department.py         ← Terminal 3 (Processes & Logs)
├── crypto_utils.py       ← Core cryptographic operations
├── db_logger.py          ← SQLite audit log + replay protection
├── config.py             ← Paths and constants
├── requirements.txt      ← Project dependencies
├── keys/                 ← Created by setup.py (6 PEM files)
├── messages/             ← Simulated network transmission (JSON files)
└── audit.db              ← Created automatically on the first run
```

---

## 🚀 Getting Started (Setup)

Follow these steps to set up the environment on your local machine. These steps only need to be performed once.

### 1. Check Python versionù

Make sure you have Python 3.10 or newer installed.

```bash
python --version
```

### 2. Create a virtual environment (Recommended)

It is highly recommended to run this project inside an isolated virtual environment.

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

Install the required cryptography library.

```bash
pip install -r requirements.txt
```

### 4. Generate RSA key pairs

Run the setup script to initialize the environment and generate the public/private key pairs for all three roles.

```bash
python setup.py
```
> **Note:** You should see 6 `.pem` files written to the `keys/` directory. **Do this only once.** Re-running it will replace all existing keys and invalidate previous messages.

---

## 💻 Usage (Running the Demo)

To simulate the network nodes, open three separate terminal windows on the same machine. Make sure you are in the project folder and your virtual environment is activated in all of them.

### Terminal 1 — Purchaser

Initiates the purchase order, signs it, and encrypts it for the Supervisor.

```bash
python purchaser.py
```

- Enter the order details when prompted.
- Confirm with `y` to sign and encrypt.
- *Output:* The encrypted file is written to `messages/purchaser_to_supervisor.json`.

### Terminal 2 — Supervisor

Acts as the middleman. Verifies the Purchaser, makes a decision, and securely forwards it.

```bash
python supervisor.py
```

- Reads and decrypts the purchaser's message.
- Shows you the full order + signature status.
- Enter `A` (Approve) or `R` (Reject).
- Adds supervisor signature and re-encrypts the payload for the Department.
- *Output:* `messages/supervisor_to_dept.json`.

### Terminal 3 — Department

The final endpoint. Validates all signatures, checks for replay attacks, and logs the transaction.

```bash
python department.py
```

- Reads and decrypts the Supervisor's message.
- Independently re-verifies *BOTH* signatures (Purchaser and Supervisor).
- Performs replay-attack check using UUIDs.
- Shows the full order and both signature statuses.
- Confirm with `y` to process
- Prints the complete audit log from the SQLite database.

---

## 🛡️ Security Testing & Scenarios

You can test the system's resilience against common cyber threats by simulating the following scenarios:
- **Normal Happy Path:** Run all three terminals in order. Both signatures verify, and the order processes successfully.
- **Tamper Attack (Integrity loss):** After running `purchaser.py`, open `messages/purchaser_to_supervisor.json` in a text editor and change a single character in the encrypted_payload. Run `supervisor.py` — it will immediately catch the SHA-256 hash mismatch and drop the message.
- **Forgery Attempt (Authentication failure):** Comment out the signing line in `purchaser.py` and replace the signature with a random Base64 string. The Supervisor will reject it and display `[INVALID ✗]`.
- **Replay Attack:** Run the full flow once successfully. Then, run `department.py` again without generating a new order. The Department will detect the already-processed `order_id` in the database and block the execution.
- **Rejection Flow:** At the Supervisor prompt, enter `R` instead of `A`. The Department will securely receive the message, verify the signatures, see the `REJECTED` status, and take no further action.

---

## 🏗️ Security Architecture Flow

The following diagram illustrates the cryptographic pipeline from the Purchaser to the Department:

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

## 📄 Academic Report Mapping

For evaluation purposes, here is how the codebase maps to the final project report:

| Report Section                | Files                                      |
|-------------------------------|--------------------------------------------|
| Introduction / Background     | This README                                |
| Architecture Diagram          | Provided in the report docs                |
| Security Protocols Used       | `crypto_utils.py` and Features Table above |
| Threat model                  | Phase 1 document (Section 7)               |
| Results / Screenshots         | Output generated by the 3 terminal scripts |
| Source code appendix          | All `.py` files in the repository          |

---

## 🛠️ Troubleshooting

| Problem                              | Fix                                              |
|--------------------------------------|--------------------------------------------------|
| `ModuleNotFoundError: cryptography`  | Run `pip install -r requirements.txt`            |
| `Key files not found`                | Run `python setup.py`                            |
| `No message found from Purchaser`    | You must run `purchaser.py` first                |
| `No message found from Supervisor`   | You must run `supervisor.py` first               |
| Timestamp replay rejection           | Order is >5 min old. Re-run `purchaser.py`       |
| Replay blocked at Department         | Order already processed. Re-run `purchaser.py`   |
