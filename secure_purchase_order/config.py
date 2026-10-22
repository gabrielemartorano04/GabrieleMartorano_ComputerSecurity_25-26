from pathlib import Path

BASE_DIR    = Path(__file__).parent
KEYS_DIR    = BASE_DIR / "keys"
MESSAGES_DIR = BASE_DIR / "messages"
DB_PATH     = BASE_DIR / "audit.db"

KEYS_DIR.mkdir(exist_ok=True)
MESSAGES_DIR.mkdir(exist_ok=True)

# RSA key files
PURCHASER_PRIVATE  = KEYS_DIR / "purchaser_private.pem"
PURCHASER_PUBLIC   = KEYS_DIR / "purchaser_public.pem"
SUPERVISOR_PRIVATE = KEYS_DIR / "supervisor_private.pem"
SUPERVISOR_PUBLIC  = KEYS_DIR / "supervisor_public.pem"
DEPT_PRIVATE       = KEYS_DIR / "dept_private.pem"
DEPT_PUBLIC        = KEYS_DIR / "dept_public.pem"

# Message files (simulated transmission)
MSG_P2S = MESSAGES_DIR / "purchaser_to_supervisor.json"
MSG_S2D = MESSAGES_DIR / "supervisor_to_dept.json"

# Replay protection: max age of a message in seconds
REPLAY_WINDOW = 300  # 5 minutes
