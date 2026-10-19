import os
import secrets
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

WORKSPACES_DIR = DATA_DIR / "workspaces"
RED_TEAM_DIR = WORKSPACES_DIR / "red_team"
BLUE_TEAM_DIR = WORKSPACES_DIR / "blue_team"
MODEL_DIR = WORKSPACES_DIR / "model"
AUDIT_DIR = DATA_DIR / "audit"
KEYS_DIR = DATA_DIR / "keys"
CANARIES_DIR = DATA_DIR / "canaries"
CHECKPOINTS_DIR = DATA_DIR / "checkpoints"

# Ensure directories exist with proper isolation
for directory in [RED_TEAM_DIR, BLUE_TEAM_DIR, MODEL_DIR, AUDIT_DIR, KEYS_DIR, CANARIES_DIR, CHECKPOINTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

AUDIT_LOG_FILE = AUDIT_DIR / "audit_chain.jsonl"
PRIVATE_KEY_FILE = KEYS_DIR / "ed25519_private.pem"
PUBLIC_KEY_FILE = KEYS_DIR / "ed25519_public.pem"
CHECKPOINT_LOG_FILE = CHECKPOINTS_DIR / "external_anchors.jsonl"

# Internal Model Secret: Ephemeral or Environment-driven (no static predictable default)
SECRET_FILE = KEYS_DIR / "orchestrator_internal.key"
if os.getenv("BAYORA_INTERNAL_SECRET"):
    ORCHESTRATOR_INTERNAL_SECRET = os.getenv("BAYORA_INTERNAL_SECRET")
elif SECRET_FILE.exists():
    ORCHESTRATOR_INTERNAL_SECRET = SECRET_FILE.read_text(encoding="utf-8").strip()
else:
    ORCHESTRATOR_INTERNAL_SECRET = f"bayora-sec-{secrets.token_urlsafe(32)}"
    try:
        SECRET_FILE.write_text(ORCHESTRATOR_INTERNAL_SECRET, encoding="utf-8")
    except Exception:
        pass

# Signed Bearer Authentication Secret
AUTH_TOKEN_SECRET = os.getenv("BAYORA_AUTH_SECRET", secrets.token_hex(32))

# Limits & Quotas
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_PAYLOAD_BYTES = 64 * 1024  # 64 KB
MAX_TEST_CASES_PER_RUN = 50
TEST_SET_VERSION = "2026.10-v1.0"
MAX_CONCURRENT_EVALS_PER_ROLE = 2
MAX_REQUESTS_PER_MINUTE = 120

# Strict Authentication Enforcement (Require signed bearer token; reject header fallback)
BAYORA_STRICT_AUTH = os.getenv("BAYORA_STRICT_AUTH", "false").strip().lower() in ("true", "1", "yes")

# Configurable CORS Allowed Origins
DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]
cors_env = os.getenv("BAYORA_CORS_ORIGINS")
if cors_env:
    CORS_ALLOW_ORIGINS = [orig.strip() for orig in cors_env.split(",") if orig.strip()]
else:
    CORS_ALLOW_ORIGINS = DEFAULT_CORS_ORIGINS

# Runtime Environment Fingerprint
RUNTIME_PLATFORM = {
    "system": platform.system(),
    "release": platform.release(),
    "machine": platform.machine(),
    "python_version": platform.python_version(),
    "processor": platform.processor(),
}


