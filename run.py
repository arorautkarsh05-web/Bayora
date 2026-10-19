import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn

if __name__ == "__main__":
    host = os.getenv("BAYORA_HOST", "127.0.0.1")
    port = int(os.getenv("BAYORA_PORT", "8000"))
    print(f"\n=================================================================")
    print(f"  BAYORA — Secure Adversarial AI Safety Infrastructure (MVP v1.0)")
    print(f"=================================================================")
    print(f"  Reviewer Dashboard: http://{host}:{port}")
    print(f"  Interactive OpenAPI Docs: http://{host}:{port}/docs")
    print(f"  System Health Endpoint: http://{host}:{port}/health")
    print(f"=================================================================\n")
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)
