from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .config import CORS_ALLOW_ORIGINS
from .models import Role
from .audit import audit_mgr
from .seed_data import seed_workspaces_if_empty
from .routes import (
    auth_routes,
    red_team_routes,
    blue_team_routes,
    eval_routes,
    audit_routes,
    security_test_routes,
    canary_routes,
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"


# Initialize seed data on module load so test runners and servers have it
seed_workspaces_if_empty()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure seed data
    seed_workspaces_if_empty()
    # Log startup audit event
    audit_mgr.append_event(
        actor="system",
        role=Role.OPERATOR,
        event_type="system_startup",
        payload={
            "service": "Bayora Secure Adversarial Safety Testing Infrastructure",
            "version": "1.0.0",
            "ed25519_key_fingerprint": audit_mgr.get_public_key_fingerprint(),
        },
    )
    yield


app = FastAPI(
    title="Bayora API",
    description="Secure Adversarial AI Safety Testing Infrastructure - Hackathon MVP",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Bayora-Role", "X-Bayora-User"],
)

# Register API Routers
app.include_router(auth_routes.router)
app.include_router(red_team_routes.router)
app.include_router(blue_team_routes.router)
app.include_router(eval_routes.router)
app.include_router(audit_routes.router)
app.include_router(security_test_routes.router)
app.include_router(canary_routes.router)


@app.get("/health")
def health_check():
    """System health check (PR-8, PR-9: no secrets or internal tokens returned)."""
    return {
        "status": "healthy",
        "service": "Bayora Secure Adversarial AI Safety Infrastructure",
        "version": "1.0.0",
        "enforced_boundaries": [
            "red_team_storage_namespace",
            "blue_team_storage_namespace",
            "model_service_orchestrator_token_gate",
            "sha256_hash_linked_audit_chain",
            "ed25519_manifest_signatures",
            "cryptographic_hmac_bearer_tokens",
            "external_trust_anchor_checkpoints",
            "model_output_egress_sanitizer",
            "concurrency_resource_quotas",
            "scientific_repeatability_manifests",
        ],
    }


FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

# Serve original static frontend files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file)
        return {"message": "Bayora API running. Frontend index.html not yet placed."}

    @app.get("/favicon.ico", include_in_schema=False)
    def serve_favicon():
        fav_file = FRONTEND_DIR / "assets" / "logo.png"
        if fav_file.exists():
            return FileResponse(fav_file)
        return FileResponse(FRONTEND_DIR / "index.html")

