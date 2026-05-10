from fastapi import FastAPI

from app.core.config import settings
from app.api.router import api_router

import os

app = FastAPI(
    title="ReconX Backend",
    version="1.0.0"
)

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.EXTRACT_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)

app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "message": "ReconX Backend Running"
    }