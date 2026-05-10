from fastapi import APIRouter
from app.api.routes import upload, scan, results, reports,behavior_scan

api_router = APIRouter()

api_router.include_router(upload.router, tags=["Upload"])
api_router.include_router(scan.router, tags=["Scan"])
api_router.include_router(results.router, tags=["Results"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(behavior_scan.router, tags=["Behavior Scan"])
