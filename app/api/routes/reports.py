from fastapi import (
    APIRouter,
    HTTPException
)

from app.core.database import (
    database
)

from app.services.risk_engine import (
    calculate_risk
)

from app.services.recommendation_engine import (
    generate_recommendations
)

router = APIRouter()


@router.get("/report/{scan_id}")
async def generate_report(
    scan_id: str
):

    # ==========================
    # Find Scan
    # ==========================

    scan = await database.scans.find_one(
        {"scan_id": scan_id},
        {"_id": 0}
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # ==========================
    # Validate Scan Status
    # ==========================

    if scan["status"] != "completed":

        raise HTTPException(
            status_code=400,
            detail="Scan not completed yet"
        )

    # ==========================
    # Risk Calculation
    # ==========================

    risk = calculate_risk(
        scan["summary"]
    )

    # ==========================
    # Recommendations
    # ==========================

    recommendations = (
        generate_recommendations(
            scan["vulnerabilities"]
        )
    )

    # ==========================
    # Executive Summary
    # ==========================

    executive_summary = f"""
    The scanned APK contains
    {scan['summary']['total']} vulnerabilities.
    The application has a
    {risk['risk_level']} security risk level.
    """

    return {
        "scan_id": scan["scan_id"],
        "file_name": scan.get("file_name", "unknown.apk"),
        "status": scan["status"],
        "uploaded_at": scan.get("uploaded_at"),
        "overall_risk": risk["risk_level"],
        "scan_summary": executive_summary.strip(),
        "summary": scan["summary"],
        "vulnerabilities": scan["vulnerabilities"]
    }