from fastapi import (
    APIRouter,
    HTTPException
)

from app.core.database import (
    database
)

from app.utils.file_utils import (
    cleanup_scan_data
)

router = APIRouter()


@router.get("/scan/{scan_id}")
async def get_scan(
    scan_id: str
):

    scan = await database.scans.find_one(
        {"scan_id": scan_id},
        {"_id": 0}
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return scan


@router.get("/scans")
async def get_all_scans():

    scans = []

    cursor = database.scans.find(
        {},
        {"_id": 0}
    )

    async for scan in cursor:

        scans.append(scan)

    return {

        "total_scans": len(scans),

        "scans": scans
    }


@router.delete("/scan/{scan_id}")
async def delete_scan(
    scan_id: str
):
    # Get scan to find file path before deleting
    scan = await database.scans.find_one({"scan_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # Perform cleanup of files
    cleanup_scan_data(scan_id, scan.get("file_path"))

    # Delete from database
    result = await database.scans.delete_one(
        {"scan_id": scan_id}
    )

    return {
        "message": "Scan and associated files deleted"
    }