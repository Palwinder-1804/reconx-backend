from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException
)

from app.core.config import settings
from app.core.database import database

from app.models.scan_model import (
    scan_document
)

from app.schemas.scan_schema import (
    ScanResponse
)

from app.utils.file_utils import (
    generate_scan_id,
    generate_file_path
)

import aiofiles

router = APIRouter()


@router.post(
    "/upload",
    response_model=ScanResponse
)
async def upload_apk(
    file: UploadFile = File(...)
):

    # Validate APK

    if not file.filename.endswith(".apk"):

        raise HTTPException(
            status_code=400,
            detail="Only APK files are allowed"
        )

    # Generate scan ID

    scan_id = generate_scan_id()

    # Generate file path

    file_path = generate_file_path(
        settings.UPLOAD_DIR,
        file.filename
    )

    # Save APK file

    async with aiofiles.open(
        file_path,
        "wb"
    ) as out_file:

        while chunk := await file.read(
            1024 * 1024
        ):

            await out_file.write(chunk)

    # Create DB document

    scan_data = scan_document(
        scan_id=scan_id,
        file_name=file.filename,
        file_path=file_path
    )

    # Save to MongoDB

    await database.scans.insert_one(
        scan_data
    )

    # Return response

    return ScanResponse(
        scan_id=scan_id,
        file_name=file.filename,
        status="uploaded",
        uploaded_at=scan_data[
            "uploaded_at"
        ]
    )