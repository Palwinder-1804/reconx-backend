import uuid
import os
import shutil
from app.core.config import settings


def generate_scan_id():

    return str(uuid.uuid4())


def generate_file_path(
    upload_dir,
    filename
):

    unique_name = (
        f"{uuid.uuid4()}_{filename}"
    )

    return os.path.join(
        upload_dir,
        unique_name
    )


def cleanup_scan_data(scan_id: str, file_path: str = None):
    """
    Removes extracted data and optionally the original upload for a scan.
    """
    # 1. Cleanup Extracted Directory
    extract_path = os.path.join(settings.EXTRACT_DIR, scan_id)
    if os.path.exists(extract_path):
        try:
            shutil.rmtree(extract_path)
            print(f"Cleaned up extracted data for {scan_id}")
        except Exception as e:
            print(f"Error cleaning up extracted data: {e}")

    # 2. Cleanup Recon Zip Directory (if exists)
    recon_zip_path = os.path.join("recon_zip", scan_id)
    if os.path.exists(recon_zip_path):
        try:
            shutil.rmtree(recon_zip_path)
            print(f"Cleaned up recon zip for {scan_id}")
        except Exception as e:
            print(f"Error cleaning up recon zip: {e}")

    # 3. Optionally cleanup uploaded file
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            print(f"Removed uploaded file: {file_path}")
        except Exception as e:
            print(f"Error removing uploaded file: {e}")