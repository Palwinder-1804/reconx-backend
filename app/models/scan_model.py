from datetime import datetime


def scan_document(
    scan_id: str,
    file_name: str,
    file_path: str
):

    return {

        "scan_id": scan_id,

        "file_name": file_name,

        "file_path": file_path,

        "status": "uploaded",

        "uploaded_at": datetime.utcnow(),

        "summary": {},

        "vulnerabilities": []
    }