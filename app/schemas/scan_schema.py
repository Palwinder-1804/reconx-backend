from pydantic import BaseModel
from datetime import datetime


class ScanResponse(BaseModel):

    scan_id: str
    file_name: str
    status: str
    uploaded_at: datetime