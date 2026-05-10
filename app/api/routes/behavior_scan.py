from fastapi import APIRouter, HTTPException
import os

from app.core.database import database
from app.services.code_scanner import get_source_files
from app.services.behavioral_analyzer import run_behavioral_analysis

router = APIRouter()

@router.post("/dynamic-scan/{scan_id}")
async def start_dynamic_scan(scan_id: str):
    scan = await database.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    if "jadx_output" not in scan:
        raise HTTPException(status_code=400, detail="Static scan has not been completed. JADX output missing.")

    source_path = os.path.join(scan["jadx_output"], "sources")
    if not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source path not found")
        
    source_files = get_source_files(source_path)
    
    # Run dynamic / behavioral analysis
    analysis_result = run_behavioral_analysis(source_files)
    
    new_findings = analysis_result["findings"]
    dynamic_events = analysis_result["dynamic_events"]
    
    for finding in new_findings:
        finding["source"] = "DYNAMIC"
        
    # Append to existing vulnerabilities
    existing_vulnerabilities = scan.get("vulnerabilities", [])
    updated_vulnerabilities = existing_vulnerabilities + new_findings
    
    # Recalculate summary
    high_count = 0
    medium_count = 0
    low_count = 0
    for finding in updated_vulnerabilities:
        severity = finding.get("severity")
        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1
            
    summary = {
        "total": len(updated_vulnerabilities),
        "high": high_count,
        "medium": medium_count,
        "low": low_count
    }
    
    await database.scans.update_one(
        {"scan_id": scan_id},
        {
            "$set": {
                "vulnerabilities": updated_vulnerabilities,
                "summary": summary,
                "dynamic_events": dynamic_events,
                "has_dynamic": True
            }
        }
    )
    
    return {
        "message": "Dynamic scan completed",
        "scan_id": scan_id,
        "file_name": scan.get("file_name", "unknown.apk"),
        "status": "completed",
        "summary": summary,
        "total_vulnerabilities": len(updated_vulnerabilities),
        "vulnerabilities": updated_vulnerabilities,
        "dynamic_events": dynamic_events
    }