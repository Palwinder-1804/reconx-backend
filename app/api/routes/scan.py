from fastapi import (
    APIRouter,
    HTTPException
)

from app.core.database import (
    database
)

from app.services.apk_extractor import (
    extract_apk
)

from app.services.manifest_parser import (
    parse_manifest
)

from app.services.permission_scanner import (
    scan_permissions
)

from app.services.vulnerability_engine import (
    analyze_manifest_security
)

from app.services.code_scanner import (
    get_source_files
)

from app.services.static_analyzer import (
    analyze_file
)

import os
from concurrent.futures import ThreadPoolExecutor

router = APIRouter()


@router.post("/scan/{scan_id}")
async def start_scan(
    scan_id: str
):

    # ==========================
    # Find Scan
    # ==========================

    scan = await database.scans.find_one(
        {"scan_id": scan_id}
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # ==========================
    # Update Status
    # ==========================

    await database.scans.update_one(
        {"scan_id": scan_id},
        {
            "$set": {
                "status": "scanning"
            }
        }
    )

    # ==========================
    # APK Extraction
    # ==========================

    extraction_result = extract_apk(
        apk_path=scan["file_path"],
        scan_id=scan_id
    )

    # ==========================
    # Extraction Failed
    # ==========================

    if not extraction_result["success"]:

        await database.scans.update_one(
            {"scan_id": scan_id},
            {
                "$set": {
                    "status": "failed",
                    "error":
                        extraction_result["error"]
                }
            }
        )

        raise HTTPException(
            status_code=500,
            detail=extraction_result["error"]
        )

    # ==========================
    # Manifest Analysis
    # ==========================

    manifest_path = os.path.join(

        extraction_result[
            "apktool_output"
        ],

        "AndroidManifest.xml"
    )

    manifest_root = parse_manifest(
        manifest_path
    )

    findings = []

    if manifest_root:

        findings.extend(

            scan_permissions(
                manifest_root
            )
        )

        findings.extend(

            analyze_manifest_security(
                manifest_root
            )
        )

    # ==========================
    # Static Code Analysis
    # ==========================

    source_path = os.path.join(

    extraction_result["jadx_output"],

    "sources"
    )

    source_files = get_source_files(
        source_path
    )

    max_workers = min(
        8,
        max(
            1,
            (os.cpu_count() or 1)
        )
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        for file_findings in executor.map(
            analyze_file,
            source_files
        ):
            findings.extend(
                file_findings
            )

    # ==========================
    # Remove Duplicate Findings
    # ==========================

    unique_findings = []

    seen = set()

    for finding in findings:

        key = (

            finding["title"],

            finding["description"],

            finding.get("file", "")
        )

        if key not in seen:

            seen.add(key)

            unique_findings.append(
                finding
            )

    findings = unique_findings

    # ==========================
    # Severity Summary
    # ==========================

    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:
        severity = finding.get(
            "severity"
        )
        if severity == "HIGH":
            high_count += 1
        elif severity == "MEDIUM":
            medium_count += 1
        elif severity == "LOW":
            low_count += 1

    summary = {
        "total": len(findings),
        "high": high_count,
        "medium": medium_count,
        "low": low_count
    }

    # ==========================
    # Save Results
    # ==========================

    await database.scans.update_one(
        {"scan_id": scan_id},
        {
            "$set": {

                "status":
                    "completed",

                "apktool_output":
                    extraction_result[
                        "apktool_output"
                    ],

                "jadx_output":
                    extraction_result[
                        "jadx_output"
                    ],

                "summary":
                    summary,

                "vulnerabilities":
                    findings
            }
        }
    )

    return {

        "message":
            "Scan completed",

        "scan_id":
            scan_id,

        "file_name":
            scan.get("file_name", "unknown.apk"),

        "status":
            "completed",

        "summary":
            summary,

        "total_vulnerabilities":
            len(findings),

        "vulnerabilities":
            findings
    }