import os

# Files that shouldn't be in a production APK or are suspicious
SUSPICIOUS_FILES = [
    "debug.keystore",
    "signing_key",
    "credentials.json",
    "google-services.json", # Usually fine but can contain sensitive data if not handled well
    "config.json",
    "env.local",
    ".env",
    "backup.sql",
    "database.db",
    "test_credentials",
    "temp_file",
    "log.txt",
    "development.log",
    "secret.txt",
    "private_key.pem",
    "id_rsa"
]

def scan_files_for_vulnerabilities(extracted_path):
    """
    Scans the extracted APK directory for suspicious or junk files.
    """
    findings = []
    
    for root, dirs, files in os.walk(extracted_path):
        for file in files:
            # Check for suspicious file names
            if any(suspicious in file.lower() for suspicious in SUSPICIOUS_FILES):
                findings.append({
                    "title": "Suspicious/Junk File Found",
                    "severity": "MEDIUM",
                    "description": f"Potential sensitive or development file found: {file}",
                    "file": os.path.join(root, file)
                })
            
            # Check for large log files (junk)
            if file.endswith(".log") or file.endswith(".txt"):
                file_path = os.path.join(root, file)
                if os.path.getsize(file_path) > 1024 * 1024: # 1MB
                    findings.append({
                        "title": "Large Log/Text File (Junk)",
                        "severity": "LOW",
                        "description": f"Large file detected which might be junk: {file} ({os.path.getsize(file_path)} bytes)",
                        "file": file_path
                    })

    return findings
