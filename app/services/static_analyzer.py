import re

from app.utils.regex_patterns import (

    SECRET_PATTERNS,

    HTTP_PATTERN,

    FIREBASE_PATTERN,

    WEAK_CRYPTO_PATTERNS
)

# ==========================
# Compile Regex Once
# ==========================

COMPILED_SECRET_PATTERNS = {

    name: re.compile(pattern)

    for name, pattern in (
        SECRET_PATTERNS.items()
    )
}

COMPILED_HTTP_PATTERN = re.compile(
    HTTP_PATTERN
)

COMPILED_FIREBASE_PATTERN = re.compile(
    FIREBASE_PATTERN
)


def analyze_file(
    file_path
):

    findings = []

    try:

        with open(

            file_path,

            "r",

            encoding="utf-8",

            errors="ignore"

        ) as file:

            lines = file.readlines()

        content = "".join(lines)

        # ==========================
        # Skip Huge Files
        # ==========================

        if len(content) > 2_000_000:

            return findings

        # ==========================
        # Secret Detection
        # ==========================

        for name, compiled_pattern in (

            COMPILED_SECRET_PATTERNS.items()
        ):

            for i, line in enumerate(lines):
                matches = compiled_pattern.findall(
                    line
                )

                if matches:

                    findings.append({

                        "title":
                            "Hardcoded Secret",

                        "severity":
                            "HIGH",

                        "description":
                            f"{name} detected",

                        "file":
                            file_path,
                        
                        "line": i + 1,
                        "snippet": line.strip()
                    })

        # ==========================
        # HTTP URL Detection
        # ==========================

        for i, line in enumerate(lines):
            if "http://" in line.lower():
                matches = COMPILED_HTTP_PATTERN.findall(line)
                if matches:
                    findings.append({
                        "title": "Insecure HTTP URL",
                        "severity": "HIGH",
                        "description": "HTTP communication detected",
                        "file": file_path,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

        # ==========================
        # Firebase Detection
        # ==========================

        for i, line in enumerate(lines):
            if "firebaseio.com" in line.lower():
                matches = COMPILED_FIREBASE_PATTERN.findall(line)
                if matches:
                    findings.append({
                        "title": "Firebase URL Found",
                        "severity": "MEDIUM",
                        "description": "Firebase endpoint detected",
                        "file": file_path,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

        # ==========================
        # Weak Crypto Detection
        # ==========================

        for crypto in (
            WEAK_CRYPTO_PATTERNS
        ):
            for i, line in enumerate(lines):
                if crypto in line:
                    findings.append({
                        "title": "Weak Cryptography",
                        "severity": "HIGH",
                        "description": f"{crypto} detected",
                        "file": file_path,
                        "line": i + 1,
                        "snippet": line.strip()
                    })

    except Exception:
        pass

    return findings