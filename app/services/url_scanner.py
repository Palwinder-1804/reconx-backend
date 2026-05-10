import re

from app.utils.regex_patterns import (
    HTTP_PATTERN,
    FIREBASE_PATTERN
)


def scan_urls(file_path):

    findings = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

            http_matches = re.findall(
                HTTP_PATTERN,
                content
            )

            firebase_matches = re.findall(
                FIREBASE_PATTERN,
                content
            )

            if http_matches:

                findings.append({
                    "title":
                        "Insecure HTTP URL",

                    "severity":
                        "HIGH",

                    "description":
                        "HTTP communication detected",

                    "file":
                        file_path
                })

            if firebase_matches:

                findings.append({
                    "title":
                        "Firebase URL Found",

                    "severity":
                        "MEDIUM",

                    "description":
                        "Firebase endpoint detected",

                    "file":
                        file_path
                })

    except Exception:
        pass

    return findings