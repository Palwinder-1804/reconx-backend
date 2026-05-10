import re

from app.utils.regex_patterns import (
    SECRET_PATTERNS
)


def scan_secrets(file_path):

    findings = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

            for name, pattern in (
                SECRET_PATTERNS.items()
            ):

                matches = re.findall(
                    pattern,
                    content
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
                            file_path
                    })

    except Exception:
        pass

    return findings