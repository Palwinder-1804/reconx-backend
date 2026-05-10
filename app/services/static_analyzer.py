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

            content = file.read()

        # ==========================
        # Skip Huge Files
        # ==========================

        if len(content) > 2_000_000:

            return findings

        lower_content = content.lower()

        # ==========================
        # Secret Detection
        # ==========================

        for name, compiled_pattern in (

            COMPILED_SECRET_PATTERNS.items()
        ):

            matches = compiled_pattern.findall(
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

        # ==========================
        # HTTP URL Detection
        # ==========================

        http_matches = []
        if "http://" in lower_content:
            http_matches = (
                COMPILED_HTTP_PATTERN.findall(
                    content
                )
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

        # ==========================
        # Firebase Detection
        # ==========================

        firebase_matches = []
        if "firebaseio.com" in lower_content:
            firebase_matches = (

                COMPILED_FIREBASE_PATTERN.findall(
                    content
                )
            )

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

        # ==========================
        # Weak Crypto Detection
        # ==========================

        for crypto in (
            WEAK_CRYPTO_PATTERNS
        ):

            if crypto in content:

                findings.append({

                    "title":
                        "Weak Cryptography",

                    "severity":
                        "HIGH",

                    "description":
                        f"{crypto} detected",

                    "file":
                        file_path
                })

    except Exception:
        pass

    return findings