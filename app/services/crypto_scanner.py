from app.utils.regex_patterns import (
    WEAK_CRYPTO_PATTERNS
)


def scan_crypto(file_path):

    findings = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            content = file.read()

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