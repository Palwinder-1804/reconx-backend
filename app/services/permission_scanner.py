from app.utils.dangerous_permissions import (
    DANGEROUS_PERMISSIONS
)

ANDROID_NS = (
    "{http://schemas.android.com/apk/res/android}"
)


def scan_permissions(
    manifest_root
):

    findings = []

    permissions = manifest_root.findall(
        "uses-permission"
    )

    for permission in permissions:

        permission_name = permission.get(
            ANDROID_NS + "name"
        )

        if permission_name in (
            DANGEROUS_PERMISSIONS
        ):

            findings.append({

                "title":
                    "Dangerous Permission",

                "severity":
                    "MEDIUM",

                "description":
                    f"{permission_name} detected"
            })

    return findings