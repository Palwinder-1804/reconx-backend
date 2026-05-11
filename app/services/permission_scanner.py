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

    permission_names = []
    for permission in permissions:

        permission_name = permission.get(
            ANDROID_NS + "name"
        )
        if permission_name:
            permission_names.append(permission_name)

        if permission_name in (
            DANGEROUS_PERMISSIONS
        ):

            findings.append({

                "title":
                    "Dangerous Permission",

                "severity":
                    "MEDIUM",

                "description":
                    f"{permission_name} is a dangerous permission that should be carefully reviewed."
            })

    return findings, permission_names


def check_unnecessary_permissions(permissions, all_code_content):
    """
    Checks if declared permissions are actually used in the code.
    Simple heuristic based on keyword matching in decompiled source.
    """
    unnecessary = []
    
    # Mapping of permissions to keywords that suggest usage
    USAGE_KEYWORDS = {
        "android.permission.READ_CONTACTS": ["ContactsContract", "getContacts", "Contacts"],
        "android.permission.WRITE_CONTACTS": ["ContactsContract", "insert", "update"],
        "android.permission.ACCESS_FINE_LOCATION": ["LocationManager", "getLastKnownLocation", "requestLocationUpdates", "FusedLocationProviderClient"],
        "android.permission.ACCESS_COARSE_LOCATION": ["LocationManager", "getLastKnownLocation"],
        "android.permission.CAMERA": ["Camera", "CameraDevice", "SurfaceView", "TextureView", "camera2"],
        "android.permission.RECORD_AUDIO": ["AudioRecord", "MediaRecorder", "AudioSource"],
        "android.permission.READ_SMS": ["Telephony", "SmsMessage", "sms"],
        "android.permission.SEND_SMS": ["SmsManager", "sendTextMessage"],
        "android.permission.READ_PHONE_STATE": ["getDeviceId", "getSubscriberId", "getLine1Number", "TelephonyManager"],
        "android.permission.CALL_PHONE": ["ACTION_CALL", "tel:"],
        "android.permission.READ_EXTERNAL_STORAGE": ["getExternalStorageDirectory", "MediaStore", "FileInputStream"],
        "android.permission.WRITE_EXTERNAL_STORAGE": ["getExternalStorageDirectory", "FileOutputStream"],
        "android.permission.GET_ACCOUNTS": ["AccountManager", "getAccounts"],
    }

    for perm in permissions:
        if perm in USAGE_KEYWORDS:
            keywords = USAGE_KEYWORDS[perm]
            used = False
            for kw in keywords:
                if kw in all_code_content:
                    used = True
                    break
            
            if not used:
                unnecessary.append({
                    "title": "Potentially Unnecessary Permission",
                    "severity": "LOW",
                    "description": f"The app requests {perm} but no common usage patterns were found in the code.",
                    "file": "AndroidManifest.xml"
                })
    
    return unnecessary