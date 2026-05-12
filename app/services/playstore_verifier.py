import os
import xml.etree.ElementTree as ET

def verify_playstore_status(manifest_root, extracted_path):
    """
    Checks if the app has markers of being Play Store verified or follows standard play store patterns.
    Note: Real verification would require checking the signature against Google Play APIs.
    """
    
    is_verified = False
    reasons = []
    google_patterns = ["com.google.android.gms", "com.android.vending", "com.google.android.finsky", "com.google.firebase"]
    
    # Manifest markers
    meta_data = manifest_root.findall(".//meta-data")
    for meta in meta_data:
        name = meta.get("{http://schemas.android.com/apk/res/android}name")
        if name and any(p in name for p in google_patterns):
            is_verified = True
            reasons.append("Google Metadata Found")
            break

    # Signature markers
    paths = [os.path.join(extracted_path, "original", "META-INF"), os.path.join(extracted_path, "META-INF")]
    for p in paths:
        if os.path.exists(p):
            sig_files = [f for f in os.listdir(p) if f.endswith(".RSA") or f.endswith(".DSA") or f.endswith(".SF")]
            if sig_files:
                is_verified = True
                reasons.append("Official Signature Found")
                break

    return {
        "is_playstore_verified": is_verified,
        "verification_details": ", ".join(reasons) if reasons else "No official Play Store markers found"
    }