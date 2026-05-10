SECRET_PATTERNS = {

    "AWS Access Key":
        r"AKIA[0-9A-Z]{16}",

    "Google API Key":
        r"AIza[0-9A-Za-z\\-_]{35}",

    "Stripe Secret":
        r"sk_live_[0-9a-zA-Z]{24}",

    "JWT Token":
        r"eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9._-]*",
}

HTTP_PATTERN = r"http://[^\\s'\\\"]+"

FIREBASE_PATTERN = r"firebaseio\\.com"

WEAK_CRYPTO_PATTERNS = [

    "MD5",

    "SHA1",

    "AES/ECB"
]