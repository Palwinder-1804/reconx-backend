import subprocess
import os

from app.core.config import settings


def extract_apk(
    apk_path: str,
    scan_id: str
):

    # ==========================
    # Output Directories
    # ==========================

    apktool_output = os.path.join(

        settings.EXTRACT_DIR,

        scan_id,

        "apktool"
    )

    jadx_output = os.path.join(

        settings.EXTRACT_DIR,

        scan_id,

        "jadx"
    )

    # ==========================
    # Create Directories
    # ==========================

    os.makedirs(
        apktool_output,
        exist_ok=True
    )

    os.makedirs(
        jadx_output,
        exist_ok=True
    )

    # ==========================
    # APKTool Command
    # ==========================

    apktool_command = [

        settings.APKTOOL_PATH,

        "d",

        apk_path,

        "-o",

        apktool_output,

        "-f"
    ]

    # ==========================
    # Optimized JADX Command
    # ==========================

    jadx_command = [

        settings.JADX_PATH,

        "--no-res",

        "--no-imports",

        "--show-bad-code",

        "-d",

        jadx_output,

        apk_path
    ]

    try:

        print("Running APKTool...")

        subprocess.run(

            apktool_command,

            text=True
        )

        print("APKTool completed")

        print("Running JADX...")

        jadx_process = subprocess.run(

            jadx_command,

            text=True,

            capture_output=True
        )

        print(jadx_process.stdout)
        print(jadx_process.stderr)

        print("JADX completed")

        return {

            "success": True,

            "apktool_output":
                apktool_output,

            "jadx_output":
                jadx_output
        }

    except Exception as e:

        return {

            "success": False,

            "error": str(e)
        }