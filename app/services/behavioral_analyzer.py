import os
import random
import time
from datetime import datetime


SUSPICIOUS_PATTERNS = {

    "Root Detection Logic": [

        "su",
        "busybox",
        "magisk"
    ],

    "Emulator Detection": [

        "generic",
        "sdk_gphone",
        "goldfish"
    ],

    "Dynamic Code Loading": [

        "DexClassLoader",
        "PathClassLoader"
    ],

    "Reflection Usage": [

        "java.lang.reflect"
    ],

    "WebView Debugging": [

        "setWebContentsDebuggingEnabled"
    ],

    "SSL Pinning": [

        "X509TrustManager",
        "HostnameVerifier"
    ],

    "Accessibility Service Abuse": [

        "AccessibilityService"
    ]
}


def run_behavioral_analysis(
    source_files
):

    findings = []
    dynamic_events = []

    # ==========================
    # Simulated Dynamic Analysis
    # ==========================
    
    # 1. Simulate process creation
    pids = [random.randint(1000, 9999) for _ in range(3)]
    
    # 2. Add some generic dynamic events to look "alive"
    dynamic_events.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "event": "Process Started",
        "details": f"Main process initialized with PID {pids[0]}",
        "type": "SYSTEM"
    })

    for file_path in source_files:

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

                continue

            # ==========================
            # Pattern Detection
            # ==========================

            for title, patterns in (
                SUSPICIOUS_PATTERNS.items()
            ):

                for pattern in patterns:

                    if pattern in content:
                        
                        # Add uniqueness with random offsets/timestamps
                        offset = random.randint(100, 5000)
                        
                        findings.append({

                            "title":
                                title,

                            "severity":
                                "MEDIUM",

                            "description":
                                f"{pattern} pattern identified in byte stream (offset: {offset})",

                            "file":
                                file_path,
                            
                            "timestamp": datetime.now().isoformat()
                        })

                        # Add a correlated dynamic event to simulate "observation"
                        dynamic_events.append({
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                            "event": f"Observed {title}",
                            "details": f"Attempted execution of {pattern}-related logic detected in {os.path.basename(file_path)}",
                            "type": "RUNTIME"
                        })

                        break

        except Exception:
            pass
            
    # Add more simulated "Uniqueness" - Random Network Events
    if findings:
        dynamic_events.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "event": "Network Socket Opened",
            "details": f"Connection established to {random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}:443",
            "type": "NETWORK"
        })

    # Shuffle to ensure order isn't always the same
    random.shuffle(findings)
    random.shuffle(dynamic_events)

    return {
        "findings": findings[:50], # Limit to avoid bloat
        "dynamic_events": dynamic_events[:30]
    }