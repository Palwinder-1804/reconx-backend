import os

EXCLUDED_DIRECTORIES = {

    # Resources

    "layout",
    "drawable",
    "mipmap",
    "font",
    "anim",

    # SDKs

    "google",
    "androidx",
    "kotlin",
    "okhttp3",
    "retrofit2",
    "firebase",
    "com/google",
    "com/facebook"
}

EXCLUDED_PATH_PREFIXES = (
    os.path.join("com", "google"),
    os.path.join("com", "facebook"),
)


def get_source_files(
    source_path
):

    source_files = []

    for root, dirs, files in os.walk(
        source_path
    ):
        relative_root = os.path.relpath(
            root,
            source_path
        )

        if relative_root != "." and any(
            relative_root.startswith(prefix)
            for prefix in EXCLUDED_PATH_PREFIXES
        ):
            dirs[:] = []
            continue


        # ==========================
        # Skip Heavy Directories
        # ==========================

        dirs[:] = [

            d for d in dirs

            if d not in (
                EXCLUDED_DIRECTORIES
            )
        ]

        # ==========================
        # Collect Source Files
        # ==========================

        for file in files:

            if file.endswith((

                ".java",

                ".kt"
            )):

                source_files.append(

                    os.path.join(
                        root,
                        file
                    )
                )

    return source_files