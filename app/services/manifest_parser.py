import os
import xml.etree.ElementTree as ET


def parse_manifest(
    manifest_path: str
):

    if not os.path.exists(
        manifest_path
    ):

        return None

    tree = ET.parse(
        manifest_path
    )

    root = tree.getroot()

    return root