from dotenv import load_dotenv
import os

load_dotenv()


class Settings:

    MONGO_URL = os.getenv("MONGO_URL")
    DATABASE_NAME = os.getenv("DATABASE_NAME")

    UPLOAD_DIR = os.getenv("UPLOAD_DIR")
    EXTRACT_DIR = os.getenv("EXTRACT_DIR")
    REPORT_DIR = os.getenv("REPORT_DIR")

    APKTOOL_PATH = os.getenv("APKTOOL_PATH")
    JADX_PATH = os.getenv("JADX_PATH")


settings = Settings()