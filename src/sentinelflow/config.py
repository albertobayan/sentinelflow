import os

from dotenv import load_dotenv


load_dotenv()


def get_virustotal_api_key() -> str | None:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return None

    return api_key


def get_abuseipdb_api_key() -> str | None:
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return None

    return api_key