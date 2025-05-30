import os
import pytest
from dotenv import load_dotenv

load_dotenv()

REQUIRED_KEYS = ["VT_API_KEY", "HYBRID_API_KEY"]

@pytest.fixture(scope="session", autouse=True)
def check_api_keys():
    missing = [k for k in REQUIRED_KEYS if not os.getenv(k)]
    if missing:
        pytest.exit(f"Missing required API keys in .env: {missing}", returncode=1)
