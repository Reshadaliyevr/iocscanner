import os
import pytest
from clients.virustotal import VirusTotalClient

@pytest.fixture
def vt():
    return VirusTotalClient(api_key=os.getenv("VT_API_KEY"))

def test_upload_eicar(vt, tmp_path):
    # Create fake EICAR file
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    file_path = tmp_path / "eicar.com"
    file_path.write_bytes(eicar)

    result = vt.upload_file(str(file_path))
    assert "data" in result
    print(result)
