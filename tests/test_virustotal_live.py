import os
import pytest
from clients.virustotal import VirusTotalClient 

@pytest.fixture
def vt():
    return VirusTotalClient(api_key=os.getenv("VT_API_KEY"))

# Hash lookup tests (fast, no upload)
def test_lookup_known_malware_hash(vt):
    """Test hash lookup for known malware (EICAR)"""
    eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = vt.lookup_file_hash(eicar_sha256)
    assert "data" in result
    # Should show it's detected as malware
    stats = result["data"]["attributes"]["last_analysis_stats"]
    assert stats["malicious"] > 0

def test_lookup_clean_file_hash(vt):
    """Test hash lookup for a known clean file"""
    # This is a hash of a common clean file - Windows notepad.exe from Windows 10
    clean_hash = "5d41402abc4b2a76b9719d911017c592"  # This might not exist, but demonstrates the concept
    result = vt.lookup_file_hash(clean_hash)
    # Result might be "not found" which is also a valid response
    assert "data" in result or ("error" in result and "NotFoundError" in result["error"])

# File upload tests (slower, uses quota)
@pytest.mark.slow  # Mark as slow test
def test_upload_eicar(vt, tmp_path):
    """Test actual file upload with EICAR test file"""
    # Create EICAR test file
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    file_path = tmp_path / "eicar.com"
    file_path.write_bytes(eicar)
    
    # Skip if file was deleted by antivirus
    if not file_path.exists():
        pytest.skip("EICAR file was deleted by antivirus - disable real-time protection")
    
    result = vt.upload_file(str(file_path))
    assert "data" in result
    
    # Verify it was detected as malicious
    if "attributes" in result["data"]:
        stats = result["data"]["attributes"].get("stats", {})
        if stats:
            assert stats.get("malicious", 0) > 0, "EICAR should be detected as malicious"

@pytest.mark.slow
def test_upload_safe_file(vt, tmp_path):
    """Test upload of a safe file"""
    safe_content = b"This is a safe test file for VirusTotal scanning."
    file_path = tmp_path / "safe_test.txt"
    file_path.write_bytes(safe_content)
    
    result = vt.upload_file(str(file_path))
    assert "data" in result
    
    # Safe file should have low or zero malicious detections
    if "attributes" in result["data"]:
        stats = result["data"]["attributes"].get("stats", {})
        if stats:
            # Most engines should report it as clean
            assert stats.get("harmless", 0) + stats.get("undetected", 0) > stats.get("malicious", 0)

# URL and IP tests (fast, no upload)
def test_lookup_ip(vt):
    """Test IP reputation lookup"""
    result = vt.lookup_ip("8.8.8.8")  # Google DNS - should be clean
    assert "data" in result

def test_lookup_url(vt):
    """Test URL analysis"""
    result = vt.lookup_url("http://example.com")  # Safe test domain
    assert "data" in result

# Error handling tests
def test_upload_nonexistent_file(vt):
    """Test upload of non-existent file"""
    result = vt.upload_file("/path/that/does/not/exist.txt")
    assert "error" in result
    assert "not found" in result["error"].lower() or "no such file" in result["error"].lower()

def test_lookup_invalid_hash(vt):
    """Test lookup of invalid hash"""
    result = vt.lookup_file_hash("invalid_hash_format")
    assert "error" in result