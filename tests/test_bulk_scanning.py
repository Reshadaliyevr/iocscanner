import pytest
from engine.processor import IOCProcessor

@pytest.fixture
def processor():
    return IOCProcessor()

def test_bulk_ip_scan(processor):
    ips = ["1.1.1.1", "8.8.8.8"]
    results = processor.scan_bulk(ips, target_type="ip", max_workers=3)
    assert len(results) == 2
    for r in results:
        assert isinstance(r, dict)
        print(r)
