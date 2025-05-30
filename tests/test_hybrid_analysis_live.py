import os
import pytest
from clients.hybrid import HybridAnalysisClient

@pytest.fixture
def hybrid():
    return HybridAnalysisClient(api_key=os.getenv("HYBRID_API_KEY"))

def test_search_eicar_hash(hybrid):
    hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = hybrid.search_by_hash(hash)
    assert isinstance(result, dict)
    print(result)
