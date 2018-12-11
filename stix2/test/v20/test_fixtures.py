import uuid

from stix2 import utils

from .constants import FAKE_TIME


def test_clock(clock):
    assert utils.STIXdatetime.now() == FAKE_TIME


def test_my_uuid4_fixture(uuid4):
    assert uuid.uuid4() == "00000000-0000-4000-8000-000000000001"
    assert uuid.uuid4() == "00000000-0000-4000-8000-000000000002"
    assert uuid.uuid4() == "00000000-0000-4000-8000-000000000003"
    for _ in range(256):
        uuid.uuid4()
    assert uuid.uuid4() == "00000000-0000-4000-8000-000000000104"
