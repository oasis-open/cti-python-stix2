import uuid

import pytest

import stix2

from .constants import (FAKE_TIME, INDICATOR_KWARGS, MALWARE_KWARGS,
                        RELATIONSHIP_KWARGS)


# Inspired by: http://stackoverflow.com/a/24006251
@pytest.fixture
def clock(monkeypatch):

    class mydatetime(stix2.utils.STIXdatetime):
        @classmethod
        def now(cls, tz=None):
            return FAKE_TIME

    monkeypatch.setattr(stix2.utils, 'STIXdatetime', mydatetime)


@pytest.fixture
def uuid4(monkeypatch):
    def wrapper():
        data = [0]

        def wrapped():
            data[0] += 1
            return "00000000-0000-0000-0000-00000000%04x" % data[0]

        return wrapped
    monkeypatch.setattr(uuid, "uuid4", wrapper())


@pytest.fixture
def indicator(uuid4, clock):
    return stix2.Indicator(**INDICATOR_KWARGS)


@pytest.fixture
def malware(uuid4, clock):
    return stix2.Malware(**MALWARE_KWARGS)


@pytest.fixture
def relationship(uuid4, clock):
    return stix2.Relationship(**RELATIONSHIP_KWARGS)
