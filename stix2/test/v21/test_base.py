import datetime as dt
import json
import uuid

import pytest
import pytz

import stix2
from stix2.base import STIXJSONEncoder


def test_encode_json_datetime():
    now = dt.datetime(2017, 3, 22, 0, 0, 0, tzinfo=pytz.UTC)
    test_dict = {'now': now}

    expected = '{"now": "2017-03-22T00:00:00Z"}'
    assert json.dumps(test_dict, cls=STIXJSONEncoder) == expected


def test_encode_json_object():
    obj = object()
    test_dict = {'obj': obj}

    with pytest.raises(TypeError) as excinfo:
        json.dumps(test_dict, cls=STIXJSONEncoder)

    assert " is not JSON serializable" in str(excinfo.value)


def test_deterministic_id_unicode():
    mutex = {'name': u'D*Fl#Ed*\u00a3\u00a8', 'type': 'mutex'}
    obs = stix2.parse(mutex, version="2.1")

    dd_idx = obs.id.index("--")
    id_uuid = uuid.UUID(obs.id[dd_idx+2:])

    assert id_uuid.variant == uuid.RFC_4122
    assert id_uuid.version == 5
