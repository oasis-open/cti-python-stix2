import datetime as dt
import json

import pytest
import pytz

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
