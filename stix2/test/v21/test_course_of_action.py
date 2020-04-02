import json

import pytest

import stix2
import stix2.exceptions
import stix2.utils

COA_WITH_BIN_JSON = """{
    "type": "course-of-action",
    "spec_version": "2.1",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
    "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
}"""


COA_WITH_REF_JSON = """{
    "type": "course-of-action",
    "spec_version": "2.1",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
    "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
}"""


COA_WITH_BIN_DICT = json.loads(COA_WITH_BIN_JSON)
COA_WITH_REF_DICT = json.loads(COA_WITH_REF_JSON)


@pytest.mark.parametrize(
    "sdo_json,sdo_dict", [
        (COA_WITH_BIN_JSON, COA_WITH_BIN_DICT),
        (COA_WITH_REF_JSON, COA_WITH_REF_DICT),
    ],
)
def test_course_of_action_example(sdo_json, sdo_dict):
    coa = stix2.v21.CourseOfAction(**sdo_dict)
    assert str(coa) == sdo_json


@pytest.mark.parametrize(
    "sdo_json,sdo_dict", [
        (COA_WITH_BIN_JSON, COA_WITH_BIN_DICT),
        (COA_WITH_REF_JSON, COA_WITH_REF_DICT),
    ],
)
def test_parse_course_of_action(sdo_json, sdo_dict):

    # Names of timestamp-valued attributes
    ts_attrs = {"created", "modified"}

    for data in (sdo_json, sdo_dict):
        coa = stix2.parse(data, version="2.1")

        # sdo_dict is handy as a source of attribute names/values to check
        for attr_name, attr_value in sdo_dict.items():
            cmp_value = stix2.utils.parse_into_datetime(attr_value) \
                if attr_name in ts_attrs else attr_value

            assert getattr(coa, attr_name) == cmp_value


# TODO: Add other examples
