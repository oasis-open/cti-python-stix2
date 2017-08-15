import datetime as dt

import pytest
import pytz

import stix2

from .constants import COURSE_OF_ACTION_ID


EXPECTED = """{
    "type": "course-of-action",
    "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
    "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
}"""


def test_course_of_action_example():
    coa = stix2.CourseOfAction(
        id="course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        name="Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        description="This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
    )

    assert str(coa) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "created": "2016-04-06T20:03:48.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "description": "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ...",
        "id": "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter",
        "type": "course-of-action"
    },
])
def test_parse_course_of_action(data):
    coa = stix2.parse(data)

    assert coa.type == 'course-of-action'
    assert coa.id == COURSE_OF_ACTION_ID
    assert coa.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert coa.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert coa.created_by_ref == "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    assert coa.description == "This is how to add a filter rule to block inbound access to TCP port 80 to the existing UDP 1434 filter ..."
    assert coa.name == "Add TCP port 80 Filter Rule to the existing Block UDP 1434 Filter"

# TODO: Add other examples
