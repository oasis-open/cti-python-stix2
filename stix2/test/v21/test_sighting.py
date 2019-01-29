import datetime as dt

import pytest
import pytz

import stix2

from .constants import IDENTITY_ID, INDICATOR_ID, SIGHTING_ID, SIGHTING_KWARGS

EXPECTED_SIGHTING = """{
    "type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb",
    "created": "2016-04-06T20:06:37.000Z",
    "modified": "2016-04-06T20:06:37.000Z",
    "sighting_of_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
    "where_sighted_refs": [
        "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
    ]
}"""

BAD_SIGHTING = """{
    "created": "2016-04-06T20:06:37.000Z",
    "id": "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb",
    "modified": "2016-04-06T20:06:37.000Z",
    "sighting_of_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
    "spec_version": "2.1",
    "type": "sighting",
    "where_sighted_refs": [
        "malware--8cc7afd6-5455-4d2b-a736-e614ee631d99"
    ]
}"""


def test_sighting_all_required_properties():
    now = dt.datetime(2016, 4, 6, 20, 6, 37, tzinfo=pytz.utc)

    s = stix2.v21.Sighting(
        type='sighting',
        id=SIGHTING_ID,
        created=now,
        modified=now,
        sighting_of_ref=INDICATOR_ID,
        where_sighted_refs=[IDENTITY_ID],
    )
    assert str(s) == EXPECTED_SIGHTING


def test_sighting_bad_where_sighted_refs():
    now = dt.datetime(2016, 4, 6, 20, 6, 37, tzinfo=pytz.utc)

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Sighting(
            type='sighting',
            id=SIGHTING_ID,
            created=now,
            modified=now,
            sighting_of_ref=INDICATOR_ID,
            where_sighted_refs=["malware--8cc7afd6-5455-4d2b-a736-e614ee631d99"],
        )

    assert excinfo.value.cls == stix2.v21.Sighting
    assert excinfo.value.prop_name == "where_sighted_refs"
    assert excinfo.value.reason == "must start with 'identity'."
    assert str(excinfo.value) == "Invalid value for Sighting 'where_sighted_refs': must start with 'identity'."


def test_sighting_type_must_be_sightings():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Sighting(type='xxx', **SIGHTING_KWARGS)

    assert excinfo.value.cls == stix2.v21.Sighting
    assert excinfo.value.prop_name == "type"
    assert excinfo.value.reason == "must equal 'sighting'."
    assert str(excinfo.value) == "Invalid value for Sighting 'type': must equal 'sighting'."


def test_invalid_kwarg_to_sighting():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.v21.Sighting(my_custom_property="foo", **SIGHTING_KWARGS)

    assert excinfo.value.cls == stix2.v21.Sighting
    assert excinfo.value.properties == ['my_custom_property']
    assert str(excinfo.value) == "Unexpected properties for Sighting: (my_custom_property)."


def test_create_sighting_from_objects_rather_than_ids(malware):  # noqa: F811
    rel = stix2.v21.Sighting(sighting_of_ref=malware)

    assert rel.sighting_of_ref == 'malware--00000000-0000-4000-8000-000000000001'
    assert rel.id == 'sighting--00000000-0000-4000-8000-000000000003'


@pytest.mark.parametrize(
    "data", [
        EXPECTED_SIGHTING,
        {
            "created": "2016-04-06T20:06:37Z",
            "id": SIGHTING_ID,
            "modified": "2016-04-06T20:06:37Z",
            "sighting_of_ref": "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
            "spec_version": "2.1",
            "type": "sighting",
            "where_sighted_refs": [
                IDENTITY_ID,
            ],
        },
    ],
)
def test_parse_sighting(data):
    sighting = stix2.parse(data, version="2.1")

    assert sighting.type == 'sighting'
    assert sighting.spec_version == '2.1'
    assert sighting.id == SIGHTING_ID
    assert sighting.created == dt.datetime(2016, 4, 6, 20, 6, 37, tzinfo=pytz.utc)
    assert sighting.modified == dt.datetime(2016, 4, 6, 20, 6, 37, tzinfo=pytz.utc)
    assert sighting.sighting_of_ref == INDICATOR_ID
    assert sighting.where_sighted_refs == [IDENTITY_ID]
