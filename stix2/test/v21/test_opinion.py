import datetime as dt
import re

import pytest
import pytz

import stix2

from .constants import OPINION_ID

EXPLANATION = (
    'This doesn\'t seem like it is feasible. We\'ve seen how '
    'PandaCat has attacked Spanish infrastructure over the '
    'last 3 years, so this change in targeting seems too great'
    ' to be viable. The methods used are more commonly '
    'associated with the FlameDragonCrew.'
)

EXPECTED_OPINION = """{
    "type": "opinion",
    "spec_version": "2.1",
    "id": "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "explanation": "%s",
    "object_refs": [
        "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471"
    ],
    "opinion": "strongly-disagree"
}""" % EXPLANATION

EXPECTED_OPINION_REPR = "Opinion(" + " ".join((
    """
    type='opinion',
    spec_version='2.1',
    id='opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7',
    created='2016-05-12T08:17:27.000Z',
    modified='2016-05-12T08:17:27.000Z',
    explanation="%s",
    object_refs=['relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471'],
    opinion='strongly-disagree'""" % EXPLANATION
).split()) + ")"


def test_opinion_with_required_properties():
    now = dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)

    opi = stix2.v21.Opinion(
        type='opinion',
        id=OPINION_ID,
        created=now,
        modified=now,
        object_refs=['relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471'],
        opinion='strongly-disagree',
        explanation=EXPLANATION,
    )

    assert str(opi) == EXPECTED_OPINION
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(opi))
    assert rep == EXPECTED_OPINION_REPR


@pytest.mark.parametrize(
    "data", [
        EXPECTED_OPINION,
        {
            "type": "opinion",
            "spec_version": "2.1",
            "id": OPINION_ID,
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "explanation": EXPLANATION,
            "object_refs": [
                "relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471",
            ],
            "opinion": "strongly-disagree",
        },
    ],
)
def test_parse_opinion(data):
    opinion = stix2.parse(data, version="2.1")

    assert opinion.type == 'opinion'
    assert opinion.spec_version == '2.1'
    assert opinion.id == OPINION_ID
    assert opinion.created == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert opinion.modified == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert opinion.opinion == 'strongly-disagree'
    assert opinion.object_refs[0] == 'relationship--16d2358f-3b0d-4c88-b047-0da2f7ed4471'
    assert opinion.explanation == EXPLANATION
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(opinion))
    assert rep == EXPECTED_OPINION_REPR
