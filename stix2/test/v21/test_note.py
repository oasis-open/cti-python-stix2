import datetime as dt
import re

import pytest
import pytz

import stix2

from .constants import CAMPAIGN_ID, NOTE_ID

CONTENT = (
    'This note indicates the various steps taken by the threat'
    ' analyst team to investigate this specific campaign. Step'
    ' 1) Do a scan 2) Review scanned results for identified '
    'hosts not known by external intel... etc'
)

EXPECTED_NOTE = """{
    "type": "note",
    "spec_version": "2.1",
    "id": "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "abstract": "Tracking Team Note#1",
    "content": "%s",
    "authors": [
        "John Doe"
    ],
    "object_refs": [
        "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
    ],
    "external_references": [
        {
            "source_name": "job-tracker",
            "external_id": "job-id-1234"
        }
    ]
}""" % CONTENT

EXPECTED_OPINION_REPR = "Note(" + " ".join((
    """
    type='note',
    spec_version='2.1',
    id='note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061',
    created='2016-05-12T08:17:27.000Z',
    modified='2016-05-12T08:17:27.000Z',
    abstract='Tracking Team Note#1',
    content='%s',
    authors=['John Doe'],
    object_refs=['campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f'],
    external_references=[ExternalReference(source_name='job-tracker', external_id='job-id-1234')]
""" % CONTENT
).split()) + ")"


def test_note_with_required_properties():
    now = dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)

    note = stix2.v21.Note(
        type='note',
        id=NOTE_ID,
        created=now,
        modified=now,
        abstract='Tracking Team Note#1',
        object_refs=[CAMPAIGN_ID],
        authors=['John Doe'],
        content=CONTENT,
        external_references=[
            {
                'source_name': 'job-tracker',
                'external_id': 'job-id-1234',
            },
        ],
    )

    assert str(note) == EXPECTED_NOTE
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(note))
    assert rep == EXPECTED_OPINION_REPR


@pytest.mark.parametrize(
    "data", [
        EXPECTED_NOTE,
        {
            "type": "note",
            "spec_version": "2.1",
            "id": NOTE_ID,
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "abstract": "Tracking Team Note#1",
            "content": CONTENT,
            "authors": [
                "John Doe",
            ],
            "object_refs": [
                CAMPAIGN_ID,
            ],
            "external_references": [
                {
                    "source_name": "job-tracker",
                    "external_id": "job-id-1234",
                },
            ],
        },
    ],
)
def test_parse_note(data):
    note = stix2.parse(data, version="2.1")

    assert note.type == 'note'
    assert note.spec_version == '2.1'
    assert note.id == NOTE_ID
    assert note.created == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert note.modified == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert note.object_refs[0] == CAMPAIGN_ID
    assert note.authors[0] == 'John Doe'
    assert note.abstract == 'Tracking Team Note#1'
    assert note.content == CONTENT
    rep = re.sub(r"(\[|=| )u('|\"|\\\'|\\\")", r"\g<1>\g<2>", repr(note))
    assert rep == EXPECTED_OPINION_REPR
