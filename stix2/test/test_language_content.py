import datetime as dt

import pytest
import pytz

import stix2

CAMPAIGN_ID = "campaign--12a111f0-b824-4baf-a224-83b80237a094"

LANGUAGE_CONTENT_ID = "language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d"

TEST_CAMPAIGN = """{
    "type": "campaign",
    "id": "campaign--12a111f0-b824-4baf-a224-83b80237a094",
    "lang": "en",
    "created": "2017-02-08T21:31:22.007Z",
    "modified": "2017-02-08T21:31:22.007Z",
    "name": "Bank Attack",
    "description": "More information about bank attack"
}"""

TEST_LANGUAGE_CONTENT = """{
    "type": "language-content",
    "id": "language-content--b86bd89f-98bb-4fa9-8cb2-9ad421da981d",
    "created": "2017-02-08T21:31:22.007Z",
    "modified": "2017-02-08T21:31:22.007Z",
    "object_ref": "campaign--12a111f0-b824-4baf-a224-83b80237a094",
    "object_modified": "2017-02-08T21:31:22.007Z",
    "contents": {
        "de": {
            "name": "Bank Angriff 1",
            "description": "Weitere Informationen über Banküberfall"
        },
        "fr": {
            "name": "Attaque Bank 1",
            "description": "Plus d'informations sur la crise bancaire"
        }
    }
}"""


@pytest.mark.xfail(reason="Dictionary keys are too short")
def test_language_content_campaign():
    now = dt.datetime(2017, 2, 8, 21, 31, 22, microsecond=7000, tzinfo=pytz.utc)

    lc = stix2.LanguageContent(
        type='language-content',
        id=LANGUAGE_CONTENT_ID,
        created=now,
        modified=now,
        object_ref=CAMPAIGN_ID,
        object_modified=now,
        contents={
            "de": {
                "name": "Bank Angriff 1",
                "description": "Weitere Informationen über Banküberfall"
            },
            "fr": {
                "name": "Attaque Bank 1",
                "description": "Plus d'informations sur la crise bancaire"
            }
        }
    )

    camp = stix2.parse(TEST_CAMPAIGN)

    assert str(lc) in TEST_LANGUAGE_CONTENT
    assert lc.modified == camp.modified
