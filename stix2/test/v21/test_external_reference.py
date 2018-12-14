"""Tests for stix.ExternalReference"""

import re

import pytest

import stix2

VERIS = """{
    "source_name": "veris",
    "url": "https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
    "hashes": {
        "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"
    },
    "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7"
}"""


def test_external_reference_veris():
    ref = stix2.v21.ExternalReference(
        source_name="veris",
        external_id="0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
        hashes={
            "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
        },
        url="https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
    )

    assert str(ref) == VERIS


CAPEC = """{
    "source_name": "capec",
    "external_id": "CAPEC-550"
}"""


def test_external_reference_capec():
    ref = stix2.v21.ExternalReference(
        source_name="capec",
        external_id="CAPEC-550",
    )

    assert str(ref) == CAPEC
    assert re.match("ExternalReference\\(source_name=u?'capec', external_id=u?'CAPEC-550'\\)", repr(ref))


CAPEC_URL = """{
    "source_name": "capec",
    "url": "http://capec.mitre.org/data/definitions/550.html",
    "external_id": "CAPEC-550"
}"""


def test_external_reference_capec_url():
    ref = stix2.v21.ExternalReference(
        source_name="capec",
        external_id="CAPEC-550",
        url="http://capec.mitre.org/data/definitions/550.html",
    )

    assert str(ref) == CAPEC_URL


THREAT_REPORT = """{
    "source_name": "ACME Threat Intel",
    "description": "Threat report",
    "url": "http://www.example.com/threat-report.pdf"
}"""


def test_external_reference_threat_report():
    ref = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
        url="http://www.example.com/threat-report.pdf",
    )

    assert str(ref) == THREAT_REPORT


BUGZILLA = """{
    "source_name": "ACME Bugzilla",
    "url": "https://www.example.com/bugs/1370",
    "external_id": "1370"
}"""


def test_external_reference_bugzilla():
    ref = stix2.v21.ExternalReference(
        source_name="ACME Bugzilla",
        external_id="1370",
        url="https://www.example.com/bugs/1370",
    )

    assert str(ref) == BUGZILLA


OFFLINE = """{
    "source_name": "ACME Threat Intel",
    "description": "Threat report"
}"""


def test_external_reference_offline():
    ref = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )

    assert str(ref) == OFFLINE
    assert re.match("ExternalReference\\(source_name=u?'ACME Threat Intel', description=u?'Threat report'\\)", repr(ref))
    # Yikes! This works
    assert eval("stix2." + repr(ref)) == ref


def test_external_reference_source_required():
    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        stix2.v21.ExternalReference()

    assert excinfo.value.cls == stix2.v21.ExternalReference
    assert excinfo.value.properties == ["source_name"]
