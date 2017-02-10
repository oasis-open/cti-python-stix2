"""Tests for stix.ExternalReference"""

import pytest

import stix2

VERIS = """{
    "external_id": "0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
    "source_name": "veris",
    "url": "https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json"
}"""


def test_external_reference_veris():
    ref = stix2.ExternalReference(
        source_name="veris",
        external_id="0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
        url="https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
    )

    assert str(ref) == VERIS


CAPEC = """{
    "external_id": "CAPEC-550",
    "source_name": "capec"
}"""


def test_external_reference_capec():
    ref = stix2.ExternalReference(
        source_name="capec",
        external_id="CAPEC-550",
    )

    assert str(ref) == CAPEC
    assert repr(ref) == "ExternalReference(external_id='CAPEC-550', source_name='capec')"


CAPEC_URL = """{
    "external_id": "CAPEC-550",
    "source_name": "capec",
    "url": "http://capec.mitre.org/data/definitions/550.html"
}"""


def test_external_reference_capec_url():
    ref = stix2.ExternalReference(
        source_name="capec",
        external_id="CAPEC-550",
        url="http://capec.mitre.org/data/definitions/550.html",
    )

    assert str(ref) == CAPEC_URL


THREAT_REPORT = """{
    "description": "Threat report",
    "source_name": "ACME Threat Intel",
    "url": "http://www.example.com/threat-report.pdf"
}"""


def test_external_reference_threat_report():
    ref = stix2.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
        url="http://www.example.com/threat-report.pdf",
    )

    assert str(ref) == THREAT_REPORT


BUGZILLA = """{
    "external_id": "1370",
    "source_name": "ACME Bugzilla",
    "url": "https://www.example.com/bugs/1370"
}"""


def test_external_reference_bugzilla():
    ref = stix2.ExternalReference(
        source_name="ACME Bugzilla",
        external_id="1370",
        url="https://www.example.com/bugs/1370",
    )

    assert str(ref) == BUGZILLA


OFFLINE = """{
    "description": "Threat report",
    "source_name": "ACME Threat Intel"
}"""


def test_external_reference_offline():
    ref = stix2.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )

    assert str(ref) == OFFLINE
    assert repr(ref) == "ExternalReference(description='Threat report', source_name='ACME Threat Intel')"
    # Yikes! This works
    assert eval("stix2." + repr(ref)) == ref


def test_external_reference_source_required():
    with pytest.raises(ValueError) as excinfo:
        ref = stix2.ExternalReference()
    assert str(excinfo.value) == "Missing required field(s) for ExternalReference: (source_name)."
