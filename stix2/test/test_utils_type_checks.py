import pytest

import stix2.utils

###
# Tests using types/behaviors common to STIX 2.0 and 2.1.
###


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "attack-pattern",
        "campaign",
        "course-of-action",
        "identity",
        "indicator",
        "intrusion-set",
        "malware",
        "observed-data",
        "report",
        "threat-actor",
        "tool",
        "vulnerability",
    ],
)
def test_is_sdo(type_, stix_version):
    assert stix2.utils.is_sdo(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert stix2.utils.is_sdo(id_, stix_version)

    assert stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SDO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "relationship",
        "sighting",
        "marking-definition",
        "bundle",
        "language-content",
        "ipv4-addr",
        "foo",
    ],
)
def test_is_not_sdo(type_, stix_version):
    assert not stix2.utils.is_sdo(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert not stix2.utils.is_sdo(id_, stix_version)

    d = {
        "type": type_,
    }
    assert not stix2.utils.is_sdo(d, stix_version)

    assert not stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SDO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    ],
)
def test_is_sco(type_, stix_version):
    assert stix2.utils.is_sco(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert stix2.utils.is_sco(id_, stix_version)

    assert stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SCO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "identity",
        "sighting",
        "marking-definition",
        "bundle",
        "language-content",
        "foo",
    ],
)
def test_is_not_sco(type_, stix_version):
    assert not stix2.utils.is_sco(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert not stix2.utils.is_sco(id_, stix_version)

    d = {
        "type": type_,
    }
    assert not stix2.utils.is_sco(d, stix_version)

    assert not stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SCO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "relationship",
        "sighting",
    ],
)
def test_is_sro(type_, stix_version):
    assert stix2.utils.is_sro(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert stix2.utils.is_sro(id_, stix_version)

    assert stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SRO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "identity",
        "marking-definition",
        "bundle",
        "language-content",
        "ipv4-addr",
        "foo",
    ],
)
def test_is_not_sro(type_, stix_version):
    assert not stix2.utils.is_sro(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert not stix2.utils.is_sro(id_, stix_version)

    d = {
        "type": type_,
    }
    assert not stix2.utils.is_sro(d, stix_version)

    assert not stix2.utils.is_stix_type(
        type_, stix_version, stix2.utils.STIXTypeClass.SRO,
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
def test_is_marking(stix_version):
    assert stix2.utils.is_marking("marking-definition", stix_version)

    id_ = "marking-definition--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert stix2.utils.is_marking(id_, stix_version)

    assert stix2.utils.is_stix_type(
        "marking-definition", stix_version, "marking-definition",
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "identity",
        "bundle",
        "language-content",
        "ipv4-addr",
        "foo",
    ],
)
def test_is_not_marking(type_, stix_version):
    assert not stix2.utils.is_marking(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert not stix2.utils.is_marking(id_, stix_version)

    d = {
        "type": type_,
    }
    assert not stix2.utils.is_marking(d, stix_version)

    assert not stix2.utils.is_stix_type(
        type_, stix_version, "marking-definition",
    )


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
@pytest.mark.parametrize(
    "type_", [
        "identity",
        "relationship",
        "sighting",
        "marking-definition",
        "bundle",
        "ipv4-addr",
    ],
)
def test_is_object(type_, stix_version):
    assert stix2.utils.is_object(type_, stix_version)

    id_ = type_ + "--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert stix2.utils.is_object(id_, stix_version)


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
def test_is_not_object(stix_version):
    assert not stix2.utils.is_object("foo", stix_version)

    id_ = "foo--a12fa04c-6586-4128-8d1a-cfe0d1c081f5"
    assert not stix2.utils.is_object(id_, stix_version)

    d = {
        "type": "foo",
    }
    assert not stix2.utils.is_object(d, stix_version)


@pytest.mark.parametrize("stix_version", ["2.0", "2.1"])
def test_is_stix_type(stix_version):

    assert not stix2.utils.is_stix_type(
        "foo", stix_version, stix2.utils.STIXTypeClass.SDO, "foo",
    )

    assert stix2.utils.is_stix_type(
        "bundle", stix_version, "foo", "bundle",
    )

    assert stix2.utils.is_stix_type(
        "identity", stix_version,
        stix2.utils.STIXTypeClass.SDO,
        stix2.utils.STIXTypeClass.SRO,
    )

    assert stix2.utils.is_stix_type(
        "software", stix_version,
        stix2.utils.STIXTypeClass.SDO,
        stix2.utils.STIXTypeClass.SCO,
    )
