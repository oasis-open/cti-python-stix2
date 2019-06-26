
import pytest

from stix2 import exceptions
from stix2.v21 import (
    TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE, MarkingDefinition, TLPMarking,
)


def test_bad_id_marking_tlp_white():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--4c9faac1-3558-43d2-919e-95c88d3bc332',
            definition_type='tlp',
            definition=TLPMarking(tlp='white'),
        )


def test_bad_id_marking_tlp_green():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--93023361-d3cf-4666-bca2-8c017948dc3d',
            definition_type='tlp',
            definition=TLPMarking(tlp='green'),
        )


def test_bad_id_marking_tlp_amber():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--05e32101-a940-42ba-8fe9-39283b999ce4',
            definition_type='tlp',
            definition=TLPMarking(tlp='amber'),
        )


def test_bad_id_marking_tlp_red():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--9eceb00c-c158-43f4-87f8-1e3648de17e2',
            definition_type='tlp',
            definition=TLPMarking(tlp='red'),
        )


def test_bad_created_marking_tlp_white():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
            definition_type='tlp',
            definition=TLPMarking(tlp='white'),
        )


def test_bad_created_marking_tlp_green():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            definition_type='tlp',
            definition=TLPMarking(tlp='green'),
        )


def test_bad_created_marking_tlp_amber():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            id='marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
            definition_type='tlp',
            definition=TLPMarking(tlp='amber'),
        )


def test_bad_created_marking_tlp_red():
    with pytest.raises(exceptions.TLPMarkingDefinitionError) as excinfo:
        MarkingDefinition(
            id='marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
            definition_type='tlp',
            definition=TLPMarking(tlp='red'),
        )

    assert "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed" in str(excinfo.value)


def test_successful_tlp_white():
    white = MarkingDefinition(
        id='marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
        created='2017-01-20T00:00:00.000Z',
        definition_type='tlp',
        definition=TLPMarking(tlp='white'),
    )

    assert white.serialize(sort_keys=True) == TLP_WHITE.serialize(sort_keys=True)


def test_successful_tlp_green():
    green = MarkingDefinition(
        id='marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
        created='2017-01-20T00:00:00.000Z',
        definition_type='tlp',
        definition=TLPMarking(tlp='green'),
    )

    assert green.serialize(sort_keys=True) == TLP_GREEN.serialize(sort_keys=True)


def test_successful_tlp_amber():
    amber = MarkingDefinition(
        id='marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
        created='2017-01-20T00:00:00.000Z',
        definition_type='tlp',
        definition=TLPMarking(tlp='amber'),
    )

    assert amber.serialize(sort_keys=True) == TLP_AMBER.serialize(sort_keys=True)


def test_successful_tlp_red():
    red = MarkingDefinition(
        id='marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
        created='2017-01-20T00:00:00.000Z',
        definition_type='tlp',
        definition=TLPMarking(tlp='red'),
    )

    assert red.serialize(sort_keys=True) == TLP_RED.serialize(sort_keys=True)


def test_unknown_tlp_marking():
    with pytest.raises(exceptions.TLPMarkingDefinitionError):
        MarkingDefinition(
            definition_type='tlp',
            definition=TLPMarking(tlp='gray'),
        )
