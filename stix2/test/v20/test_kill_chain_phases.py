"""Tests for stix.ExternalReference"""

import pytest

import stix2

LMCO_RECON = """{
    "kill_chain_name": "lockheed-martin-cyber-kill-chain",
    "phase_name": "reconnaissance"
}"""


def test_lockheed_martin_cyber_kill_chain():
    recon = stix2.v20.KillChainPhase(
        kill_chain_name="lockheed-martin-cyber-kill-chain",
        phase_name="reconnaissance",
    )

    assert str(recon) == LMCO_RECON


FOO_PRE_ATTACK = """{
    "kill_chain_name": "foo",
    "phase_name": "pre-attack"
}"""


def test_kill_chain_example():
    preattack = stix2.v20.KillChainPhase(
        kill_chain_name="foo",
        phase_name="pre-attack",
    )

    assert str(preattack) == FOO_PRE_ATTACK


def test_kill_chain_required_properties():

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        stix2.v20.KillChainPhase()

    assert excinfo.value.cls == stix2.v20.KillChainPhase
    assert excinfo.value.properties == ["kill_chain_name", "phase_name"]


def test_kill_chain_required_property_chain_name():

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        stix2.v20.KillChainPhase(phase_name="weaponization")

    assert excinfo.value.cls == stix2.v20.KillChainPhase
    assert excinfo.value.properties == ["kill_chain_name"]


def test_kill_chain_required_property_phase_name():

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        stix2.v20.KillChainPhase(kill_chain_name="lockheed-martin-cyber-kill-chain")

    assert excinfo.value.cls == stix2.v20.KillChainPhase
    assert excinfo.value.properties == ["phase_name"]
