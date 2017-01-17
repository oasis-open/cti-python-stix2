"""Tests for the stix2 library"""

import stix2


def test_basic_indicator():
    indicator = stix2.Indicator()
    assert indicator.id.startswith("indicator")
