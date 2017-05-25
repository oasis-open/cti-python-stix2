import pytest

import stix2.sources


def test_data_source():
    ds = stix2.sources.DataSource()

    assert ds.name == "DataSource"


def test_set_data_source_name():
    ds = stix2.sources.DataSource(name="My Data Source")

    assert ds.name == "My Data Source"


def test_data_source_get():
    ds = stix2.sources.DataSource(name="My Data Source")

    with pytest.raises(NotImplementedError):
        ds.get("foo")
