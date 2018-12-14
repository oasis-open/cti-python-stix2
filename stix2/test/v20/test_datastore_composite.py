import pytest

from stix2.datastore import CompositeDataSource, make_id
from stix2.datastore.filters import Filter
from stix2.datastore.memory import MemorySink, MemorySource, MemoryStore
from stix2.utils import parse_into_datetime
from stix2.v20.common import TLP_GREEN


def test_add_remove_composite_datasource():
    cds = CompositeDataSource()
    ds1 = MemorySource()
    ds2 = MemorySource()
    ds3 = MemorySink()

    with pytest.raises(TypeError) as excinfo:
        cds.add_data_sources([ds1, ds2, ds1, ds3])
    assert str(excinfo.value) == (
        "DataSource (to be added) is not of type "
        "stix2.DataSource. DataSource type is '<class 'stix2.datastore.memory.MemorySink'>'"
    )

    cds.add_data_sources([ds1, ds2, ds1])

    assert len(cds.get_all_data_sources()) == 2

    cds.remove_data_sources([ds1.id, ds2.id])

    assert len(cds.get_all_data_sources()) == 0


def test_composite_datasource_operations(stix_objs1, stix_objs2):
    BUNDLE1 = dict(
        id="bundle--%s" % make_id(),
        objects=stix_objs1,
        spec_version="2.0",
        type="bundle",
    )
    cds1 = CompositeDataSource()
    ds1_1 = MemorySource(stix_data=BUNDLE1)
    ds1_2 = MemorySource(stix_data=stix_objs2)

    cds2 = CompositeDataSource()
    ds2_1 = MemorySource(stix_data=BUNDLE1)
    ds2_2 = MemorySource(stix_data=stix_objs2)

    cds1.add_data_sources([ds1_1, ds1_2])
    cds2.add_data_sources([ds2_1, ds2_2])

    indicators = cds1.all_versions("indicator--00000000-0000-4000-8000-000000000001")

    # In STIX_OBJS2 changed the 'modified' property to a later time...
    assert len(indicators) == 3

    cds1.add_data_sources([cds2])

    indicator = cds1.get("indicator--00000000-0000-4000-8000-000000000001")

    assert indicator["id"] == "indicator--00000000-0000-4000-8000-000000000001"
    assert indicator["modified"] == parse_into_datetime("2017-01-31T13:49:53.935Z")
    assert indicator["type"] == "indicator"

    query1 = [
        Filter("type", "=", "indicator"),
    ]

    query2 = [
        Filter("valid_from", "=", "2017-01-27T13:49:53.935382Z"),
    ]

    cds1.filters.add(query2)

    results = cds1.query(query1)

    # STIX_OBJS2 has indicator with later time, one with different id, one with
    # original time in STIX_OBJS1
    assert len(results) == 4

    indicator = cds1.get("indicator--00000000-0000-4000-8000-000000000001")

    assert indicator["id"] == "indicator--00000000-0000-4000-8000-000000000001"
    assert indicator["modified"] == parse_into_datetime("2017-01-31T13:49:53.935Z")
    assert indicator["type"] == "indicator"

    results = cds1.all_versions("indicator--00000000-0000-4000-8000-000000000001")
    assert len(results) == 3

    # Since we have filters already associated with our CompositeSource providing
    # nothing returns the same as cds1.query(query1) (the associated query is query2)
    results = cds1.query([])
    assert len(results) == 4


def test_source_markings():
    msrc = MemorySource(TLP_GREEN)

    assert msrc.get(TLP_GREEN.id) == TLP_GREEN
    assert msrc.all_versions(TLP_GREEN.id) == [TLP_GREEN]
    assert msrc.query(Filter("id", "=", TLP_GREEN.id)) == [TLP_GREEN]


def test_sink_markings():
    # just make sure there is no crash
    msink = MemorySink(TLP_GREEN)
    msink.add(TLP_GREEN)


def test_store_markings():
    mstore = MemoryStore(TLP_GREEN)

    assert mstore.get(TLP_GREEN.id) == TLP_GREEN
    assert mstore.all_versions(TLP_GREEN.id) == [TLP_GREEN]
    assert mstore.query(Filter("id", "=", TLP_GREEN.id)) == [TLP_GREEN]


def test_source_mixed(indicator):
    msrc = MemorySource([TLP_GREEN, indicator])

    assert msrc.get(TLP_GREEN.id) == TLP_GREEN
    assert msrc.all_versions(TLP_GREEN.id) == [TLP_GREEN]
    assert msrc.query(Filter("id", "=", TLP_GREEN.id)) == [TLP_GREEN]

    assert msrc.get(indicator.id) == indicator
    assert msrc.all_versions(indicator.id) == [indicator]
    assert msrc.query(Filter("id", "=", indicator.id)) == [indicator]

    all_objs = msrc.query()
    assert TLP_GREEN in all_objs
    assert indicator in all_objs
    assert len(all_objs) == 2


def test_sink_mixed(indicator):
    # just make sure there is no crash
    msink = MemorySink([TLP_GREEN, indicator])
    msink.add([TLP_GREEN, indicator])


def test_store_mixed(indicator):
    mstore = MemoryStore([TLP_GREEN, indicator])

    assert mstore.get(TLP_GREEN.id) == TLP_GREEN
    assert mstore.all_versions(TLP_GREEN.id) == [TLP_GREEN]
    assert mstore.query(Filter("id", "=", TLP_GREEN.id)) == [TLP_GREEN]

    assert mstore.get(indicator.id) == indicator
    assert mstore.all_versions(indicator.id) == [indicator]
    assert mstore.query(Filter("id", "=", indicator.id)) == [indicator]

    all_objs = mstore.query()
    assert TLP_GREEN in all_objs
    assert indicator in all_objs
    assert len(all_objs) == 2
