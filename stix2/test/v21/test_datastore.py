import pytest

from stix2.datastore import (
    CompositeDataSource, DataSink, DataSource, DataStoreMixin,
)
from stix2.datastore.filters import Filter

from .constants import CAMPAIGN_MORE_KWARGS


def test_datasource_abstract_class_raises_error():
    with pytest.raises(TypeError):
        DataSource()


def test_datasink_abstract_class_raises_error():
    with pytest.raises(TypeError):
        DataSink()


def test_datastore_smoke():
    assert DataStoreMixin() is not None


def test_datastore_get_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().get("indicator--00000000-0000-4000-8000-000000000001")
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_all_versions_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().all_versions("indicator--00000000-0000-4000-8000-000000000001")
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_query_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().query([Filter("type", "=", "indicator")])
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_creator_of_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().creator_of(CAMPAIGN_MORE_KWARGS)
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_relationships_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().relationships(
            obj="indicator--00000000-0000-4000-8000-000000000001",
            target_only=True,
        )
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_related_to_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().related_to(
            obj="indicator--00000000-0000-4000-8000-000000000001",
            target_only=True,
        )
    assert "DataStoreMixin has no data source to query" == str(excinfo.value)


def test_datastore_add_raises():
    with pytest.raises(AttributeError) as excinfo:
        DataStoreMixin().add(CAMPAIGN_MORE_KWARGS)
    assert "DataStoreMixin has no data sink to put objects in" == str(excinfo.value)


def test_composite_datastore_get_raises_error():
    with pytest.raises(AttributeError) as excinfo:
        CompositeDataSource().get("indicator--00000000-0000-4000-8000-000000000001")
    assert "CompositeDataSource has no data sources" == str(excinfo.value)


def test_composite_datastore_all_versions_raises_error():
    with pytest.raises(AttributeError) as excinfo:
        CompositeDataSource().all_versions("indicator--00000000-0000-4000-8000-000000000001")
    assert "CompositeDataSource has no data sources" == str(excinfo.value)


def test_composite_datastore_query_raises_error():
    with pytest.raises(AttributeError) as excinfo:
        CompositeDataSource().query([Filter("type", "=", "indicator")])
    assert "CompositeDataSource has no data sources" == str(excinfo.value)


def test_composite_datastore_relationships_raises_error():
    with pytest.raises(AttributeError) as excinfo:
        CompositeDataSource().relationships(
            obj="indicator--00000000-0000-4000-8000-000000000001",
            target_only=True,
        )
    assert "CompositeDataSource has no data sources" == str(excinfo.value)


def test_composite_datastore_related_to_raises_error():
    with pytest.raises(AttributeError) as excinfo:
        CompositeDataSource().related_to(
            obj="indicator--00000000-0000-4000-8000-000000000001",
            target_only=True,
        )
    assert "CompositeDataSource has no data sources" == str(excinfo.value)


def test_composite_datastore_add_data_source_raises_error():
    with pytest.raises(TypeError) as excinfo:
        ind = "indicator--00000000-0000-4000-8000-000000000001"
        CompositeDataSource().add_data_source(ind)
    assert "DataSource (to be added) is not of type stix2.DataSource. DataSource type is '{}'".format(type(ind)) == str(excinfo.value)


def test_composite_datastore_add_data_sources_raises_error():
    with pytest.raises(TypeError) as excinfo:
        ind = "indicator--00000000-0000-4000-8000-000000000001"
        CompositeDataSource().add_data_sources(ind)
    assert "DataSource (to be added) is not of type stix2.DataSource. DataSource type is '{}'".format(type(ind)) == str(excinfo.value)


def test_composite_datastore_no_datasource():
    cds = CompositeDataSource()
    with pytest.raises(AttributeError) as excinfo:
        cds.get("indicator--00000000-0000-4000-8000-000000000001")
    assert 'CompositeDataSource has no data source' in str(excinfo.value)
