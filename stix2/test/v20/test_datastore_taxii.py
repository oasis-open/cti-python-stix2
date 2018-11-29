import json

from medallion.filters.basic_filter import BasicFilter
import pytest
from requests.models import Response
import six
from taxii2client import Collection, _filter_kwargs_to_query_params

import stix2
from stix2.datastore import DataSourceError
from stix2.datastore.filters import Filter

COLLECTION_URL = 'https://example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/'


class MockTAXIICollectionEndpoint(Collection):
    """Mock for taxii2_client.TAXIIClient"""

    def __init__(self, url, collection_info):
        super(MockTAXIICollectionEndpoint, self).__init__(
            url, collection_info=collection_info,
        )
        self.objects = []

    def add_objects(self, bundle):
        self._verify_can_write()
        if isinstance(bundle, six.string_types):
            bundle = json.loads(bundle, encoding='utf-8')
        for object in bundle.get("objects", []):
            self.objects.append(object)

    def get_objects(self, **filter_kwargs):
        self._verify_can_read()
        query_params = _filter_kwargs_to_query_params(filter_kwargs)
        assert isinstance(query_params, dict)
        full_filter = BasicFilter(query_params)
        objs = full_filter.process_filter(
            self.objects,
            ("id", "type", "version"),
            [],
        )
        if objs:
            return stix2.v20.Bundle(objects=objs)
        else:
            resp = Response()
            resp.status_code = 404
            resp.raise_for_status()

    def get_object(self, id, **filter_kwargs):
        self._verify_can_read()
        query_params = _filter_kwargs_to_query_params(filter_kwargs)
        assert isinstance(query_params, dict)
        full_filter = BasicFilter(query_params)

        # In this endpoint we must first filter objects by id beforehand.
        objects = [x for x in self.objects if x["id"] == id]
        if objects:
            filtered_objects = full_filter.process_filter(
                objects,
                ("version",),
                [],
            )
        else:
            filtered_objects = []
        if filtered_objects:
            return stix2.v20.Bundle(objects=filtered_objects)
        else:
            resp = Response()
            resp.status_code = 404
            resp.raise_for_status()


@pytest.fixture
def collection(stix_objs1):
    mock = MockTAXIICollectionEndpoint(
        COLLECTION_URL, {
            "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "title": "Writable Collection",
            "description": "This collection is a dropbox for submitting indicators",
            "can_read": True,
            "can_write": True,
            "media_types": [
                "application/vnd.oasis.stix+json; version=2.0",
            ],
        },
    )

    mock.objects.extend(stix_objs1)
    return mock


@pytest.fixture
def collection_no_rw_access(stix_objs1):
    mock = MockTAXIICollectionEndpoint(
        COLLECTION_URL, {
            "id": "91a7b528-80eb-42ed-a74d-c6fbd5a26116",
            "title": "Not writeable or readable Collection",
            "description": "This collection is a dropbox for submitting indicators",
            "can_read": False,
            "can_write": False,
            "media_types": [
                "application/vnd.oasis.stix+json; version=2.0",
            ],
        },
    )

    mock.objects.extend(stix_objs1)
    return mock


def test_ds_taxii(collection):
    ds = stix2.TAXIICollectionSource(collection)
    assert ds.collection is not None


def test_add_stix2_object(collection):
    tc_sink = stix2.TAXIICollectionSink(collection)

    # create new STIX threat-actor
    ta = stix2.v20.ThreatActor(
        name="Teddy Bear",
        labels=["nation-state"],
        sophistication="innovator",
        resource_level="government",
        goals=[
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector",
        ],
    )

    tc_sink.add(ta)


def test_add_stix2_with_custom_object(collection):
    tc_sink = stix2.TAXIICollectionStore(collection, allow_custom=True)

    # create new STIX threat-actor
    ta = stix2.v20.ThreatActor(
        name="Teddy Bear",
        labels=["nation-state"],
        sophistication="innovator",
        resource_level="government",
        goals=[
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector",
        ],
        foo="bar",
        allow_custom=True,
    )

    tc_sink.add(ta)


def test_add_list_object(collection, indicator):
    tc_sink = stix2.TAXIICollectionSink(collection)

    # create new STIX threat-actor
    ta = stix2.v20.ThreatActor(
        name="Teddy Bear",
        labels=["nation-state"],
        sophistication="innovator",
        resource_level="government",
        goals=[
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector",
        ],
    )

    tc_sink.add([ta, indicator])


def test_get_object_found(collection):
    tc_source = stix2.TAXIICollectionSource(collection)
    result = tc_source.query([
        stix2.Filter("id", "=", "indicator--00000000-0000-4000-8000-000000000001"),
    ])
    assert result


def test_get_object_not_found(collection):
    tc_source = stix2.TAXIICollectionSource(collection)
    result = tc_source.get("indicator--00000000-0000-4000-8000-000000000005")
    assert result is None


def test_add_stix2_bundle_object(collection):
    tc_sink = stix2.TAXIICollectionSink(collection)

    # create new STIX threat-actor
    ta = stix2.v20.ThreatActor(
        name="Teddy Bear",
        labels=["nation-state"],
        sophistication="innovator",
        resource_level="government",
        goals=[
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector",
        ],
    )

    tc_sink.add(stix2.v20.Bundle(objects=[ta]))


def test_add_str_object(collection):
    tc_sink = stix2.TAXIICollectionSink(collection)

    # create new STIX threat-actor
    ta = """{
        "type": "threat-actor",
        "id": "threat-actor--eddff64f-feb1-4469-b07c-499a73c96415",
        "created": "2018-04-23T16:40:50.847Z",
        "modified": "2018-04-23T16:40:50.847Z",
        "name": "Teddy Bear",
        "goals": [
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector"
        ],
        "sophistication": "innovator",
        "resource_level": "government",
        "labels": [
            "nation-state"
        ]
    }"""

    tc_sink.add(ta)


def test_add_dict_object(collection):
    tc_sink = stix2.TAXIICollectionSink(collection)

    ta = {
        "type": "threat-actor",
        "id": "threat-actor--eddff64f-feb1-4469-b07c-499a73c96415",
        "created": "2018-04-23T16:40:50.847Z",
        "modified": "2018-04-23T16:40:50.847Z",
        "name": "Teddy Bear",
        "goals": [
            "compromising environment NGOs",
            "water-hole attacks geared towards energy sector",
        ],
        "sophistication": "innovator",
        "resource_level": "government",
        "labels": [
            "nation-state",
        ],
    }

    tc_sink.add(ta)


def test_add_dict_bundle_object(collection):
    tc_sink = stix2.TAXIICollectionSink(collection)

    ta = {
        "type": "bundle",
        "id": "bundle--860ccc8d-56c9-4fda-9384-84276fb52fb1",
        "objects": [
            {
                "type": "threat-actor",
                "id": "threat-actor--dc5a2f41-f76e-425a-81fe-33afc7aabd75",
                "created": "2018-04-23T18:45:11.390Z",
                "modified": "2018-04-23T18:45:11.390Z",
                "name": "Teddy Bear",
                "goals": [
                    "compromising environment NGOs",
                    "water-hole attacks geared towards energy sector",
                ],
                "sophistication": "innovator",
                "resource_level": "government",
                "labels": [
                    "nation-state",
                ],
            },
        ],
    }

    tc_sink.add(ta)


def test_get_stix2_object(collection):
    tc_sink = stix2.TAXIICollectionSource(collection)

    objects = tc_sink.get("indicator--00000000-0000-4000-8000-000000000001")

    assert objects


def test_parse_taxii_filters(collection):
    query = [
        Filter("added_after", "=", "2016-02-01T00:00:01.000Z"),
        Filter("id", "=", "taxii stix object ID"),
        Filter("type", "=", "taxii stix object ID"),
        Filter("version", "=", "first"),
        Filter("created_by_ref", "=", "Bane"),
    ]

    taxii_filters_expected = [
        Filter("added_after", "=", "2016-02-01T00:00:01.000Z"),
        Filter("id", "=", "taxii stix object ID"),
        Filter("type", "=", "taxii stix object ID"),
        Filter("version", "=", "first"),
    ]

    ds = stix2.TAXIICollectionSource(collection)

    taxii_filters = ds._parse_taxii_filters(query)

    assert taxii_filters == taxii_filters_expected


def test_add_get_remove_filter(collection):
    ds = stix2.TAXIICollectionSource(collection)

    # First 3 filters are valid, remaining properties are erroneous in some way
    valid_filters = [
        Filter('type', '=', 'malware'),
        Filter('id', '!=', 'stix object id'),
        Filter('labels', 'in', ["heartbleed", "malicious-activity"]),
    ]

    assert len(ds.filters) == 0

    ds.filters.add(valid_filters[0])
    assert len(ds.filters) == 1

    # Addin the same filter again will have no effect since `filters` acts
    # like a set
    ds.filters.add(valid_filters[0])
    assert len(ds.filters) == 1

    ds.filters.add(valid_filters[1])
    assert len(ds.filters) == 2

    ds.filters.add(valid_filters[2])
    assert len(ds.filters) == 3

    assert valid_filters == [f for f in ds.filters]

    # remove
    ds.filters.remove(valid_filters[0])

    assert len(ds.filters) == 2

    ds.filters.add(valid_filters)


def test_get_all_versions(collection):
    ds = stix2.TAXIICollectionStore(collection)

    indicators = ds.all_versions('indicator--00000000-0000-4000-8000-000000000001')
    # There are 3 indicators but 2 share the same 'modified' timestamp
    assert len(indicators) == 2


def test_can_read_error(collection_no_rw_access):
    """create a TAXIICOllectionSource with a taxii2client.Collection
    instance that does not have read access, check ValueError exception is raised"""

    with pytest.raises(DataSourceError) as excinfo:
        stix2.TAXIICollectionSource(collection_no_rw_access)
    assert "Collection object provided does not have read access" in str(excinfo.value)


def test_can_write_error(collection_no_rw_access):
    """create a TAXIICOllectionSink with a taxii2client.Collection
    instance that does not have write access, check ValueError exception is raised"""

    with pytest.raises(DataSourceError) as excinfo:
        stix2.TAXIICollectionSink(collection_no_rw_access)
    assert "Collection object provided does not have write access" in str(excinfo.value)


def test_get_404():
    """a TAXIICollectionSource.get() call that receives an HTTP 404 response
    code from the taxii2client should be be returned as None.

    TAXII spec states that a TAXII server can return a 404 for nonexistent
    resources or lack of access. Decided that None is acceptable reponse
    to imply that state of the TAXII endpoint.
    """

    class TAXIICollection404():
        can_read = True

        def get_object(self, id, version=None):
            resp = Response()
            resp.status_code = 404
            resp.raise_for_status()

    ds = stix2.TAXIICollectionSource(TAXIICollection404())

    # this will raise 404 from mock TAXII Client but TAXIICollectionStore
    # should handle gracefully and return None
    stix_obj = ds.get("indicator--1")
    assert stix_obj is None


def test_all_versions_404(collection):
    """ a TAXIICollectionSource.all_version() call that recieves an HTTP 404
    response code from the taxii2client should be returned as an exception"""

    ds = stix2.TAXIICollectionStore(collection)

    with pytest.raises(DataSourceError) as excinfo:
        ds.all_versions("indicator--1")
    assert "are either not found or access is denied" in str(excinfo.value)
    assert "404" in str(excinfo.value)


def test_query_404(collection):
    """ a TAXIICollectionSource.query() call that recieves an HTTP 404
    response code from the taxii2client should be returned as an exception"""

    ds = stix2.TAXIICollectionStore(collection)
    query = [Filter("type", "=", "malware")]

    with pytest.raises(DataSourceError) as excinfo:
        ds.query(query=query)
    assert "are either not found or access is denied" in str(excinfo.value)
    assert "404" in str(excinfo.value)
