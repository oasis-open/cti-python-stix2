import pytest
from taxii2client import Collection

from stix2 import Filter, MemorySink, MemorySource
from stix2.sources import (CompositeDataSource, DataSink, DataSource, make_id,
                           taxii)
from stix2.sources.filters import apply_common_filters
from stix2.utils import deduplicate

COLLECTION_URL = 'https://example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/'


class MockTAXIIClient(object):
    """Mock for taxii2_client.TAXIIClient"""
    pass


@pytest.fixture
def collection():
    return Collection(COLLECTION_URL, MockTAXIIClient())


IND1 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND2 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND3 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.936Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND4 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND5 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND6 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-31T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND7 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}
IND8 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}

STIX_OBJS2 = [IND6, IND7, IND8]
STIX_OBJS1 = [IND1, IND2, IND3, IND4, IND5]


def test_ds_abstract_class_smoke():
    with pytest.raises(TypeError):
        DataSource()

    with pytest.raises(TypeError):
        DataSink()


def test_ds_taxii(collection):
    ds = taxii.TAXIICollectionSource(collection)
    assert ds.collection is not None


def test_ds_taxii_name(collection):
    ds = taxii.TAXIICollectionSource(collection)
    assert ds.collection is not None


def test_parse_taxii_filters():
    query = [
        Filter("added_after", "=", "2016-02-01T00:00:01.000Z"),
        Filter("id", "=", "taxii stix object ID"),
        Filter("type", "=", "taxii stix object ID"),
        Filter("version", "=", "first"),
        Filter("created_by_ref", "=", "Bane"),
    ]

    expected_params = {
        "added_after": "2016-02-01T00:00:01.000Z",
        "match[id]": "taxii stix object ID",
        "match[type]": "taxii stix object ID",
        "match[version]": "first"
    }

    ds = taxii.TAXIICollectionSource(collection)

    taxii_filters = ds._parse_taxii_filters(query)

    assert taxii_filters == expected_params


def test_add_get_remove_filter():
    ds = taxii.TAXIICollectionSource(collection)

    # First 3 filters are valid, remaining properties are erroneous in some way
    valid_filters = [
        Filter('type', '=', 'malware'),
        Filter('id', '!=', 'stix object id'),
        Filter('labels', 'in', ["heartbleed", "malicious-activity"]),
    ]

    # Invalid filters - wont pass creation
    # these filters will not be allowed to be created
    # check proper errors are raised when trying to create them

    with pytest.raises(ValueError) as excinfo:
        # create Filter that has an operator that is not allowed
        Filter('modified', '*', 'not supported operator - just place holder')
    assert str(excinfo.value) == "Filter operator '*' not supported for specified property: 'modified'"

    with pytest.raises(TypeError) as excinfo:
        # create Filter that has a value type that is not allowed
        Filter('created', '=', object())
    # On Python 2, the type of object() is `<type 'object'>` On Python 3, it's `<class 'object'>`.
    assert str(excinfo.value).startswith("Filter value type")
    assert str(excinfo.value).endswith("is not supported. The type must be a Python immutable type or dictionary")

    assert len(ds.filters) == 0

    ds.filters.add(valid_filters[0])
    assert len(ds.filters) == 1

    # Addin the same filter again will have no effect since `filters` uses a set
    ds.filters.add(valid_filters[0])
    assert len(ds.filters) == 1

    ds.filters.add(valid_filters[1])
    assert len(ds.filters) == 2
    ds.filters.add(valid_filters[2])
    assert len(ds.filters) == 3

    assert set(valid_filters) == ds.filters

    # remove
    ds.filters.remove(valid_filters[0])

    assert len(ds.filters) == 2

    ds.filters.update(valid_filters)


def test_apply_common_filters():
    stix_objs = [
        {
            "created": "2017-01-27T13:49:53.997Z",
            "description": "\n\nTITLE:\n\tPoison Ivy",
            "id": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
            "labels": [
                "remote-access-trojan"
            ],
            "modified": "2017-01-27T13:49:53.997Z",
            "name": "Poison Ivy",
            "type": "malware"
        },
        {
            "created": "2014-05-08T09:00:00.000Z",
            "id": "indicator--a932fcc6-e032-176c-126f-cb970a5a1ade",
            "labels": [
                "file-hash-watchlist"
            ],
            "modified": "2014-05-08T09:00:00.000Z",
            "name": "File hash for Poison Ivy variant",
            "pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
            "type": "indicator",
            "valid_from": "2014-05-08T09:00:00.000000Z"
        },
        {
            "created": "2014-05-08T09:00:00.000Z",
            "granular_markings": [
                {
                    "marking_ref": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                    "selectors": [
                        "relationship_type"
                    ]
                }
            ],
            "id": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463",
            "modified": "2014-05-08T09:00:00.000Z",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "relationship_type": "indicates",
            "revoked": True,
            "source_ref": "indicator--a932fcc6-e032-176c-126f-cb970a5a1ade",
            "target_ref": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
            "type": "relationship"
        },
        {
            "id": "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef",
            "created": "2016-02-14T00:00:00.000Z",
            "created_by_ref": "identity--00000000-0000-0000-0000-b8e91df99dc9",
            "modified": "2016-02-14T00:00:00.000Z",
            "type": "vulnerability",
            "name": "CVE-2014-0160",
            "description": "The (1) TLS...",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": "CVE-2014-0160"
                }
            ],
            "labels": ["heartbleed", "has-logo"]
        }
    ]

    filters = [
        Filter("type", "!=", "relationship"),
        Filter("id", "=", "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"),
        Filter("labels", "in", "remote-access-trojan"),
        Filter("created", ">", "2015-01-01T01:00:00.000Z"),
        Filter("revoked", "=", True),
        Filter("revoked", "!=", True),
        Filter("object_marking_refs", "=", "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"),
        Filter("granular_markings.selectors", "in", "relationship_type"),
        Filter("granular_markings.marking_ref", "=", "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"),
        Filter("external_references.external_id", "in", "CVE-2014-0160,CVE-2017-6608"),
        Filter("created_by_ref", "=", "identity--00000000-0000-0000-0000-b8e91df99dc9"),
        Filter("object_marking_refs", "=", "marking-definition--613f2e26-0000-0000-0000-b8e91df99dc9"),
        Filter("granular_markings.selectors", "in", "description"),
        Filter("external_references.source_name", "=", "CVE"),
    ]

    # "Return any object whose type is not relationship"
    resp = list(apply_common_filters(stix_objs, [filters[0]]))
    ids = [r['id'] for r in resp]
    assert stix_objs[0]['id'] in ids
    assert stix_objs[1]['id'] in ids
    assert stix_objs[3]['id'] in ids
    assert len(ids) == 3

    # "Return any object that matched id relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"
    resp = list(apply_common_filters(stix_objs, [filters[1]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains remote-access-trojan in labels"
    resp = list(apply_common_filters(stix_objs, [filters[2]]))
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 1

    # "Return any object created after 2015-01-01T01:00:00.000Z"
    resp = list(apply_common_filters(stix_objs, [filters[3]]))
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 2

    # "Return any revoked object"
    resp = list(apply_common_filters(stix_objs, [filters[4]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object whose not revoked"
    # Note that if 'revoked' property is not present in object.
    # Currently we can't use such an expression to filter for... :(
    resp = list(apply_common_filters(stix_objs, [filters[5]]))
    assert len(resp) == 0

    # "Return any object that matches marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9 in object_marking_refs"
    resp = list(apply_common_filters(stix_objs, [filters[6]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains relationship_type in their selectors AND
    # also has marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed in marking_ref"
    resp = list(apply_common_filters(stix_objs, [filters[7], filters[8]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains CVE-2014-0160,CVE-2017-6608 in their external_id"
    resp = list(apply_common_filters(stix_objs, [filters[9]]))
    assert resp[0]['id'] == stix_objs[3]['id']
    assert len(resp) == 1

    # "Return any object that matches created_by_ref identity--00000000-0000-0000-0000-b8e91df99dc9"
    resp = list(apply_common_filters(stix_objs, [filters[10]]))
    assert len(resp) == 1

    # "Return any object that matches marking-definition--613f2e26-0000-0000-0000-b8e91df99dc9 in object_marking_refs" (None)
    resp = list(apply_common_filters(stix_objs, [filters[11]]))
    assert len(resp) == 0

    # "Return any object that contains description in its selectors" (None)
    resp = list(apply_common_filters(stix_objs, [filters[12]]))
    assert len(resp) == 0

    # "Return any object that object that matches CVE in source_name" (None, case sensitive)
    resp = list(apply_common_filters(stix_objs, [filters[13]]))
    assert len(resp) == 0


def test_filters0():
    # "Return any object modified before 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("modified", "<", "2017-01-28T13:49:53.935Z")]))
    assert resp[0]['id'] == STIX_OBJS2[1]['id']
    assert len(resp) == 2


def test_filters1():
    # "Return any object modified after 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("modified", ">", "2017-01-28T13:49:53.935Z")]))
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 1


def test_filters2():
    # "Return any object modified after or on 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("modified", ">=", "2017-01-27T13:49:53.935Z")]))
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 3


def test_filters3():
    # "Return any object modified before or on 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("modified", "<=", "2017-01-27T13:49:53.935Z")]))
    assert resp[0]['id'] == STIX_OBJS2[1]['id']
    assert len(resp) == 2


def test_filters4():
    # Assert invalid Filter cannot be created
    with pytest.raises(ValueError) as excinfo:
        Filter("modified", "?", "2017-01-27T13:49:53.935Z")
    assert str(excinfo.value) == ("Filter operator '?' not supported "
                                  "for specified property: 'modified'")


def test_filters5():
    # "Return any object whose id is not indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f"
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("id", "!=", "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")]))
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 1


def test_filters6():
    # Test filtering on non-common property
    resp = list(apply_common_filters(STIX_OBJS2, [Filter("name", "=", "Malicious site hosting downloader")]))
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 3


def test_filters7():
    # Test filtering on embedded property
    stix_objects = list(STIX_OBJS2) + [{
        "type": "observed-data",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "objects": {
            "0": {
                "type": "file",
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f"
                },
                "extensions": {
                    "pdf-ext": {
                        "version": "1.7",
                        "document_info_dict": {
                            "Title": "Sample document",
                            "Author": "Adobe Systems Incorporated",
                            "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
                            "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
                            "CreationDate": "20070412090123-02"
                        },
                        "pdfid0": "DFCE52BD827ECF765649852119D",
                        "pdfid1": "57A1E0F9ED2AE523E313C"
                    }
                }
            }
        }
    }]
    resp = list(apply_common_filters(stix_objects, [Filter("objects.0.extensions.pdf-ext.version", ">", "1.2")]))
    assert resp[0]['id'] == stix_objects[3]['id']
    assert len(resp) == 1


def test_deduplicate():
    unique = deduplicate(STIX_OBJS1)

    # Only 3 objects are unique
    # 2 id's vary
    # 2 modified times vary for a particular id

    assert len(unique) == 3

    ids = [obj['id'] for obj in unique]
    mods = [obj['modified'] for obj in unique]

    assert "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f" in ids
    assert "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f" in ids
    assert "2017-01-27T13:49:53.935Z" in mods
    assert "2017-01-27T13:49:53.936Z" in mods


def test_add_remove_composite_datasource():
    cds = CompositeDataSource()
    ds1 = MemorySource()
    ds2 = MemorySource()
    ds3 = MemorySink()

    with pytest.raises(TypeError) as excinfo:
        cds.add_data_sources([ds1, ds2, ds1, ds3])
    assert str(excinfo.value) == ("DataSource (to be added) is not of type "
                                  "stix2.DataSource. DataSource type is '<class 'stix2.sources.memory.MemorySink'>'")

    cds.add_data_sources([ds1, ds2, ds1])

    assert len(cds.get_all_data_sources()) == 2

    cds.remove_data_sources([ds1.id, ds2.id])

    assert len(cds.get_all_data_sources()) == 0


def test_composite_datasource_operations():
    BUNDLE1 = dict(id="bundle--%s" % make_id(),
                   objects=STIX_OBJS1,
                   spec_version="2.0",
                   type="bundle")
    cds1 = CompositeDataSource()
    ds1_1 = MemorySource(stix_data=BUNDLE1)
    ds1_2 = MemorySource(stix_data=STIX_OBJS2)

    cds2 = CompositeDataSource()
    ds2_1 = MemorySource(stix_data=BUNDLE1)
    ds2_2 = MemorySource(stix_data=STIX_OBJS2)

    cds1.add_data_sources([ds1_1, ds1_2])
    cds2.add_data_sources([ds2_1, ds2_2])

    indicators = cds1.all_versions("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    # In STIX_OBJS2 changed the 'modified' property to a later time...
    assert len(indicators) == 2

    cds1.add_data_sources([cds2])

    indicator = cds1.get("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    assert indicator["id"] == "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f"
    assert indicator["modified"] == "2017-01-31T13:49:53.935Z"
    assert indicator["type"] == "indicator"

    query1 = [
        Filter("type", "=", "indicator")
    ]

    query2 = [
        Filter("valid_from", "=", "2017-01-27T13:49:53.935382Z")
    ]

    cds1.filters.update(query2)

    results = cds1.query(query1)

    # STIX_OBJS2 has indicator with later time, one with different id, one with
    # original time in STIX_OBJS1
    assert len(results) == 3

    indicator = cds1.get("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    assert indicator["id"] == "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f"
    assert indicator["modified"] == "2017-01-31T13:49:53.935Z"
    assert indicator["type"] == "indicator"

    # There is only one indicator with different ID. Since we use the same data
    # when deduplicated, only two indicators (one with different modified).
    results = cds1.all_versions("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")
    assert len(results) == 2

    # Since we have filters already associated with our CompositeSource providing
    # nothing returns the same as cds1.query(query1) (the associated query is query2)
    results = cds1.query([])
    assert len(results) == 3
