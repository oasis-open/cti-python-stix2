import os

import pytest
from taxii2client import Collection

from stix2 import (Campaign, FileSystemSink, FileSystemSource, FileSystemStore,
                   Filter, MemorySource, MemoryStore)
from stix2.sources import (CompositeDataSource, DataSink, DataSource,
                           DataStore, make_id, taxii)
from stix2.sources.filters import apply_common_filters
from stix2.utils import deduplicate

COLLECTION_URL = 'https://example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/'
FS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")


class MockTAXIIClient(object):
    """Mock for taxii2_client.TAXIIClient"""
    pass


@pytest.fixture
def collection():
    return Collection(COLLECTION_URL, MockTAXIIClient())


@pytest.fixture
def ds():
    return DataSource()


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
    ds1 = DataSource()
    ds2 = DataSink()
    ds3 = DataStore(source=ds1, sink=ds2)

    with pytest.raises(NotImplementedError):
        ds3.add(None)

    with pytest.raises(NotImplementedError):
        ds3.all_versions("malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111")

    with pytest.raises(NotImplementedError):
        ds3.get("malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111")

    with pytest.raises(NotImplementedError):
        ds3.query([Filter("id", "=", "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111")])


def test_memory_store_smoke():
    # Initialize MemoryStore with dict
    ms = MemoryStore(STIX_OBJS1)

    # Add item to sink
    ms.add(dict(id="bundle--%s" % make_id(),
                objects=STIX_OBJS2,
                spec_version="2.0",
                type="bundle"))

    resp = ms.all_versions("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")
    assert len(resp) == 1

    resp = ms.get("indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")
    assert resp["id"] == "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f"

    query = [Filter('type', '=', 'malware')]

    resp = ms.query(query)
    assert len(resp) == 0


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


def test_add_get_remove_filter(ds):

    # First 3 filters are valid, remaining fields are erroneous in some way
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
    assert str(excinfo.value) == "Filter operator '*' not supported for specified field: 'modified'"

    with pytest.raises(TypeError) as excinfo:
        # create Filter that has a value type that is not allowed
        Filter('created', '=', object())
    # On Python 2, the type of object() is `<type 'object'>` On Python 3, it's `<class 'object'>`.
    assert str(excinfo.value).startswith("Filter value type")
    assert str(excinfo.value).endswith("is not supported. The type must be a python immutable type or dictionary")

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


def test_apply_common_filters(ds):
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
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[0]])]
    ids = [r['id'] for r in resp]
    assert stix_objs[0]['id'] in ids
    assert stix_objs[1]['id'] in ids
    assert stix_objs[3]['id'] in ids
    assert len(ids) == 3

    # "Return any object that matched id relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[1]])]
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains remote-access-trojan in labels"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[2]])]
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 1

    # "Return any object created after 2015-01-01T01:00:00.000Z"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[3]])]
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 2

    # "Return any revoked object"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[4]])]
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object whose not revoked"
    # Note that if 'revoked' property is not present in object.
    # Currently we can't use such an expression to filter for... :(
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[5]])]
    assert len(resp) == 0

    # "Return any object that matches marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9 in object_marking_refs"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[6]])]
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains relationship_type in their selectors AND
    # also has marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed in marking_ref"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[7], filters[8]])]
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    # "Return any object that contains CVE-2014-0160,CVE-2017-6608 in their external_id"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[9]])]
    assert resp[0]['id'] == stix_objs[3]['id']
    assert len(resp) == 1

    # "Return any object that matches created_by_ref identity--00000000-0000-0000-0000-b8e91df99dc9"
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[10]])]
    assert len(resp) == 1

    # "Return any object that matches marking-definition--613f2e26-0000-0000-0000-b8e91df99dc9 in object_marking_refs" (None)
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[11]])]
    assert len(resp) == 0

    # "Return any object that contains description in its selectors" (None)
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[12]])]
    assert len(resp) == 0

    # "Return any object that object that matches CVE in source_name" (None, case sensitive)
    resp = [stix_obj for stix_obj in apply_common_filters(stix_objs, [filters[13]])]
    assert len(resp) == 0


def test_filters0(ds):
    # "Return any object modified before 2017-01-28T13:49:53.935Z"
    resp = [stix_obj for stix_obj in apply_common_filters(STIX_OBJS2, [Filter("modified", "<", "2017-01-28T13:49:53.935Z")])]
    assert resp[0]['id'] == STIX_OBJS2[1]['id']
    assert len(resp) == 2


def test_filters1(ds):
    # "Return any object modified after 2017-01-28T13:49:53.935Z"
    resp = [stix_obj for stix_obj in apply_common_filters(STIX_OBJS2, [Filter("modified", ">", "2017-01-28T13:49:53.935Z")])]
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 1


def test_filters2(ds):
    # "Return any object modified after or on 2017-01-28T13:49:53.935Z"
    resp = [stix_obj for stix_obj in apply_common_filters(STIX_OBJS2, [Filter("modified", ">=", "2017-01-27T13:49:53.935Z")])]
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 3


def test_filters3(ds):
    # "Return any object modified before or on 2017-01-28T13:49:53.935Z"
    resp = [stix_obj for stix_obj in apply_common_filters(STIX_OBJS2, [Filter("modified", "<=", "2017-01-27T13:49:53.935Z")])]
    assert resp[0]['id'] == STIX_OBJS2[1]['id']
    assert len(resp) == 2


def test_filters4(ds):
    # Assert invalid Filter cannot be created
    with pytest.raises(ValueError) as excinfo:
        Filter("modified", "?", "2017-01-27T13:49:53.935Z")
    assert str(excinfo.value) == ("Filter operator '?' not supported "
                                  "for specified field: 'modified'")


def test_filters5(ds):
    # "Return any object whose id is not indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f"
    resp = [stix_obj for stix_obj in apply_common_filters(STIX_OBJS2, [Filter("id", "!=", "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")])]
    assert resp[0]['id'] == STIX_OBJS2[0]['id']
    assert len(resp) == 1


def test_deduplicate(ds):
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
    ds1 = DataSource()
    ds2 = DataSource()
    ds3 = DataSink()

    with pytest.raises(TypeError) as excinfo:
        cds.add_data_sources([ds1, ds2, ds1, ds3])
    assert str(excinfo.value) == ("DataSource (to be added) is not of type "
                                  "stix2.DataSource. DataSource type is '<class 'stix2.sources.DataSink'>'")

    cds.add_data_sources([ds1, ds2, ds1])

    assert len(cds.get_all_data_sources()) == 2

    cds.remove_data_sources([ds1.id, ds2.id])

    assert len(cds.get_all_data_sources()) == 0


def test_composite_datasource_operations():
    BUNDLE1 = dict(id="bundle--%s" % make_id(),
                   objects=STIX_OBJS1,
                   spec_version="2.0",
                   type="bundle")
    cds = CompositeDataSource()
    ds1 = MemorySource(stix_data=BUNDLE1)
    ds2 = MemorySource(stix_data=STIX_OBJS2)

    cds.add_data_sources([ds1, ds2])

    indicators = cds.all_versions("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    # In STIX_OBJS2 changed the 'modified' property to a later time...
    assert len(indicators) == 2

    indicator = cds.get("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    assert indicator["id"] == "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f"
    assert indicator["modified"] == "2017-01-31T13:49:53.935Z"
    assert indicator["type"] == "indicator"

    query = [
        Filter("type", "=", "indicator")
    ]

    results = cds.query(query)

    # STIX_OBJS2 has indicator with later time, one with different id, one with
    # original time in STIX_OBJS1
    assert len(results) == 3


def test_filesytem_source():
    # creation
    fs_source = FileSystemSource(FS_PATH)
    assert fs_source.stix_dir == FS_PATH

    # get object
    mal = fs_source.get("malware--6b616fc1-1505-48e3-8b2c-0d19337bff38")
    assert mal.id == "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"
    assert mal.name == "Rover"

    # all versions - (currently not a true all versions call as FileSystem cant have multiple versions)
    id_ = fs_source.get("identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5")
    assert id_.id == "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
    assert id_.name == "The MITRE Corporation"
    assert id_.type == "identity"

    # query
    intrusion_sets = fs_source.query([Filter("type", '=', "intrusion-set")])
    assert len(intrusion_sets) == 2
    assert "intrusion-set--a653431d-6a5e-4600-8ad3-609b5af57064" in [is_.id for is_ in intrusion_sets]
    assert "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a" in [is_.id for is_ in intrusion_sets]

    is_1 = [is_ for is_ in intrusion_sets if is_.id == "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a"][0]
    assert "DragonOK" in is_1.aliases
    assert len(is_1.external_references) == 4

    # query2
    is_2 = fs_source.query([Filter("external_references.external_id", '=', "T1027")])
    assert len(is_2) == 1

    is_2 = is_2[0]
    assert is_2.id == "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a"
    assert is_2.type == "attack-pattern"


def test_filesystem_sink():
    # creation
    fs_sink = FileSystemSink(FS_PATH)
    assert fs_sink.stix_dir == FS_PATH

    fs_source = FileSystemSource(FS_PATH)

    # Test all the ways stix objects can be added (via different supplied forms)

    # add python stix object
    camp1 = Campaign(name="Hannibal",
                     objective="Targeting Italian and Spanish Diplomat internet accounts",
                     aliases=["War Elephant"])

    fs_sink.add(camp1)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", camp1.id + ".json"))

    camp1_r = fs_source.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == "Hannibal"
    assert "War Elephant" in camp1_r.aliases

    # add stix object dict
    camp2 = {
        "name": "Aurelius",
        "type": "campaign",
        "objective": "German and French Intelligence Services",
        "aliases": ["Purple Robes"],
        "id": "campaign--111111b6-1112-4fb0-111b-b111107ca70a",
        "created": "2017-05-31T21:31:53.197755Z"
    }

    fs_sink.add(camp2)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", camp2["id"] + ".json"))

    camp2_r = fs_source.get(camp2["id"])
    assert camp2_r.id == camp2["id"]
    assert camp2_r.name == camp2["name"]
    assert "Purple Robes" in camp2_r.aliases

    # add stix bundle dict
    bund = {
        "type": "bundle",
        "id": "bundle--112211b6-1112-4fb0-111b-b111107ca70a",
        "spec_version": "2.0",
        "objects": [
            {
                "name": "Atilla",
                "type": "campaign",
                "objective": "Bulgarian, Albanian and Romanian Intelligence Services",
                "aliases": ["Huns"],
                "id": "campaign--133111b6-1112-4fb0-111b-b111107ca70a",
                "created": "2017-05-31T21:31:53.197755Z"
            }
        ]
    }

    fs_sink.add(bund)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", bund["objects"][0]["id"] + ".json"))

    camp3_r = fs_source.get(bund["objects"][0]["id"])
    assert camp3_r.id == bund["objects"][0]["id"]
    assert camp3_r.name == bund["objects"][0]["name"]
    assert "Huns" in camp3_r.aliases

    # add json-encoded stix obj
    camp4 = '{"type": "campaign", "id":"campaign--144111b6-1112-4fb0-111b-b111107ca70a",'\
            ' "created":"2017-05-31T21:31:53.197755Z", "name": "Ghengis Khan", "objective": "China and Russian infrastructure"}'

    fs_sink.add(camp4)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", "campaign--144111b6-1112-4fb0-111b-b111107ca70a" + ".json"))

    camp4_r = fs_source.get("campaign--144111b6-1112-4fb0-111b-b111107ca70a")
    assert camp4_r.id == "campaign--144111b6-1112-4fb0-111b-b111107ca70a"
    assert camp4_r.name == "Ghengis Khan"

    # add json-encoded stix bundle
    bund2 = '{"type": "bundle", "id": "bundle--332211b6-1132-4fb0-111b-b111107ca70a",' \
            ' "spec_version": "2.0", "objects": [{"type": "campaign", "id": "campaign--155155b6-1112-4fb0-111b-b111107ca70a",' \
            ' "created":"2017-05-31T21:31:53.197755Z", "name": "Spartacus", "objective": "Oppressive regimes of Africa and Middle East"}]}'
    fs_sink.add(bund2)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", "campaign--155155b6-1112-4fb0-111b-b111107ca70a" + ".json"))

    camp5_r = fs_source.get("campaign--155155b6-1112-4fb0-111b-b111107ca70a")
    assert camp5_r.id == "campaign--155155b6-1112-4fb0-111b-b111107ca70a"
    assert camp5_r.name == "Spartacus"

    # add list of objects
    camp6 = Campaign(name="Comanche",
                     objective="US Midwest manufacturing firms, oil refineries, and businesses",
                     aliases=["Horse Warrior"])

    camp7 = {
        "name": "Napolean",
        "type": "campaign",
        "objective": "Central and Eastern Europe military commands and departments",
        "aliases": ["The Frenchmen"],
        "id": "campaign--122818b6-1112-4fb0-111b-b111107ca70a",
        "created": "2017-05-31T21:31:53.197755Z"
    }

    fs_sink.add([camp6, camp7])

    assert os.path.exists(os.path.join(FS_PATH, "campaign", camp6.id + ".json"))
    assert os.path.exists(os.path.join(FS_PATH, "campaign", "campaign--122818b6-1112-4fb0-111b-b111107ca70a" + ".json"))

    camp6_r = fs_source.get(camp6.id)
    assert camp6_r.id == camp6.id
    assert "Horse Warrior" in camp6_r.aliases

    camp7_r = fs_source.get(camp7["id"])
    assert camp7_r.id == camp7["id"]
    assert "The Frenchmen" in camp7_r.aliases

    # remove all added objects
    os.remove(os.path.join(FS_PATH, "campaign", camp1_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp2_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp3_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp4_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp5_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp6_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp7_r.id + ".json"))

    # remove campaign dir (that was added in course of testing)
    os.rmdir(os.path.join(FS_PATH, "campaign"))


def test_filesystem_store():
    # creation
    fs_store = FileSystemStore(FS_PATH)

    # get()
    coa = fs_store.get("course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd")
    assert coa.id == "course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd"
    assert coa.type == "course-of-action"

    # all versions() - (note at this time, all_versions() is still not applicable to FileSystem, as only one version is ever stored)
    rel = fs_store.all_versions("relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1")[0]
    assert rel.id == "relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1"
    assert rel.type == "relationship"

    # query()
    tools = fs_store.query([Filter("labels", "in", "tool")])
    assert len(tools) == 2
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [tool.id for tool in tools]
    assert "tool--03342581-f790-4f03-ba41-e82e67392e23" in [tool.id for tool in tools]

    # add()
    camp1 = Campaign(name="Great Heathen Army",
                     objective="Targeting the government of United Kingdom and insitutions affiliated with the Church Of Englang",
                     aliases=["Ragnar"])
    fs_store.add(camp1)

    camp1_r = fs_store.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == camp1.name

    # remove
    os.remove(os.path.join(FS_PATH, "campaign", camp1_r.id + ".json"))

    # remove campaign dir
    os.rmdir(os.path.join(FS_PATH, "campaign"))
