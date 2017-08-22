import pytest
from taxii2client import Collection

from stix2.sources import DataSource, Filter, taxii

COLLECTION_URL = 'https://example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/'


class MockTAXIIClient(object):
    """Mock for taxii2_client.TAXIIClient"""

    def get(self):
        return {}

    def post(self):
        return {}


@pytest.fixture
def collection():
    return Collection(COLLECTION_URL, MockTAXIIClient())


def test_ds_taxii(collection):
    ds = taxii.TAXIICollectionSource(collection)
    assert ds.name == 'TAXIICollectionSource'


def test_ds_taxii_name(collection):
    ds = taxii.TAXIICollectionSource(collection, name='My Data Source Name')
    assert ds.name == "My Data Source Name"


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

    # First 3 filters are valid, remaining fields are erroneous in some way
    valid_filters = [
        Filter('type', '=', 'malware'),
        Filter('id', '!=', 'stix object id'),
        Filter('labels', 'in', ["heartbleed", "malicious-activity"]),
    ]
    invalid_filters = [
        Filter('description', '=', 'not supported field - just place holder'),
        Filter('modified', '*', 'not supported operator - just place holder'),
        Filter('created', '=', object()),
    ]

    ds = DataSource()

    assert len(ds.filters) == 0

    ds.add_filter(valid_filters[0])
    assert len(ds.filters) == 1

    # Addin the same filter again will have no effect since `filters` uses a set
    ds.add_filter(valid_filters[0])
    assert len(ds.filters) == 1

    ds.add_filter(valid_filters[1])
    assert len(ds.filters) == 2
    ds.add_filter(valid_filters[2])
    assert len(ds.filters) == 3

    # TODO: make better error messages
    with pytest.raises(ValueError) as excinfo:
        ds.add_filter(invalid_filters[0])
    assert str(excinfo.value) == "Filter 'field' is not a STIX 2.0 common property. Currently only STIX object common properties supported"

    with pytest.raises(ValueError) as excinfo:
        ds.add_filter(invalid_filters[1])
    assert str(excinfo.value) == "Filter operation(from 'op' field) not supported"

    with pytest.raises(ValueError) as excinfo:
        ds.add_filter(invalid_filters[2])
    assert str(excinfo.value) == "Filter 'value' type is not supported. The type(value) must be python immutable type or dictionary"

    assert set(valid_filters) == ds.filters

    # remove
    ds.filters.remove(valid_filters[0])

    assert len(ds.filters) == 2


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
            "id": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463",
            "modified": "2014-05-08T09:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--a932fcc6-e032-176c-126f-cb970a5a1ade",
            "target_ref": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
            "type": "relationship"
        }
    ]

    filters = [
        Filter("type", "!=", "relationship"),
        Filter("id", "=", "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"),
        Filter("labels", "in", "remote-access-trojan"),
    ]

    ds = DataSource()

    resp = ds.apply_common_filters(stix_objs, [filters[0]])
    ids = [r['id'] for r in resp]
    assert stix_objs[0]['id'] in ids
    assert stix_objs[1]['id'] in ids

    resp = ds.apply_common_filters(stix_objs, [filters[1]])
    assert resp[0]['id'] == stix_objs[2]['id']

    resp = ds.apply_common_filters(stix_objs, [filters[2]])
    assert resp[0]['id'] == stix_objs[0]['id']


def test_deduplicate():
    stix_objs = [
        {
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
        },
        {
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
        },
        {
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
        },
        {
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
        },
        {
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
    ]

    ds = DataSource()
    unique = ds.deduplicate(stix_objs)

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


# def test_data_source_file():
#     ds = file.FileDataSource()
#
#     assert ds.name == "DataSource"
#
#
# def test_data_source_name():
#     ds = file.FileDataSource(name="My File Data Source")
#
#     assert ds.name == "My File Data Source"
#
#
# def test_data_source_get():
#     ds = file.FileDataSource(name="My File Data Source")
#
#     with pytest.raises(NotImplementedError):
#         ds.get("foo")
#
# #filter testing
# def test_add_filter():
#     ds = file.FileDataSource()
