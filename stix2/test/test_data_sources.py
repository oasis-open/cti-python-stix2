from stix2.sources import taxii


def test_ds_taxii():
    ds = taxii.TAXIICollectionSource()
    assert ds.name == 'TAXII'


def test_ds_taxii_name():
    ds = taxii.TAXIICollectionSource(name='My Data Source Name')
    assert ds.name == "My Data Source Name"


def test_ds_params():
    url = "http://taxii_url.com:5000"
    creds = {"username": "Wade", "password": "Wilson"}
    ds = taxii.TAXIICollectionSource(api_root=url, auth=creds)
    assert ds.taxii_info['api_root']['url'] == url
    assert ds.taxii_info['auth'] == creds


def test_parse_taxii_filters():
    query = [
        {
            "field": "added_after",
            "op": "=",
            "value": "2016-02-01T00:00:01.000Z"
        },
        {
            "field": "id",
            "op": "=",
            "value": "taxii stix object ID"
        },
        {
            "field": "type",
            "op": "=",
            "value": "taxii stix object ID"
        },
        {
            "field": "version",
            "op": "=",
            "value": "first"
        },
        {
            "field": "created_by_ref",
            "op": "=",
            "value": "Bane"
        }
    ]

    expected_params = {
        "added_after": "2016-02-01T00:00:01.000Z",
        "match[id]": "taxii stix object ID",
        "match[type]": "taxii stix object ID",
        "match[version]": "first"
    }

    ds = taxii.TAXIICollectionSource()

    taxii_filters = ds._parse_taxii_filters(query)

    assert taxii_filters == expected_params


def test_add_get_remove_filter():

    class dummy(object):
        x = 4

    obj_1 = dummy()

    # First 3 filters are valid, remaining fields are erroneous in some way
    filters = [
        {
            "field": "type",
            "op": '=',
            "value": "malware"
        },
        {
            "field": "id",
            "op": "!=",
            "value": "stix object id"
        },
        {
            "field": "labels",
            "op": "in",
            "value": ["heartbleed", "malicious-activity"]
        },
        {
            "field": "revoked",
            "value": "filter missing \'op\' field"
        },
        {
            "field": "granular_markings",
            "op": "=",
            "value": "not supported field - just place holder"
        },
        {
            "field": "modified",
            "op": "*",
            "value": "not supported operator - just place holder"
        },
        {
            "field": "created",
            "op": "=",
            "value": obj_1
        }
    ]

    expected_errors = [
        "Filter was missing a required field(key). Each filter requires 'field', 'op', 'value' keys.",
        "Filter 'field' is not a STIX 2.0 common property. Currently only STIX object common properties supported",
        "Filter operation(from 'op' field) not supported",
        "Filter 'value' type is not supported. The type(value) must be python immutable type or dictionary"
    ]

    ds = taxii.TAXIICollectionSource()
    # add
    ids, statuses = ds.add_filter(filters)

    # 7 filters should have been successfully added
    assert len(ids) == 7

    # all filters added to data source
    for idx, status in enumerate(statuses):
        assert status['filter'] == filters[idx]

    # proper status warnings were triggered
    assert statuses[3]['errors'][0] == expected_errors[0]
    assert statuses[4]['errors'][0] == expected_errors[1]
    assert statuses[5]['errors'][0] == expected_errors[2]
    assert statuses[6]['errors'][0] == expected_errors[3]

    # get
    ds_filters = ds.get_filters()

    # TODO: what are we trying to test here?
    for idx, flt in enumerate(filters):
        assert flt['value'] == ds_filters[idx]['value']

    # remove
    ds.remove_filter([ids[3]])
    ds.remove_filter([ids[4]])
    ds.remove_filter([ids[5]])
    ds.remove_filter([ids[6]])

    rem_filters = ds.get_filters()

    assert len(rem_filters) == 3

    # check remaining filters
    rem_ids = [f['id'] for f in rem_filters]

    # check remaining
    for id_ in rem_ids:
        assert id_ in ids[:3]


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
        {
            "field": "type",
            "op": "!=",
            "value": "relationship"
        },
        {
            "field": "id",
            "op": "=",
            "value": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"
        },
        {
            "field": "labels",
            "op": "in",
            "value": "trojan"
        }
    ]

    ds = taxii.TAXIICollectionSource()

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

    ds = taxii.TAXIICollectionSource()
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
