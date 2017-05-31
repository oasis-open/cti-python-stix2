from stix2.sources import taxii


def test_ds_taxii():
    ds = taxii.TAXIIDataSource()
    assert ds.name == 'TAXII'


def test_ds_taxii_name():
    ds = taxii.TAXIIDataSource(name='My Data Source Name')
    assert ds.name == "My Data Source Name"


def test_ds_params():
    url = "http://taxii_url.com:5000"
    creds = {"username": "Wade", "password": "Wilson"}
    ds = taxii.TAXIIDataSource(api_root=url, auth=creds)
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

    ds = taxii.TAXIIDataSource()

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

    ds = taxii.TAXIIDataSource()
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
