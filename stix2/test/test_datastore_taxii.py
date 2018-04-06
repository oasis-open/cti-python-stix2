COLLECTION_URL = 'https://example.com/api1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/'


class MockTAXIIClient(object):
    """Mock for taxii2_client.TAXIIClient"""
    pass


@pytest.fixture
def collection():
    return Collection(COLLECTION_URL, MockTAXIIClient())


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

    taxii_filters_expected = set([
        Filter("added_after", "=", "2016-02-01T00:00:01.000Z"),
        Filter("id", "=", "taxii stix object ID"),
        Filter("type", "=", "taxii stix object ID"),
        Filter("version", "=", "first")
    ])

    ds = taxii.TAXIICollectionSource(collection)

    taxii_filters = ds._parse_taxii_filters(query)

    assert taxii_filters == taxii_filters_expected


def test_add_get_remove_filter():
    ds = taxii.TAXIICollectionSource(collection)

    # First 3 filters are valid, remaining properties are erroneous in some way
    valid_filters = [
        Filter('type', '=', 'malware'),
        Filter('id', '!=', 'stix object id'),
        Filter('labels', 'in', ["heartbleed", "malicious-activity"]),
    ]

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
