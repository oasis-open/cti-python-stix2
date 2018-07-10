import os
import shutil

import pytest

from stix2 import Filter, MemorySource, MemoryStore, properties
from stix2.datastore import make_id
from stix2.v21 import (Bundle, Campaign, CustomObject, Identity, Indicator,
                       Malware, Relationship)

from .constants import (CAMPAIGN_ID, CAMPAIGN_KWARGS, IDENTITY_ID,
                        IDENTITY_KWARGS, INDICATOR_ID, INDICATOR_KWARGS,
                        MALWARE_ID, MALWARE_KWARGS, RELATIONSHIP_IDS)

IND1 = {
    "created": "2017-01-27T13:49:53.935Z",
    "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
    "labels": [
        "url-watchlist"
    ],
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Malicious site hosting downloader",
    "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
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
    "spec_version": "2.1",
    "type": "indicator",
    "valid_from": "2017-01-27T13:49:53.935382Z"
}

STIX_OBJS2 = [IND6, IND7, IND8]
STIX_OBJS1 = [IND1, IND2, IND3, IND4, IND5]


@pytest.fixture
def mem_store():
    yield MemoryStore(STIX_OBJS1)


@pytest.fixture
def mem_source():
    yield MemorySource(STIX_OBJS1)


@pytest.fixture
def rel_mem_store():
    cam = Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    mal = Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    rel1 = Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    stix_objs = [cam, idy, ind, mal, rel1, rel2, rel3]
    yield MemoryStore(stix_objs)


@pytest.fixture
def fs_mem_store(request, mem_store):
    filename = 'memory_test/mem_store.json'
    mem_store.save_to_file(filename)

    def fin():
        # teardown, excecuted regardless of exception
        shutil.rmtree(os.path.dirname(filename))
    request.addfinalizer(fin)

    return filename


def test_memory_source_get(mem_source):
    resp = mem_source.get("indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")
    assert resp["id"] == "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f"


def test_memory_source_get_nonexistant_object(mem_source):
    resp = mem_source.get("tool--d81f86b8-975b-bc0b-775e-810c5ad45a4f")
    assert resp is None


def test_memory_store_all_versions(mem_store):
    # Add bundle of items to sink
    mem_store.add(dict(id="bundle--%s" % make_id(),
                  objects=STIX_OBJS2,
                  spec_version="2.0",
                  type="bundle"))

    resp = mem_store.all_versions("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")
    assert len(resp) == 1  # MemoryStore can only store 1 version of each object


def test_memory_store_query(mem_store):
    query = [Filter('type', '=', 'malware')]
    resp = mem_store.query(query)
    assert len(resp) == 0


def test_memory_store_query_single_filter(mem_store):
    query = Filter('id', '=', 'indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f')
    resp = mem_store.query(query)
    assert len(resp) == 1


def test_memory_store_query_empty_query(mem_store):
    resp = mem_store.query()
    # sort since returned in random order
    resp = sorted(resp, key=lambda k: k['id'])
    assert len(resp) == 2
    assert resp[0]['id'] == 'indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f'
    assert resp[0]['modified'] == '2017-01-27T13:49:53.935Z'
    assert resp[1]['id'] == 'indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f'
    assert resp[1]['modified'] == '2017-01-27T13:49:53.936Z'


def test_memory_store_query_multiple_filters(mem_store):
    mem_store.source.filters.add(Filter('type', '=', 'indicator'))
    query = Filter('id', '=', 'indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f')
    resp = mem_store.query(query)
    assert len(resp) == 1


def test_memory_store_save_load_file(mem_store, fs_mem_store):
    filename = fs_mem_store  # the fixture fs_mem_store yields filename where the memory store was written to

    # STIX2 contents of mem_store have already been written to file
    # (this is done in fixture 'fs_mem_store'), so can already read-in here
    contents = open(os.path.abspath(filename)).read()

    assert '"id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",' in contents
    assert '"id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",' in contents

    mem_store2 = MemoryStore()
    mem_store2.load_from_file(filename)
    assert mem_store2.get("indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")
    assert mem_store2.get("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")


def test_memory_store_add_invalid_object(mem_store):
    ind = ('indicator', IND1)  # tuple isn't valid
    with pytest.raises(TypeError) as excinfo:
        mem_store.add(ind)
    assert 'stix_data expected to be' in str(excinfo.value)
    assert 'a python-stix2 object' in str(excinfo.value)
    assert 'JSON formatted STIX' in str(excinfo.value)
    assert 'JSON formatted STIX bundle' in str(excinfo.value)


def test_memory_store_object_with_custom_property(mem_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    mem_store.add(camp)

    camp_r = mem_store.get(camp.id)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_memory_store_object_with_custom_property_in_bundle(mem_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    bundle = Bundle(camp, allow_custom=True)
    mem_store.add(bundle)

    camp_r = mem_store.get(camp.id)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_memory_store_custom_object(mem_store):
    @CustomObject('x-new-obj', [
        ('property1', properties.StringProperty(required=True)),
    ])
    class NewObj():
        pass

    newobj = NewObj(property1='something')
    mem_store.add(newobj)

    newobj_r = mem_store.get(newobj.id)
    assert newobj_r.id == newobj.id
    assert newobj_r.property1 == 'something'


def test_relationships(rel_mem_store):
    mal = rel_mem_store.get(MALWARE_ID)
    resp = rel_mem_store.relationships(mal)

    assert len(resp) == 3
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[1] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_type(rel_mem_store):
    mal = rel_mem_store.get(MALWARE_ID)
    resp = rel_mem_store.relationships(mal, relationship_type='indicates')

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[0]


def test_relationships_by_source(rel_mem_store):
    resp = rel_mem_store.relationships(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[1]


def test_relationships_by_target(rel_mem_store):
    resp = rel_mem_store.relationships(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_type(rel_mem_store):
    resp = rel_mem_store.relationships(MALWARE_ID, relationship_type='uses', target_only=True)

    assert len(resp) == 1
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_source(rel_mem_store):
    with pytest.raises(ValueError) as excinfo:
        rel_mem_store.relationships(MALWARE_ID, target_only=True, source_only=True)

    assert 'not both' in str(excinfo.value)


def test_related_to(rel_mem_store):
    mal = rel_mem_store.get(MALWARE_ID)
    resp = rel_mem_store.related_to(mal)

    assert len(resp) == 3
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
    assert any(x['id'] == IDENTITY_ID for x in resp)


def test_related_to_by_source(rel_mem_store):
    resp = rel_mem_store.related_to(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert any(x['id'] == IDENTITY_ID for x in resp)


def test_related_to_by_target(rel_mem_store):
    resp = rel_mem_store.related_to(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
