import os
import shutil

import pytest

from stix2 import (Bundle, Campaign, CustomObject, Filter, MemorySource,
                   MemoryStore, properties)
from stix2.sources import make_id

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


@pytest.fixture
def mem_store():
    yield MemoryStore(STIX_OBJS1)


@pytest.fixture
def mem_source():
    yield MemorySource(STIX_OBJS1)


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


def test_memory_store_save_load_file(mem_store):
    filename = 'memory_test/mem_store.json'
    mem_store.save_to_file(filename)
    contents = open(os.path.abspath(filename)).read()

    assert '"id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",' in contents
    assert '"id": "indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f",' in contents

    mem_store2 = MemoryStore()
    mem_store2.load_from_file(filename)
    assert mem_store2.get("indicator--d81f86b8-975b-bc0b-775e-810c5ad45a4f")
    assert mem_store2.get("indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f")

    shutil.rmtree(os.path.dirname(filename))


def test_memory_store_add_stix_object_str(mem_store):
    # add stix object string
    camp_id = "campaign--111111b6-1112-4fb0-111b-b111107ca70a"
    camp_name = "Aurelius"
    camp_alias = "Purple Robes"
    camp = """{
        "name": "%s",
        "type": "campaign",
        "objective": "German and French Intelligence Services",
        "aliases": ["%s"],
        "id": "%s",
        "created": "2017-05-31T21:31:53.197755Z"
    }""" % (camp_name, camp_alias, camp_id)

    mem_store.add(camp)

    camp_r = mem_store.get(camp_id)
    assert camp_r["id"] == camp_id
    assert camp_r["name"] == camp_name
    assert camp_alias in camp_r["aliases"]


def test_memory_store_add_stix_bundle_str(mem_store):
    # add stix bundle string
    camp_id = "campaign--133111b6-1112-4fb0-111b-b111107ca70a"
    camp_name = "Atilla"
    camp_alias = "Huns"
    bund = """{
        "type": "bundle",
        "id": "bundle--112211b6-1112-4fb0-111b-b111107ca70a",
        "spec_version": "2.0",
        "objects": [
            {
                "name": "%s",
                "type": "campaign",
                "objective": "Bulgarian, Albanian and Romanian Intelligence Services",
                "aliases": ["%s"],
                "id": "%s",
                "created": "2017-05-31T21:31:53.197755Z"
            }
        ]
    }""" % (camp_name, camp_alias, camp_id)

    mem_store.add(bund)

    camp_r = mem_store.get(camp_id)
    assert camp_r["id"] == camp_id
    assert camp_r["name"] == camp_name
    assert camp_alias in camp_r["aliases"]


def test_memory_store_add_invalid_object(mem_store):
    ind = ('indicator', IND1)  # tuple isn't valid
    with pytest.raises(TypeError) as excinfo:
        mem_store.add(ind)
    assert 'stix_data must be' in str(excinfo.value)
    assert 'a STIX object' in str(excinfo.value)
    assert 'JSON formatted STIX' in str(excinfo.value)
    assert 'JSON formatted STIX bundle' in str(excinfo.value)


def test_memory_store_object_with_custom_property(mem_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    mem_store.add(camp, True)

    camp_r = mem_store.get(camp.id)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_memory_store_object_with_custom_property_in_bundle(mem_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    bundle = Bundle(camp, allow_custom=True)
    mem_store.add(bundle, True)

    bundle_r = mem_store.get(bundle.id)
    camp_r = bundle_r['objects'][0]
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_memory_store_custom_object(mem_store):
    @CustomObject('x-new-obj', [
        ('property1', properties.StringProperty(required=True)),
    ])
    class NewObj():
        pass

    newobj = NewObj(property1='something')
    mem_store.add(newobj, True)

    newobj_r = mem_store.get(newobj.id)
    assert newobj_r.id == newobj.id
    assert newobj_r.property1 == 'something'
