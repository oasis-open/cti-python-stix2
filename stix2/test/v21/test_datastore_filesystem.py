import datetime
import errno
import json
import os
import shutil
import stat

import pytest
import pytz

import stix2
from stix2.datastore.filesystem import (
    AuthSet, _find_search_optimizations, _get_matching_dir_entries,
    _timestamp2filename,
)
from stix2.exceptions import STIXError

from .constants import (
    CAMPAIGN_ID, CAMPAIGN_KWARGS, IDENTITY_ID, IDENTITY_KWARGS, INDICATOR_ID,
    INDICATOR_KWARGS, MALWARE_ID, MALWARE_KWARGS, RELATIONSHIP_IDS,
)

FS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")


@pytest.fixture
def fs_store():
    # create
    yield stix2.FileSystemStore(FS_PATH)

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


@pytest.fixture
def fs_source():
    # create
    fs = stix2.FileSystemSource(FS_PATH)
    assert fs.stix_dir == FS_PATH
    yield fs

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


@pytest.fixture
def fs_sink():
    # create
    fs = stix2.FileSystemSink(FS_PATH)
    assert fs.stix_dir == FS_PATH
    yield fs

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


@pytest.fixture
def bad_json_files():
    # create erroneous JSON files for tests to make sure handled gracefully

    with open(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-non-json.txt"), "w+") as f:
        f.write("Im not a JSON file")

    with open(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-bad-json.json"), "w+") as f:
        f.write("Im not a JSON formatted file")

    yield True  # dummy yield so can have teardown

    os.remove(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-non-json.txt"))
    os.remove(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-bad-json.json"))


@pytest.fixture
def bad_stix_files():
    # create erroneous STIX JSON files for tests to make sure handled correctly

    # bad STIX object
    stix_obj = {
        "id": "intrusion-set--test-bad-stix",
        "spec_version": "2.0",
        # no "type" field
    }

    with open(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-non-stix.json"), "w+") as f:
        f.write(json.dumps(stix_obj))

    yield True  # dummy yield so can have teardown

    os.remove(os.path.join(FS_PATH, "intrusion-set", "intrusion-set--test-non-stix.json"))


@pytest.fixture(scope='module')
def rel_fs_store():
    cam = stix2.v21.Campaign(id=CAMPAIGN_ID, **CAMPAIGN_KWARGS)
    idy = stix2.v21.Identity(id=IDENTITY_ID, **IDENTITY_KWARGS)
    ind = stix2.v21.Indicator(id=INDICATOR_ID, **INDICATOR_KWARGS)
    mal = stix2.v21.Malware(id=MALWARE_ID, **MALWARE_KWARGS)
    rel1 = stix2.v21.Relationship(ind, 'indicates', mal, id=RELATIONSHIP_IDS[0])
    rel2 = stix2.v21.Relationship(mal, 'targets', idy, id=RELATIONSHIP_IDS[1])
    rel3 = stix2.v21.Relationship(cam, 'uses', mal, id=RELATIONSHIP_IDS[2])
    stix_objs = [cam, idy, ind, mal, rel1, rel2, rel3]
    fs = stix2.FileSystemStore(FS_PATH)
    for o in stix_objs:
        fs.add(o)
    yield fs

    for o in stix_objs:
        filepath = os.path.join(
            FS_PATH, o.type, o.id,
            _timestamp2filename(o.modified) + '.json',
        )

        # Some test-scoped fixtures (e.g. fs_store) delete all campaigns, so by
        # the time this module-scoped fixture tears itself down, it may find
        # its campaigns already gone, which causes not-found errors.
        try:
            os.remove(filepath)
        except OSError as e:
            # 3 is the ERROR_PATH_NOT_FOUND windows error code.  Which has an
            # errno symbolic value, but not the windows meaning...
            if e.errno in (errno.ENOENT, 3):
                continue
            raise


def test_filesystem_source_nonexistent_folder():
    with pytest.raises(ValueError) as excinfo:
        stix2.FileSystemSource('nonexistent-folder')
    assert "for STIX data does not exist" in str(excinfo)


def test_filesystem_sink_nonexistent_folder():
    with pytest.raises(ValueError) as excinfo:
        stix2.FileSystemSink('nonexistent-folder')
    assert "for STIX data does not exist" in str(excinfo)


def test_filesystem_source_bad_json_file(fs_source, bad_json_files):
    # this tests the handling of two bad json files
    #  - one file should just be skipped (silently) as its a ".txt" extension
    #  - one file should be parsed and raise Exception bc its not JSON
    try:
        fs_source.get("intrusion-set--test-bad-json")
    except TypeError as e:
        assert "intrusion-set--test-bad-json" in str(e)
        assert "could either not be parsed to JSON or was not valid STIX JSON" in str(e)


def test_filesystem_source_bad_stix_file(fs_source, bad_stix_files):
    # this tests handling of bad STIX json object
    try:
        fs_source.get("intrusion-set--test-non-stix")
    except STIXError as e:
        assert "Can't parse object with no 'type' property" in str(e)


def test_filesystem_source_get_object(fs_source):
    # get (latest) object
    mal = fs_source.get("malware--6b616fc1-1505-48e3-8b2c-0d19337bff38")
    assert mal.id == "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"
    assert mal.name == "Rover"
    assert mal.modified == datetime.datetime(
        2018, 11, 16, 22, 54, 20, 390000,
        pytz.utc,
    )


def test_filesystem_source_get_nonexistent_object(fs_source):
    ind = fs_source.get("indicator--6b616fc1-1505-48e3-8b2c-0d19337bff38")
    assert ind is None


def test_filesystem_source_all_versions(fs_source):
    ids = fs_source.all_versions(
        "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    )
    assert len(ids) == 2
    assert all(
        id_.id == "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
        for id_ in ids
    )
    assert all(id_.name == "The MITRE Corporation" for id_ in ids)
    assert all(id_.type == "identity" for id_ in ids)


def test_filesystem_source_query_single(fs_source):
    # query2
    is_2 = fs_source.query([stix2.Filter("external_references.external_id", '=', "T1027")])
    assert len(is_2) == 1

    is_2 = is_2[0]
    assert is_2.id == "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a"
    assert is_2.type == "attack-pattern"


def test_filesystem_source_query_multiple(fs_source):
    # query
    intrusion_sets = fs_source.query([stix2.Filter("type", '=', "intrusion-set")])
    assert len(intrusion_sets) == 2
    assert "intrusion-set--a653431d-6a5e-4600-8ad3-609b5af57064" in [is_.id for is_ in intrusion_sets]
    assert "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a" in [is_.id for is_ in intrusion_sets]

    is_1 = [is_ for is_ in intrusion_sets if is_.id == "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a"][0]
    assert "DragonOK" in is_1.aliases
    assert len(is_1.external_references) == 4


def test_filesystem_source_backward_compatible(fs_source):
    # this specific object is outside an "ID" directory; make sure we can get
    # it.
    modified = datetime.datetime(2018, 11, 16, 22, 54, 20, 390000, pytz.utc)
    results = fs_source.query([
        stix2.Filter("type", "=", "malware"),
        stix2.Filter("id", "=", "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"),
        stix2.Filter("modified", "=", modified),
    ])

    assert len(results) == 1
    result = results[0]
    assert result.type == "malware"
    assert result.id == "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"
    assert result.modified == modified
    assert result.malware_types == ["version four"]


def test_filesystem_sink_add_python_stix_object(fs_sink, fs_source):
    # add python stix object
    camp1 = stix2.v21.Campaign(
        name="Hannibal",
        objective="Targeting Italian and Spanish Diplomat internet accounts",
        aliases=["War Elephant"],
    )

    fs_sink.add(camp1)

    filepath = os.path.join(
        FS_PATH, "campaign", camp1.id,
        _timestamp2filename(camp1.modified) + ".json",
    )
    assert os.path.exists(filepath)

    camp1_r = fs_source.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == "Hannibal"
    assert "War Elephant" in camp1_r.aliases

    os.remove(filepath)


def test_filesystem_sink_add_stix_object_dict(fs_sink, fs_source):
    # add stix object dict
    camp2 = {
        "name": "Aurelius",
        "type": "campaign",
        "objective": "German and French Intelligence Services",
        "aliases": ["Purple Robes"],
        "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2017-05-31T21:31:53.197755Z",
        "modified": "2017-05-31T21:31:53.197755Z",
    }

    fs_sink.add(camp2)

    # Need to get the exact "modified" timestamp which would have been
    # in effect at the time the object was saved to the sink, which determines
    # the filename it would have been saved as.  It may not be exactly the same
    # as what's in the dict, since the parsing process can enforce a precision
    # constraint (e.g. truncate to milliseconds), which results in a slightly
    # different name.
    camp2obj = stix2.parse(camp2)
    filepath = os.path.join(
        FS_PATH, "campaign", camp2obj["id"],
        _timestamp2filename(camp2obj["modified"]) + ".json",
    )

    assert os.path.exists(filepath)

    camp2_r = fs_source.get(camp2["id"])
    assert camp2_r.id == camp2["id"]
    assert camp2_r.name == camp2["name"]
    assert "Purple Robes" in camp2_r.aliases

    os.remove(filepath)


def test_filesystem_sink_add_stix_bundle_dict(fs_sink, fs_source):
    # add stix bundle dict
    bund = {
        "type": "bundle",
        "id": "bundle--040ae5ec-2e91-4e94-b075-bc8b368e8ca3",
        "objects": [
            {
                "name": "Atilla",
                "type": "campaign",
                "objective": "Bulgarian, Albanian and Romanian Intelligence Services",
                "aliases": ["Huns"],
                "id": "campaign--b8f86161-ccae-49de-973a-4ca320c62478",
                "created": "2017-05-31T21:31:53.197755Z",
                "modified": "2017-05-31T21:31:53.197755Z",
            },
        ],
    }

    fs_sink.add(bund)

    camp_obj = stix2.parse(bund["objects"][0])
    filepath = os.path.join(
        FS_PATH, "campaign", camp_obj["id"],
        _timestamp2filename(camp_obj["modified"]) + ".json",
    )

    assert os.path.exists(filepath)

    camp3_r = fs_source.get(bund["objects"][0]["id"])
    assert camp3_r.id == bund["objects"][0]["id"]
    assert camp3_r.name == bund["objects"][0]["name"]
    assert "Huns" in camp3_r.aliases

    os.remove(filepath)


def test_filesystem_sink_add_json_stix_object(fs_sink, fs_source):
    # add json-encoded stix obj
    camp4 = '{"type": "campaign", "id":"campaign--6a6ca372-ba07-42cc-81ef-9840fc1f963d",'\
            ' "created":"2017-05-31T21:31:53.197755Z",'\
            ' "modified":"2017-05-31T21:31:53.197755Z",'\
            ' "name": "Ghengis Khan", "objective": "China and Russian infrastructure"}'

    fs_sink.add(camp4)

    camp4obj = stix2.parse(camp4)
    filepath = os.path.join(
        FS_PATH, "campaign",
        "campaign--6a6ca372-ba07-42cc-81ef-9840fc1f963d",
        _timestamp2filename(camp4obj["modified"]) + ".json",
    )

    assert os.path.exists(filepath)

    camp4_r = fs_source.get("campaign--6a6ca372-ba07-42cc-81ef-9840fc1f963d")
    assert camp4_r.id == "campaign--6a6ca372-ba07-42cc-81ef-9840fc1f963d"
    assert camp4_r.name == "Ghengis Khan"

    os.remove(filepath)


def test_filesystem_sink_json_stix_bundle(fs_sink, fs_source):
    # add json-encoded stix bundle
    bund2 = '{"type": "bundle", "id": "bundle--3d267103-8475-4d8f-b321-35ec6eccfa37",' \
            ' "spec_version": "2.0", "objects": [{"type": "campaign", "id": "campaign--2c03b8bf-82ee-433e-9918-ca2cb6e9534b",' \
            ' "created":"2017-05-31T21:31:53.197755Z",'\
            ' "modified":"2017-05-31T21:31:53.197755Z",'\
            ' "name": "Spartacus", "objective": "Oppressive regimes of Africa and Middle East"}]}'
    fs_sink.add(bund2)

    bund2obj = stix2.parse(bund2)
    camp_obj = bund2obj["objects"][0]

    filepath = os.path.join(
        FS_PATH, "campaign",
        "campaign--2c03b8bf-82ee-433e-9918-ca2cb6e9534b",
        _timestamp2filename(camp_obj["modified"]) + ".json",
    )

    assert os.path.exists(filepath)

    camp5_r = fs_source.get("campaign--2c03b8bf-82ee-433e-9918-ca2cb6e9534b")
    assert camp5_r.id == "campaign--2c03b8bf-82ee-433e-9918-ca2cb6e9534b"
    assert camp5_r.name == "Spartacus"

    os.remove(filepath)


def test_filesystem_sink_add_objects_list(fs_sink, fs_source):
    # add list of objects
    camp6 = stix2.v21.Campaign(
        name="Comanche",
        objective="US Midwest manufacturing firms, oil refineries, and businesses",
        aliases=["Horse Warrior"],
    )

    camp7 = {
        "name": "Napolean",
        "type": "campaign",
        "objective": "Central and Eastern Europe military commands and departments",
        "aliases": ["The Frenchmen"],
        "id": "campaign--122818b6-1112-4fb0-b11b-b111107ca70a",
        "created": "2017-05-31T21:31:53.197755Z",
        "modified": "2017-05-31T21:31:53.197755Z",
    }

    fs_sink.add([camp6, camp7])

    camp7obj = stix2.parse(camp7)

    camp6filepath = os.path.join(
        FS_PATH, "campaign", camp6.id,
        _timestamp2filename(camp6["modified"]) +
        ".json",
    )
    camp7filepath = os.path.join(
        FS_PATH, "campaign", "campaign--122818b6-1112-4fb0-b11b-b111107ca70a",
        _timestamp2filename(camp7obj["modified"]) + ".json",
    )

    assert os.path.exists(camp6filepath)
    assert os.path.exists(camp7filepath)

    camp6_r = fs_source.get(camp6.id)
    assert camp6_r.id == camp6.id
    assert "Horse Warrior" in camp6_r.aliases

    camp7_r = fs_source.get(camp7["id"])
    assert camp7_r.id == camp7["id"]
    assert "The Frenchmen" in camp7_r.aliases

    # remove all added objects
    os.remove(camp6filepath)
    os.remove(camp7filepath)


def test_filesystem_sink_marking(fs_sink):
    marking = stix2.v21.MarkingDefinition(
        definition_type="tlp",
        definition=stix2.v21.TLPMarking(tlp="green"),
    )

    fs_sink.add(marking)
    marking_filepath = os.path.join(
        FS_PATH, "marking-definition", marking["id"] + ".json",
    )

    assert os.path.exists(marking_filepath)

    os.remove(marking_filepath)


def test_filesystem_store_get_stored_as_bundle(fs_store):
    coa = fs_store.get("course-of-action--95ddb356-7ba0-4bd9-a889-247262b8946f")
    assert coa.id == "course-of-action--95ddb356-7ba0-4bd9-a889-247262b8946f"
    assert coa.type == "course-of-action"


def test_filesystem_store_get_stored_as_object(fs_store):
    coa = fs_store.get("course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd")
    assert coa.id == "course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd"
    assert coa.type == "course-of-action"


def test_filesystem_store_all_versions(fs_store):
    rels = fs_store.all_versions("relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1")
    assert len(rels) == 1
    rel = rels[0]
    assert rel.id == "relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1"
    assert rel.type == "relationship"


def test_filesystem_store_query(fs_store):
    # query()
    tools = fs_store.query([stix2.Filter("tool_types", "in", "tool")])
    assert len(tools) == 2
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [tool.id for tool in tools]
    assert "tool--03342581-f790-4f03-ba41-e82e67392e23" in [tool.id for tool in tools]


def test_filesystem_store_query_single_filter(fs_store):
    query = stix2.Filter("tool_types", "in", "tool")
    tools = fs_store.query(query)
    assert len(tools) == 2
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [tool.id for tool in tools]
    assert "tool--03342581-f790-4f03-ba41-e82e67392e23" in [tool.id for tool in tools]


def test_filesystem_store_empty_query(fs_store):
    results = fs_store.query()  # returns all
    assert len(results) == 30
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [obj.id for obj in results]
    assert "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" in [obj.id for obj in results]


def test_filesystem_store_query_multiple_filters(fs_store):
    fs_store.source.filters.add(stix2.Filter("tool_types", "in", "tool"))
    tools = fs_store.query(stix2.Filter("id", "=", "tool--242f3da3-4425-4d11-8f5c-b842886da966"))
    assert len(tools) == 1
    assert tools[0].id == "tool--242f3da3-4425-4d11-8f5c-b842886da966"


def test_filesystem_store_query_dont_include_type_folder(fs_store):
    results = fs_store.query(stix2.Filter("type", "!=", "tool"))
    assert len(results) == 28


def test_filesystem_store_add(fs_store):
    # add()
    camp1 = stix2.v21.Campaign(
        name="Great Heathen Army",
        objective="Targeting the government of United Kingdom and insitutions affiliated with the Church Of England",
        aliases=["Ragnar"],
    )
    fs_store.add(camp1)

    camp1_r = fs_store.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == camp1.name

    filepath = os.path.join(
        FS_PATH, "campaign", camp1_r.id,
        _timestamp2filename(camp1_r.modified) + ".json",
    )

    # remove
    os.remove(filepath)


def test_filesystem_store_add_as_bundle():
    fs_store = stix2.FileSystemStore(FS_PATH, bundlify=True)

    camp1 = stix2.v21.Campaign(
        name="Great Heathen Army",
        objective="Targeting the government of United Kingdom and insitutions affiliated with the Church Of England",
        aliases=["Ragnar"],
    )
    fs_store.add(camp1)

    filepath = os.path.join(
        FS_PATH, "campaign", camp1.id,
        _timestamp2filename(camp1.modified) + ".json",
    )

    with open(filepath) as bundle_file:
        assert '"type": "bundle"' in bundle_file.read()

    camp1_r = fs_store.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == camp1.name

    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


def test_filesystem_add_bundle_object(fs_store):
    bundle = stix2.v21.Bundle()
    fs_store.add(bundle)


def test_filesystem_store_add_invalid_object(fs_store):
    ind = ('campaign', 'campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f')   # tuple isn't valid
    with pytest.raises(TypeError) as excinfo:
        fs_store.add(ind)
    assert 'stix_data must be' in str(excinfo.value)
    assert 'a STIX object' in str(excinfo.value)
    assert 'JSON formatted STIX' in str(excinfo.value)
    assert 'JSON formatted STIX bundle' in str(excinfo.value)


def test_filesystem_store_add_marking(fs_store):
    marking = stix2.v21.MarkingDefinition(
        definition_type="tlp",
        definition=stix2.v21.TLPMarking(tlp="green"),
    )

    fs_store.add(marking)
    marking_filepath = os.path.join(
        FS_PATH, "marking-definition", marking["id"] + ".json",
    )

    assert os.path.exists(marking_filepath)

    marking_r = fs_store.get(marking["id"])
    assert marking_r["id"] == marking["id"]
    assert marking_r["definition"]["tlp"] == "green"

    os.remove(marking_filepath)


def test_filesystem_object_with_custom_property(fs_store):
    camp = stix2.v21.Campaign(
        name="Scipio Africanus",
        objective="Defeat the Carthaginians",
        x_empire="Roman",
        allow_custom=True,
    )

    fs_store.add(camp)

    camp_r = fs_store.get(camp.id)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_filesystem_object_with_custom_property_in_bundle(fs_store):
    camp = stix2.v21.Campaign(
        name="Scipio Africanus",
        objective="Defeat the Carthaginians",
        x_empire="Roman",
        allow_custom=True,
    )

    bundle = stix2.v21.Bundle(camp, allow_custom=True)
    fs_store.add(bundle)

    camp_r = fs_store.get(camp.id)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_filesystem_custom_object(fs_store):
    @stix2.v21.CustomObject(
        'x-new-obj', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj():
        pass

    newobj = NewObj(property1='something')
    fs_store.add(newobj)

    newobj_r = fs_store.get(newobj.id)
    assert newobj_r["id"] == newobj["id"]
    assert newobj_r["property1"] == 'something'

    # remove dir
    shutil.rmtree(os.path.join(FS_PATH, "x-new-obj"), True)


def test_relationships(rel_fs_store):
    mal = rel_fs_store.get(MALWARE_ID)
    resp = rel_fs_store.relationships(mal)

    assert len(resp) == 3
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[1] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_type(rel_fs_store):
    mal = rel_fs_store.get(MALWARE_ID)
    resp = rel_fs_store.relationships(mal, relationship_type='indicates')

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[0]


def test_relationships_by_source(rel_fs_store):
    resp = rel_fs_store.relationships(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert resp[0]['id'] == RELATIONSHIP_IDS[1]


def test_relationships_by_target(rel_fs_store):
    resp = rel_fs_store.relationships(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == RELATIONSHIP_IDS[0] for x in resp)
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_type(rel_fs_store):
    resp = rel_fs_store.relationships(MALWARE_ID, relationship_type='uses', target_only=True)

    assert len(resp) == 1
    assert any(x['id'] == RELATIONSHIP_IDS[2] for x in resp)


def test_relationships_by_target_and_source(rel_fs_store):
    with pytest.raises(ValueError) as excinfo:
        rel_fs_store.relationships(MALWARE_ID, target_only=True, source_only=True)

    assert 'not both' in str(excinfo.value)


def test_related_to(rel_fs_store):
    mal = rel_fs_store.get(MALWARE_ID)
    resp = rel_fs_store.related_to(mal)

    assert len(resp) == 3
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)
    assert any(x['id'] == IDENTITY_ID for x in resp)


def test_related_to_by_source(rel_fs_store):
    resp = rel_fs_store.related_to(MALWARE_ID, source_only=True)

    assert len(resp) == 1
    assert any(x['id'] == IDENTITY_ID for x in resp)


def test_related_to_by_target(rel_fs_store):
    resp = rel_fs_store.related_to(MALWARE_ID, target_only=True)

    assert len(resp) == 2
    assert any(x['id'] == CAMPAIGN_ID for x in resp)
    assert any(x['id'] == INDICATOR_ID for x in resp)


def test_auth_set_white1():
    auth_set = AuthSet({"A"}, set())

    assert auth_set.auth_type == AuthSet.WHITE
    assert auth_set.values == {"A"}


def test_auth_set_white2():
    auth_set = AuthSet(set(), set())

    assert auth_set.auth_type == AuthSet.WHITE
    assert len(auth_set.values) == 0


def test_auth_set_white3():
    auth_set = AuthSet({"A", "B"}, {"B", "C"})

    assert auth_set.auth_type == AuthSet.WHITE
    assert auth_set.values == {"A"}


def test_auth_set_black1():
    auth_set = AuthSet(None, {"B", "C"})

    assert auth_set.auth_type == AuthSet.BLACK
    assert auth_set.values == {"B", "C"}


def test_optimize_types1():
    filters = [
        stix2.Filter("type", "=", "foo"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"foo"}
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types2():
    filters = [
        stix2.Filter("type", "=", "foo"),
        stix2.Filter("type", "=", "bar"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert len(auth_types.values) == 0
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types3():
    filters = [
        stix2.Filter("type", "in", ["A", "B", "C"]),
        stix2.Filter("type", "in", ["B", "C", "D"]),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"B", "C"}
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types4():
    filters = [
        stix2.Filter("type", "in", ["A", "B", "C"]),
        stix2.Filter("type", "in", ["D", "E", "F"]),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert len(auth_types.values) == 0
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types5():
    filters = [
        stix2.Filter("type", "in", ["foo", "bar"]),
        stix2.Filter("type", "!=", "bar"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"foo"}
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types6():
    filters = [
        stix2.Filter("type", "!=", "foo"),
        stix2.Filter("type", "!=", "bar"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.BLACK
    assert auth_types.values == {"foo", "bar"}
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types7():
    filters = [
        stix2.Filter("type", "=", "foo"),
        stix2.Filter("type", "!=", "foo"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert len(auth_types.values) == 0
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types8():
    filters = []

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.BLACK
    assert len(auth_types.values) == 0
    assert auth_ids.auth_type == AuthSet.BLACK
    assert len(auth_ids.values) == 0


def test_optimize_types_ids1():
    filters = [
        stix2.Filter("type", "in", ["foo", "bar"]),
        stix2.Filter("id", "=", "foo--00000000-0000-0000-0000-000000000000"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"foo"}
    assert auth_ids.auth_type == AuthSet.WHITE
    assert auth_ids.values == {"foo--00000000-0000-0000-0000-000000000000"}


def test_optimize_types_ids2():
    filters = [
        stix2.Filter("type", "=", "foo"),
        stix2.Filter("id", "=", "bar--00000000-0000-0000-0000-000000000000"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert len(auth_types.values) == 0
    assert auth_ids.auth_type == AuthSet.WHITE
    assert len(auth_ids.values) == 0


def test_optimize_types_ids3():
    filters = [
        stix2.Filter("type", "in", ["foo", "bar"]),
        stix2.Filter("id", "!=", "bar--00000000-0000-0000-0000-000000000000"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"foo", "bar"}
    assert auth_ids.auth_type == AuthSet.BLACK
    assert auth_ids.values == {"bar--00000000-0000-0000-0000-000000000000"}


def test_optimize_types_ids4():
    filters = [
        stix2.Filter("type", "in", ["A", "B", "C"]),
        stix2.Filter(
            "id", "in", [
                "B--00000000-0000-0000-0000-000000000000",
                "C--00000000-0000-0000-0000-000000000000",
                "D--00000000-0000-0000-0000-000000000000",
            ],
        ),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"B", "C"}
    assert auth_ids.auth_type == AuthSet.WHITE
    assert auth_ids.values == {
        "B--00000000-0000-0000-0000-000000000000",
        "C--00000000-0000-0000-0000-000000000000",
    }


def test_optimize_types_ids5():
    filters = [
        stix2.Filter("type", "in", ["A", "B", "C"]),
        stix2.Filter("type", "!=", "C"),
        stix2.Filter(
            "id", "in", [
                "B--00000000-0000-0000-0000-000000000000",
                "C--00000000-0000-0000-0000-000000000000",
                "D--00000000-0000-0000-0000-000000000000",
            ],
        ),
        stix2.Filter("id", "!=", "D--00000000-0000-0000-0000-000000000000"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"B"}
    assert auth_ids.auth_type == AuthSet.WHITE
    assert auth_ids.values == {"B--00000000-0000-0000-0000-000000000000"}


def test_optimize_types_ids6():
    filters = [
        stix2.Filter("id", "=", "A--00000000-0000-0000-0000-000000000000"),
    ]

    auth_types, auth_ids = _find_search_optimizations(filters)

    assert auth_types.auth_type == AuthSet.WHITE
    assert auth_types.values == {"A"}
    assert auth_ids.auth_type == AuthSet.WHITE
    assert auth_ids.values == {"A--00000000-0000-0000-0000-000000000000"}


def test_search_auth_set_white1():
    auth_set = AuthSet(
        {"attack-pattern", "doesntexist"},
        set(),
    )

    results = _get_matching_dir_entries(FS_PATH, auth_set, stat.S_ISDIR)
    assert results == ["attack-pattern"]

    results = _get_matching_dir_entries(FS_PATH, auth_set, stat.S_ISREG)
    assert len(results) == 0


def test_search_auth_set_white2():
    auth_set = AuthSet(
        {
            "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38",
            "malware--92ec0cbd-2c30-44a2-b270-73f4ec949841",

        },
        {
            "malware--92ec0cbd-2c30-44a2-b270-73f4ec949841",
            "malware--96b08451-b27a-4ff6-893f-790e26393a8e",
            "doesntexist",
        },
    )

    results = _get_matching_dir_entries(
        os.path.join(FS_PATH, "malware"),
        auth_set, stat.S_ISDIR,
    )

    assert results == ["malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"]


def test_search_auth_set_white3():
    auth_set = AuthSet({"20170531213258226477", "doesntexist"}, set())

    results = _get_matching_dir_entries(
        os.path.join(
            FS_PATH, "malware",
            "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38",
        ),
        auth_set, stat.S_ISREG, ".json",
    )

    assert results == ["20170531213258226477.json"]


def test_search_auth_set_black1():
    auth_set = AuthSet(
        None,
        {"tool--242f3da3-4425-4d11-8f5c-b842886da966", "doesntexist"},
    )

    results = _get_matching_dir_entries(
        os.path.join(FS_PATH, "tool"),
        auth_set, stat.S_ISDIR,
    )

    assert set(results) == {
        "tool--03342581-f790-4f03-ba41-e82e67392e23",
    }


def test_search_auth_set_white_empty():
    auth_set = AuthSet(
        set(),
        set(),
    )

    results = _get_matching_dir_entries(FS_PATH, auth_set, stat.S_ISDIR)

    assert len(results) == 0


def test_search_auth_set_black_empty(rel_fs_store):
    # Ensure rel_fs_store fixture has run so that the type directories are
    # predictable (it adds "campaign").
    auth_set = AuthSet(
        None,
        set(),
    )

    results = _get_matching_dir_entries(FS_PATH, auth_set, stat.S_ISDIR)

    # Should get all dirs
    assert set(results) == {
        "attack-pattern",
        "campaign",
        "course-of-action",
        "identity",
        "indicator",
        "intrusion-set",
        "malware",
        "marking-definition",
        "relationship",
        "tool",
    }


def test_timestamp2filename_naive():
    dt = datetime.datetime(
        2010, 6, 15,
        8, 30, 10, 1234,
    )

    filename = _timestamp2filename(dt)
    assert filename == "20100615083010001234"


def test_timestamp2filename_tz():
    # one hour west of UTC (i.e. an hour earlier)
    tz = pytz.FixedOffset(-60)
    dt = datetime.datetime(
        2010, 6, 15,
        7, 30, 10, 1234,
        tz,
    )

    filename = _timestamp2filename(dt)
    assert filename == "20100615083010001234"
