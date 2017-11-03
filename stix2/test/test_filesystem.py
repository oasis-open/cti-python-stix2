import os
import shutil

import pytest

from stix2 import (Bundle, Campaign, CustomObject, FileSystemSink,
                   FileSystemSource, FileSystemStore, Filter, properties)

FS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "stix2_data")


@pytest.fixture
def fs_store():
    # create
    yield FileSystemStore(FS_PATH)

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


@pytest.fixture
def fs_source():
    # create
    fs = FileSystemSource(FS_PATH)
    assert fs.stix_dir == FS_PATH
    yield fs

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


@pytest.fixture
def fs_sink():
    # create
    fs = FileSystemSink(FS_PATH)
    assert fs.stix_dir == FS_PATH
    yield fs

    # remove campaign dir
    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


def test_filesystem_source_nonexistent_folder():
    with pytest.raises(ValueError) as excinfo:
        FileSystemSource('nonexistent-folder')
    assert "for STIX data does not exist" in str(excinfo)


def test_filesystem_sink_nonexistent_folder():
    with pytest.raises(ValueError) as excinfo:
        FileSystemSink('nonexistent-folder')
    assert "for STIX data does not exist" in str(excinfo)


def test_filesytem_source_get_object(fs_source):
    # get object
    mal = fs_source.get("malware--6b616fc1-1505-48e3-8b2c-0d19337bff38")
    assert mal.id == "malware--6b616fc1-1505-48e3-8b2c-0d19337bff38"
    assert mal.name == "Rover"


def test_filesytem_source_get_nonexistent_object(fs_source):
    ind = fs_source.get("indicator--6b616fc1-1505-48e3-8b2c-0d19337bff38")
    assert ind is None


def test_filesytem_source_all_versions(fs_source):
    # all versions - (currently not a true all versions call as FileSystem cant have multiple versions)
    id_ = fs_source.get("identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5")
    assert id_.id == "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
    assert id_.name == "The MITRE Corporation"
    assert id_.type == "identity"


def test_filesytem_source_query_single(fs_source):
    # query2
    is_2 = fs_source.query([Filter("external_references.external_id", '=', "T1027")])
    assert len(is_2) == 1

    is_2 = is_2[0]
    assert is_2.id == "attack-pattern--b3d682b6-98f2-4fb0-aa3b-b4df007ca70a"
    assert is_2.type == "attack-pattern"


def test_filesytem_source_query_multiple(fs_source):
    # query
    intrusion_sets = fs_source.query([Filter("type", '=', "intrusion-set")])
    assert len(intrusion_sets) == 2
    assert "intrusion-set--a653431d-6a5e-4600-8ad3-609b5af57064" in [is_.id for is_ in intrusion_sets]
    assert "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a" in [is_.id for is_ in intrusion_sets]

    is_1 = [is_ for is_ in intrusion_sets if is_.id == "intrusion-set--f3bdec95-3d62-42d9-a840-29630f6cdc1a"][0]
    assert "DragonOK" in is_1.aliases
    assert len(is_1.external_references) == 4


def test_filesystem_sink_add_python_stix_object(fs_sink, fs_source):
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

    os.remove(os.path.join(FS_PATH, "campaign", camp1_r.id + ".json"))


def test_filesystem_sink_add_stix_object_dict(fs_sink, fs_source):
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

    os.remove(os.path.join(FS_PATH, "campaign", camp2_r.id + ".json"))


def test_filesystem_sink_add_stix_bundle_dict(fs_sink, fs_source):
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

    os.remove(os.path.join(FS_PATH, "campaign", camp3_r.id + ".json"))


def test_filesystem_sink_add_json_stix_object(fs_sink, fs_source):
    # add json-encoded stix obj
    camp4 = '{"type": "campaign", "id":"campaign--144111b6-1112-4fb0-111b-b111107ca70a",'\
            ' "created":"2017-05-31T21:31:53.197755Z", "name": "Ghengis Khan", "objective": "China and Russian infrastructure"}'

    fs_sink.add(camp4)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", "campaign--144111b6-1112-4fb0-111b-b111107ca70a" + ".json"))

    camp4_r = fs_source.get("campaign--144111b6-1112-4fb0-111b-b111107ca70a")
    assert camp4_r.id == "campaign--144111b6-1112-4fb0-111b-b111107ca70a"
    assert camp4_r.name == "Ghengis Khan"

    os.remove(os.path.join(FS_PATH, "campaign", camp4_r.id + ".json"))


def test_filesystem_sink_json_stix_bundle(fs_sink, fs_source):
    # add json-encoded stix bundle
    bund2 = '{"type": "bundle", "id": "bundle--332211b6-1132-4fb0-111b-b111107ca70a",' \
            ' "spec_version": "2.0", "objects": [{"type": "campaign", "id": "campaign--155155b6-1112-4fb0-111b-b111107ca70a",' \
            ' "created":"2017-05-31T21:31:53.197755Z", "name": "Spartacus", "objective": "Oppressive regimes of Africa and Middle East"}]}'
    fs_sink.add(bund2)

    assert os.path.exists(os.path.join(FS_PATH, "campaign", "campaign--155155b6-1112-4fb0-111b-b111107ca70a" + ".json"))

    camp5_r = fs_source.get("campaign--155155b6-1112-4fb0-111b-b111107ca70a")
    assert camp5_r.id == "campaign--155155b6-1112-4fb0-111b-b111107ca70a"
    assert camp5_r.name == "Spartacus"

    os.remove(os.path.join(FS_PATH, "campaign", camp5_r.id + ".json"))


def test_filesystem_sink_add_objects_list(fs_sink, fs_source):
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
    os.remove(os.path.join(FS_PATH, "campaign", camp6_r.id + ".json"))
    os.remove(os.path.join(FS_PATH, "campaign", camp7_r.id + ".json"))


def test_filesystem_store_get_stored_as_bundle(fs_store):
    coa = fs_store.get("course-of-action--95ddb356-7ba0-4bd9-a889-247262b8946f")
    assert coa.id == "course-of-action--95ddb356-7ba0-4bd9-a889-247262b8946f"
    assert coa.type == "course-of-action"


def test_filesystem_store_get_stored_as_object(fs_store):
    coa = fs_store.get("course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd")
    assert coa.id == "course-of-action--d9727aee-48b8-4fdb-89e2-4c49746ba4dd"
    assert coa.type == "course-of-action"


def test_filesystem_store_all_versions(fs_store):
    # all versions() - (note at this time, all_versions() is still not applicable to FileSystem, as only one version is ever stored)
    rel = fs_store.all_versions("relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1")[0]
    assert rel.id == "relationship--70dc6b5c-c524-429e-a6ab-0dd40f0482c1"
    assert rel.type == "relationship"


def test_filesystem_store_query(fs_store):
    # query()
    tools = fs_store.query([Filter("labels", "in", "tool")])
    assert len(tools) == 2
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [tool.id for tool in tools]
    assert "tool--03342581-f790-4f03-ba41-e82e67392e23" in [tool.id for tool in tools]


def test_filesystem_store_query_single_filter(fs_store):
    query = Filter("labels", "in", "tool")
    tools = fs_store.query(query)
    assert len(tools) == 2
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [tool.id for tool in tools]
    assert "tool--03342581-f790-4f03-ba41-e82e67392e23" in [tool.id for tool in tools]


def test_filesystem_store_empty_query(fs_store):
    results = fs_store.query()  # returns all
    assert len(results) == 26
    assert "tool--242f3da3-4425-4d11-8f5c-b842886da966" in [obj.id for obj in results]
    assert "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168" in [obj.id for obj in results]


def test_filesystem_store_query_multiple_filters(fs_store):
    fs_store.source.filters.add(Filter("labels", "in", "tool"))
    tools = fs_store.query(Filter("id", "=", "tool--242f3da3-4425-4d11-8f5c-b842886da966"))
    assert len(tools) == 1
    assert tools[0].id == "tool--242f3da3-4425-4d11-8f5c-b842886da966"


def test_filesystem_store_query_dont_include_type_folder(fs_store):
    results = fs_store.query(Filter("type", "!=", "tool"))
    assert len(results) == 24


def test_filesystem_store_add(fs_store):
    # add()
    camp1 = Campaign(name="Great Heathen Army",
                     objective="Targeting the government of United Kingdom and insitutions affiliated with the Church Of England",
                     aliases=["Ragnar"])
    fs_store.add(camp1)

    camp1_r = fs_store.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == camp1.name

    # remove
    os.remove(os.path.join(FS_PATH, "campaign", camp1_r.id + ".json"))


def test_filesystem_store_add_as_bundle():
    fs_store = FileSystemStore(FS_PATH, bundlify=True)

    camp1 = Campaign(name="Great Heathen Army",
                     objective="Targeting the government of United Kingdom and insitutions affiliated with the Church Of England",
                     aliases=["Ragnar"])
    fs_store.add(camp1)

    with open(os.path.join(FS_PATH, "campaign", camp1.id + ".json")) as bundle_file:
        assert '"type": "bundle"' in bundle_file.read()

    camp1_r = fs_store.get(camp1.id)
    assert camp1_r.id == camp1.id
    assert camp1_r.name == camp1.name

    shutil.rmtree(os.path.join(FS_PATH, "campaign"), True)


def test_filesystem_add_bundle_object(fs_store):
    bundle = Bundle()
    fs_store.add(bundle)


def test_filesystem_store_add_invalid_object(fs_store):
    ind = ('campaign', 'campaign--111111b6-1112-4fb0-111b-b111107ca70a')  # tuple isn't valid
    with pytest.raises(TypeError) as excinfo:
        fs_store.add(ind)
    assert 'stix_data must be' in str(excinfo.value)
    assert 'a STIX object' in str(excinfo.value)
    assert 'JSON formatted STIX' in str(excinfo.value)
    assert 'JSON formatted STIX bundle' in str(excinfo.value)


def test_filesystem_object_with_custom_property(fs_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    fs_store.add(camp, True)

    camp_r = fs_store.get(camp.id, allow_custom=True)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_filesystem_object_with_custom_property_in_bundle(fs_store):
    camp = Campaign(name="Scipio Africanus",
                    objective="Defeat the Carthaginians",
                    x_empire="Roman",
                    allow_custom=True)

    bundle = Bundle(camp, allow_custom=True)
    fs_store.add(bundle, allow_custom=True)

    camp_r = fs_store.get(camp.id, allow_custom=True)
    assert camp_r.id == camp.id
    assert camp_r.x_empire == camp.x_empire


def test_filesystem_custom_object(fs_store):
    @CustomObject('x-new-obj', [
        ('property1', properties.StringProperty(required=True)),
    ])
    class NewObj():
        pass

    newobj = NewObj(property1='something')
    fs_store.add(newobj, allow_custom=True)

    newobj_r = fs_store.get(newobj.id, allow_custom=True)
    assert newobj_r.id == newobj.id
    assert newobj_r.property1 == 'something'

    # remove dir
    shutil.rmtree(os.path.join(FS_PATH, "x-new-obj"), True)
