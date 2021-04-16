import importlib
import os

import stix2
from stix2.workbench import (
    _STIX_VID, AttackPattern, Bundle, Campaign, CourseOfAction,
    ExternalReference, File, FileSystemSource, Filter, Grouping, Identity,
    Indicator, Infrastructure, IntrusionSet, Location, Malware,
    MalwareAnalysis, MarkingDefinition, Note, NTFSExt, ObservedData, Opinion,
    Relationship, Report, StatementMarking, ThreatActor, Tool, Vulnerability,
    add_data_source, all_versions, attack_patterns, campaigns,
    courses_of_action, create, get, groupings, identities, indicators,
    infrastructures, intrusion_sets, locations, malware, malware_analyses,
    notes, observed_data, opinions, query, reports, save, set_default_created,
    set_default_creator, set_default_external_refs,
    set_default_object_marking_refs, threat_actors, tools, vulnerabilities,
)

# Auto-detect some settings based on the current default STIX version
_STIX_DATA_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    _STIX_VID,
    "stix2_data",
)
_STIX_CONSTANTS_MODULE = "stix2.test." + _STIX_VID + ".constants"


constants = importlib.import_module(_STIX_CONSTANTS_MODULE)


def test_workbench_environment():

    # Create a STIX object
    ind = create(
        Indicator, id=constants.INDICATOR_ID, **constants.INDICATOR_KWARGS
    )
    save(ind)

    resp = get(constants.INDICATOR_ID)
    assert resp['indicator_types'][0] == 'malicious-activity'

    resp = all_versions(constants.INDICATOR_ID)
    assert len(resp) == 1

    # Search on something other than id
    q = [Filter('type', '=', 'vulnerability')]
    resp = query(q)
    assert len(resp) == 0


def test_workbench_get_all_attack_patterns():
    mal = AttackPattern(
        id=constants.ATTACK_PATTERN_ID, **constants.ATTACK_PATTERN_KWARGS
    )
    save(mal)

    resp = attack_patterns()
    assert len(resp) == 1
    assert resp[0].id == constants.ATTACK_PATTERN_ID


def test_workbench_get_all_campaigns():
    cam = Campaign(id=constants.CAMPAIGN_ID, **constants.CAMPAIGN_KWARGS)
    save(cam)

    resp = campaigns()
    assert len(resp) == 1
    assert resp[0].id == constants.CAMPAIGN_ID


def test_workbench_get_all_courses_of_action():
    coa = CourseOfAction(
        id=constants.COURSE_OF_ACTION_ID, **constants.COURSE_OF_ACTION_KWARGS
    )
    save(coa)

    resp = courses_of_action()
    assert len(resp) == 1
    assert resp[0].id == constants.COURSE_OF_ACTION_ID


def test_workbench_get_all_groupings():
    grup = Grouping(id=constants.GROUPING_ID, **constants.GROUPING_KWARGS)
    save(grup)

    resp = groupings()
    assert len(resp) == 1
    assert resp[0].id == constants.GROUPING_ID


def test_workbench_get_all_identities():
    idty = Identity(id=constants.IDENTITY_ID, **constants.IDENTITY_KWARGS)
    save(idty)

    resp = identities()
    assert len(resp) == 1
    assert resp[0].id == constants.IDENTITY_ID


def test_workbench_get_all_indicators():
    resp = indicators()
    assert len(resp) == 1
    assert resp[0].id == constants.INDICATOR_ID


def test_workbench_get_all_infrastructures():
    inf = Infrastructure(id=constants.INFRASTRUCTURE_ID, **constants.INFRASTRUCTURE_KWARGS)
    save(inf)

    resp = infrastructures()
    assert len(resp) == 1
    assert resp[0].id == constants.INFRASTRUCTURE_ID


def test_workbench_get_all_intrusion_sets():
    ins = IntrusionSet(
        id=constants.INTRUSION_SET_ID, **constants.INTRUSION_SET_KWARGS
    )
    save(ins)

    resp = intrusion_sets()
    assert len(resp) == 1
    assert resp[0].id == constants.INTRUSION_SET_ID


def test_workbench_get_all_locations():
    loc = Location(id=constants.LOCATION_ID, **constants.LOCATION_KWARGS)
    save(loc)

    resp = locations()
    assert len(resp) == 1
    assert resp[0].id == constants.LOCATION_ID


def test_workbench_get_all_malware():
    mal = Malware(id=constants.MALWARE_ID, **constants.MALWARE_KWARGS)
    save(mal)

    resp = malware()
    assert len(resp) == 1
    assert resp[0].id == constants.MALWARE_ID


def test_workbench_get_all_malware_analyses():
    mal = MalwareAnalysis(id=constants.MALWARE_ANALYSIS_ID, **constants.MALWARE_ANALYSIS_KWARGS)
    save(mal)

    resp = malware_analyses()
    assert len(resp) == 1
    assert resp[0].id == constants.MALWARE_ANALYSIS_ID


def test_workbench_get_all_notes():
    note = Note(id=constants.NOTE_ID, **constants.NOTE_KWARGS)
    save(note)

    resp = notes()
    assert len(resp) == 1
    assert resp[0].id == constants.NOTE_ID


def test_workbench_get_all_observed_data():
    od = ObservedData(
        id=constants.OBSERVED_DATA_ID, **constants.OBSERVED_DATA_KWARGS
    )
    save(od)

    resp = observed_data()
    assert len(resp) == 1
    assert resp[0].id == constants.OBSERVED_DATA_ID


def test_workbench_get_all_opinions():
    op = Opinion(id=constants.OPINION_ID, **constants.OPINION_KWARGS)
    save(op)

    resp = opinions()
    assert len(resp) == 1
    assert resp[0].id == constants.OPINION_ID


def test_workbench_get_all_reports():
    rep = Report(id=constants.REPORT_ID, **constants.REPORT_KWARGS)
    save(rep)

    resp = reports()
    assert len(resp) == 1
    assert resp[0].id == constants.REPORT_ID


def test_workbench_get_all_threat_actors():
    thr = ThreatActor(
        id=constants.THREAT_ACTOR_ID, **constants.THREAT_ACTOR_KWARGS
    )
    save(thr)

    resp = threat_actors()
    assert len(resp) == 1
    assert resp[0].id == constants.THREAT_ACTOR_ID


def test_workbench_get_all_tools():
    tool = Tool(id=constants.TOOL_ID, **constants.TOOL_KWARGS)
    save(tool)

    resp = tools()
    assert len(resp) == 1
    assert resp[0].id == constants.TOOL_ID


def test_workbench_get_all_vulnerabilities():
    vuln = Vulnerability(
        id=constants.VULNERABILITY_ID, **constants.VULNERABILITY_KWARGS
    )
    save(vuln)

    resp = vulnerabilities()
    assert len(resp) == 1
    assert resp[0].id == constants.VULNERABILITY_ID


def test_workbench_add_to_bundle():
    vuln = Vulnerability(**constants.VULNERABILITY_KWARGS)
    bundle = Bundle(vuln)
    assert bundle.objects[0].name == 'Heartbleed'


def test_workbench_relationships():
    rel = Relationship(
        constants.INDICATOR_ID, 'indicates', constants.MALWARE_ID,
    )
    save(rel)

    ind = get(constants.INDICATOR_ID)
    resp = ind.relationships()
    assert len(resp) == 1
    assert resp[0].relationship_type == 'indicates'
    assert resp[0].source_ref == constants.INDICATOR_ID
    assert resp[0].target_ref == constants.MALWARE_ID


def test_workbench_created_by():
    intset = IntrusionSet(
        name="Breach 123", created_by_ref=constants.IDENTITY_ID,
    )
    save(intset)
    creator = intset.created_by()
    assert creator.id == constants.IDENTITY_ID


def test_workbench_related():
    rel1 = Relationship(constants.MALWARE_ID, 'targets', constants.IDENTITY_ID)
    rel2 = Relationship(constants.CAMPAIGN_ID, 'uses', constants.MALWARE_ID)
    save([rel1, rel2])

    resp = get(constants.MALWARE_ID).related()
    assert len(resp) == 3
    assert any(x['id'] == constants.CAMPAIGN_ID for x in resp)
    assert any(x['id'] == constants.INDICATOR_ID for x in resp)
    assert any(x['id'] == constants.IDENTITY_ID for x in resp)

    resp = get(constants.MALWARE_ID).related(relationship_type='indicates')
    assert len(resp) == 1


def test_workbench_related_with_filters():
    malware = Malware(
        labels=["ransomware"], name="CryptorBit", created_by_ref=constants.IDENTITY_ID,
        is_family=False,
    )
    rel = Relationship(malware.id, 'variant-of', constants.MALWARE_ID)
    save([malware, rel])

    filters = [Filter('created_by_ref', '=', constants.IDENTITY_ID)]
    resp = get(constants.MALWARE_ID).related(filters=filters)

    assert len(resp) == 1
    assert resp[0].name == malware.name
    assert resp[0].created_by_ref == constants.IDENTITY_ID

    # filters arg can also be single filter
    resp = get(constants.MALWARE_ID).related(filters=filters[0])
    assert len(resp) == 1


def test_add_data_source():
    fs = FileSystemSource(_STIX_DATA_PATH)
    add_data_source(fs)

    resp = tools()
    assert len(resp) == 3
    resp_ids = [tool.id for tool in resp]
    assert constants.TOOL_ID in resp_ids
    assert 'tool--03342581-f790-4f03-ba41-e82e67392e23' in resp_ids
    assert 'tool--242f3da3-4425-4d11-8f5c-b842886da966' in resp_ids


def test_additional_filter():
    resp = tools(Filter('created_by_ref', '=', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'))
    assert len(resp) == 2


def test_additional_filters_list():
    resp = tools([
        Filter('created_by_ref', '=', 'identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5'),
        Filter('name', '=', 'Windows Credential Editor'),
    ])
    assert len(resp) == 1


def test_default_creator():
    set_default_creator(constants.IDENTITY_ID)
    campaign = Campaign(**constants.CAMPAIGN_KWARGS)

    assert 'created_by_ref' not in constants.CAMPAIGN_KWARGS
    assert campaign.created_by_ref == constants.IDENTITY_ID

    # turn off side-effects to avoid affecting future tests
    set_default_creator(None)


def test_default_created_timestamp():
    timestamp = "2018-03-19T01:02:03.000Z"
    set_default_created(timestamp)
    campaign = Campaign(**constants.CAMPAIGN_KWARGS)

    assert 'created' not in constants.CAMPAIGN_KWARGS
    assert stix2.utils.format_datetime(campaign.created) == timestamp
    assert stix2.utils.format_datetime(campaign.modified) == timestamp

    # turn off side-effects to avoid affecting future tests
    set_default_created(None)


def test_default_external_refs():
    ext_ref = ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
    )
    set_default_external_refs(ext_ref)
    campaign = Campaign(**constants.CAMPAIGN_KWARGS)

    assert campaign.external_references[0].source_name == "ACME Threat Intel"
    assert campaign.external_references[0].description == "Threat report"

    # turn off side-effects to avoid affecting future tests
    set_default_external_refs([])


def test_default_object_marking_refs():
    stmt_marking = StatementMarking("Copyright 2016, Example Corp")
    mark_def = MarkingDefinition(
        definition_type="statement",
        definition=stmt_marking,
    )
    set_default_object_marking_refs(mark_def)
    campaign = Campaign(**constants.CAMPAIGN_KWARGS)

    assert campaign.object_marking_refs[0] == mark_def.id

    # turn off side-effects to avoid affecting future tests
    set_default_object_marking_refs([])


def test_workbench_custom_property_object_in_observable_extension():
    ntfs = NTFSExt(
        allow_custom=True,
        sid=1,
        x_foo='bar',
    )
    artifact = File(
        allow_custom=True,
        name='test',
        extensions={'ntfs-ext': ntfs},
    )
    observed_data = ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_workbench_custom_property_dict_in_observable_extension():
    artifact = File(
        allow_custom=True,
        name='test',
        extensions={
            'ntfs-ext': {
                'sid': 1,
                'x_foo': 'bar',
            },
        },
    )
    observed_data = ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)
