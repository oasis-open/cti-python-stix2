import pytest

from stix2 import parse
from stix2.datastore.filters import Filter, apply_common_filters
from stix2.utils import STIXdatetime, parse_into_datetime

stix_objs = [
    {
        "created": "2017-01-27T13:49:53.997Z",
        "description": "\n\nTITLE:\n\tPoison Ivy",
        "id": "malware--fdd60b30-b67c-41e3-b0b9-f01faf20d111",
        "labels": [
            "remote-access-trojan",
        ],
        "modified": "2017-01-27T13:49:53.997Z",
        "name": "Poison Ivy",
        "type": "malware",
    },
    {
        "created": "2014-05-08T09:00:00.000Z",
        "id": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
        "labels": [
            "file-hash-watchlist",
        ],
        "modified": "2014-05-08T09:00:00.000Z",
        "name": "File hash for Poison Ivy variant",
        "pattern": "[file:hashes.'SHA-256' = 'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c']",
        "type": "indicator",
        "valid_from": "2014-05-08T09:00:00.000000Z",
    },
    {
        "created": "2014-05-08T09:00:00.000Z",
        "granular_markings": [
            {
                "marking_ref": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                "selectors": [
                    "relationship_type",
                ],
            },
        ],
        "id": "relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463",
        "modified": "2014-05-08T09:00:00.000Z",
        "object_marking_refs": [
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        ],
        "relationship_type": "indicates",
        "revoked": True,
        "source_ref": "indicator--a932fcc6-e032-476c-826f-cb970a5a1ade",
        "target_ref": "malware--fdd60b30-b67c-41e3-b0b9-f01faf20d111",
        "type": "relationship",
    },
    {
        "id": "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef",
        "created": "2016-02-14T00:00:00.000Z",
        "created_by_ref": "identity--f1350682-3290-4e0d-be58-69e290537647",
        "modified": "2016-02-14T00:00:00.000Z",
        "type": "vulnerability",
        "name": "CVE-2014-0160",
        "description": "The (1) TLS...",
        "external_references": [
            {
                "source_name": "cve",
                "external_id": "CVE-2014-0160",
            },
        ],
        "labels": ["heartbleed", "has-logo"],
    },
    {
        "type": "observed-data",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "file",
                "name": "HAL 9000.exe",
            },
        },

    },
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
    Filter("created_by_ref", "=", "identity--f1350682-3290-4e0d-be58-69e290537647"),
    Filter("object_marking_refs", "=", "marking-definition--613f2e26-0000-4000-8000-b8e91df99dc9"),
    Filter("granular_markings.selectors", "in", "description"),
    Filter("external_references.source_name", "=", "CVE"),
    Filter("objects", "=", {"0": {"type": "file", "name": "HAL 9000.exe"}}),
    Filter("objects", "contains", {"type": "file", "name": "HAL 9000.exe"}),
    Filter("labels", "contains", "heartbleed"),
]

# same as above objects but converted to real Python STIX2 objects
# to test filters against true Python STIX2 objects
real_stix_objs = [parse(stix_obj) for stix_obj in stix_objs]


def test_filter_ops_check():
    # invalid filters - non supported operators

    with pytest.raises(ValueError) as excinfo:
        # create Filter that has an operator that is not allowed
        Filter('modified', '*', 'not supported operator')
    assert str(excinfo.value) == "Filter operator '*' not supported for specified property: 'modified'"

    with pytest.raises(ValueError) as excinfo:
        Filter("type", "%", "4")
    assert "Filter operator '%' not supported for specified property" in str(excinfo.value)


def test_filter_value_type_check():
    # invalid filters - non supported value types

    with pytest.raises(TypeError) as excinfo:
        Filter('created', '=', object())
    # On Python 2, the type of object() is `<type 'object'>` On Python 3, it's `<class 'object'>`.
    assert any([s in str(excinfo.value) for s in ["<type 'object'>", "'<class 'object'>'"]])
    assert "is not supported. The type must be a Python immutable type or dictionary" in str(excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        Filter("type", "=", complex(2, -1))
    assert any([s in str(excinfo.value) for s in ["<type 'complex'>", "'<class 'complex'>'"]])
    assert "is not supported. The type must be a Python immutable type or dictionary" in str(excinfo.value)

    with pytest.raises(TypeError) as excinfo:
        Filter("type", "=", set([16, 23]))
    assert any([s in str(excinfo.value) for s in ["<type 'set'>", "'<class 'set'>'"]])
    assert "is not supported. The type must be a Python immutable type or dictionary" in str(excinfo.value)


def test_filter_type_underscore_check():
    # check that Filters where property="type", value (name) doesnt have underscores
    with pytest.raises(ValueError) as excinfo:
        Filter("type", "=", "oh_underscore")
    assert "Filter for property 'type' cannot have its value 'oh_underscore'" in str(excinfo.value)


def test_apply_common_filters0():
    # "Return any object whose type is not relationship"
    resp = list(apply_common_filters(stix_objs, [filters[0]]))
    ids = [r['id'] for r in resp]
    assert stix_objs[0]['id'] in ids
    assert stix_objs[1]['id'] in ids
    assert stix_objs[3]['id'] in ids
    assert len(ids) == 4

    resp = list(apply_common_filters(real_stix_objs, [filters[0]]))
    ids = [r.id for r in resp]
    assert real_stix_objs[0].id in ids
    assert real_stix_objs[1].id in ids
    assert real_stix_objs[3].id in ids
    assert len(ids) == 4


def test_apply_common_filters1():
    # "Return any object that matched id relationship--2f9a9aa9-108a-4333-83e2-4fb25add0463"
    resp = list(apply_common_filters(stix_objs, [filters[1]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[1]]))
    assert resp[0].id == real_stix_objs[2].id
    assert len(resp) == 1


def test_apply_common_filters2():
    # "Return any object that contains remote-access-trojan in labels"
    resp = list(apply_common_filters(stix_objs, [filters[2]]))
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[2]]))
    assert resp[0].id == real_stix_objs[0].id
    assert len(resp) == 1


def test_apply_common_filters3():
    # "Return any object created after 2015-01-01T01:00:00.000Z"
    resp = list(apply_common_filters(stix_objs, [filters[3]]))
    assert resp[0]['id'] == stix_objs[0]['id']
    assert len(resp) == 3

    resp = list(apply_common_filters(real_stix_objs, [filters[3]]))
    assert len(resp) == 3
    assert resp[0].id == real_stix_objs[0].id


def test_apply_common_filters4():
    # "Return any revoked object"
    resp = list(apply_common_filters(stix_objs, [filters[4]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[4]]))
    assert resp[0].id == real_stix_objs[2].id
    assert len(resp) == 1


def test_apply_common_filters5():
    # "Return any object whose not revoked"
    resp = list(apply_common_filters(stix_objs, [filters[5]]))
    assert len(resp) == 0

    resp = list(apply_common_filters(real_stix_objs, [filters[5]]))
    assert len(resp) == 4


def test_apply_common_filters6():
    # "Return any object that matches marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9 in object_marking_refs"
    resp = list(apply_common_filters(stix_objs, [filters[6]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[6]]))
    assert resp[0].id == real_stix_objs[2].id
    assert len(resp) == 1


def test_apply_common_filters7():
    # "Return any object that contains relationship_type in their selectors AND
    # also has marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed in marking_ref"
    resp = list(apply_common_filters(stix_objs, [filters[7], filters[8]]))
    assert resp[0]['id'] == stix_objs[2]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[7], filters[8]]))
    assert resp[0].id == real_stix_objs[2].id
    assert len(resp) == 1


def test_apply_common_filters8():
    # "Return any object that contains CVE-2014-0160,CVE-2017-6608 in their external_id"
    resp = list(apply_common_filters(stix_objs, [filters[9]]))
    assert resp[0]['id'] == stix_objs[3]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[9]]))
    assert resp[0].id == real_stix_objs[3].id
    assert len(resp) == 1


def test_apply_common_filters9():
    # "Return any object that matches created_by_ref identity--f1350682-3290-4e0d-be58-69e290537647"
    resp = list(apply_common_filters(stix_objs, [filters[10]]))
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[10]]))
    assert len(resp) == 1


def test_apply_common_filters10():
    # "Return any object that matches marking-definition--613f2e26-0000-4000-8000-b8e91df99dc9 in object_marking_refs" (None)
    resp = list(apply_common_filters(stix_objs, [filters[11]]))
    assert len(resp) == 0

    resp = list(apply_common_filters(real_stix_objs, [filters[11]]))
    assert len(resp) == 0


def test_apply_common_filters11():
    # "Return any object that contains description in its selectors" (None)
    resp = list(apply_common_filters(stix_objs, [filters[12]]))
    assert len(resp) == 0

    resp = list(apply_common_filters(real_stix_objs, [filters[12]]))
    assert len(resp) == 0


def test_apply_common_filters12():
    # "Return any object that matches CVE in source_name" (None, case sensitive)
    resp = list(apply_common_filters(stix_objs, [filters[13]]))
    assert len(resp) == 0

    resp = list(apply_common_filters(real_stix_objs, [filters[13]]))
    assert len(resp) == 0


def test_apply_common_filters13():
    # Return any object that matches file object in "objects"
    resp = list(apply_common_filters(stix_objs, [filters[14]]))
    assert resp[0]["id"] == stix_objs[4]["id"]
    assert len(resp) == 1
    # important additional check to make sure original File dict was
    # not converted to File object. (this was a deep bug found)
    assert isinstance(resp[0]["objects"]["0"], dict)

    resp = list(apply_common_filters(real_stix_objs, [filters[14]]))
    assert resp[0].id == real_stix_objs[4].id
    assert len(resp) == 1


def test_apply_common_filters14():
    # Return any object that contains a specific File Cyber Observable Object
    resp = list(apply_common_filters(stix_objs, [filters[15]]))
    assert resp[0]['id'] == stix_objs[4]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[15]]))
    assert resp[0].id == real_stix_objs[4].id
    assert len(resp) == 1


def test_apply_common_filters15():
    # Return any object that contains 'heartbleed' in "labels"
    resp = list(apply_common_filters(stix_objs, [filters[16]]))
    assert resp[0]['id'] == stix_objs[3]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs, [filters[16]]))
    assert resp[0].id == real_stix_objs[3].id
    assert len(resp) == 1


def test_datetime_filter_behavior():
    """if a filter is initialized with its value being a datetime object
    OR the STIX object property being filtered on is a datetime object, all
    resulting comparisons executed are done on the string representations
    of the datetime objects, as the Filter functionality will convert
    all datetime objects to there string forms using format_datetim()

    This test makes sure all datetime comparisons are carried out correctly
    """
    filter_with_dt_obj = Filter("created", "=", parse_into_datetime("2016-02-14T00:00:00.000Z", "millisecond"))
    filter_with_str = Filter("created", "=", "2016-02-14T00:00:00.000Z")

    # compare datetime obj to filter w/ datetime obj
    resp = list(apply_common_filters(real_stix_objs, [filter_with_dt_obj]))
    assert len(resp) == 1
    assert resp[0]["id"] == "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef"
    assert isinstance(resp[0].created, STIXdatetime)  # make sure original object not altered

    # compare datetime string to filter w/ str
    resp = list(apply_common_filters(stix_objs, [filter_with_str]))
    assert len(resp) == 1
    assert resp[0]["id"] == "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef"

    # compare datetime obj to filter w/ str
    resp = list(apply_common_filters(real_stix_objs, [filter_with_str]))
    assert len(resp) == 1
    assert resp[0]["id"] == "vulnerability--ee916c28-c7a4-4d0d-ad56-a8d357f89fef"
    assert isinstance(resp[0].created, STIXdatetime)  # make sure original object not altered


def test_filters0(stix_objs2, real_stix_objs2):
    # "Return any object modified before 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(stix_objs2, [Filter("modified", "<", "2017-01-28T13:49:53.935Z")]))
    assert resp[0]['id'] == stix_objs2[1]['id']
    assert len(resp) == 2

    resp = list(apply_common_filters(real_stix_objs2, [Filter("modified", "<", parse_into_datetime("2017-01-28T13:49:53.935Z"))]))
    assert resp[0].id == real_stix_objs2[1].id
    assert len(resp) == 2


def test_filters1(stix_objs2, real_stix_objs2):
    # "Return any object modified after 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(stix_objs2, [Filter("modified", ">", "2017-01-28T13:49:53.935Z")]))
    assert resp[0]['id'] == stix_objs2[0]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs2, [Filter("modified", ">", parse_into_datetime("2017-01-28T13:49:53.935Z"))]))
    assert resp[0].id == real_stix_objs2[0].id
    assert len(resp) == 1


def test_filters2(stix_objs2, real_stix_objs2):
    # "Return any object modified after or on 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(stix_objs2, [Filter("modified", ">=", "2017-01-27T13:49:53.935Z")]))
    assert resp[0]['id'] == stix_objs2[0]['id']
    assert len(resp) == 3

    resp = list(apply_common_filters(real_stix_objs2, [Filter("modified", ">=", parse_into_datetime("2017-01-27T13:49:53.935Z"))]))
    assert resp[0].id == real_stix_objs2[0].id
    assert len(resp) == 3


def test_filters3(stix_objs2, real_stix_objs2):
    # "Return any object modified before or on 2017-01-28T13:49:53.935Z"
    resp = list(apply_common_filters(stix_objs2, [Filter("modified", "<=", "2017-01-27T13:49:53.935Z")]))
    assert resp[0]['id'] == stix_objs2[1]['id']
    assert len(resp) == 2

    # "Return any object modified before or on 2017-01-28T13:49:53.935Z"
    fv = Filter("modified", "<=", parse_into_datetime("2017-01-27T13:49:53.935Z"))
    resp = list(apply_common_filters(real_stix_objs2, [fv]))
    assert resp[0].id == real_stix_objs2[1].id
    assert len(resp) == 2


def test_filters4():
    # Assert invalid Filter cannot be created
    with pytest.raises(ValueError) as excinfo:
        Filter("modified", "?", "2017-01-27T13:49:53.935Z")
    assert str(excinfo.value) == (
        "Filter operator '?' not supported "
        "for specified property: 'modified'"
    )


def test_filters5(stix_objs2, real_stix_objs2):
    # "Return any object whose id is not indicator--00000000-0000-4000-8000-000000000002"
    resp = list(apply_common_filters(stix_objs2, [Filter("id", "!=", "indicator--00000000-0000-4000-8000-000000000002")]))
    assert resp[0]['id'] == stix_objs2[0]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objs2, [Filter("id", "!=", "indicator--00000000-0000-4000-8000-000000000002")]))
    assert resp[0].id == real_stix_objs2[0].id
    assert len(resp) == 1


def test_filters6(stix_objs2, real_stix_objs2):
    # Test filtering on non-common property
    resp = list(apply_common_filters(stix_objs2, [Filter("name", "=", "Malicious site hosting downloader")]))
    assert resp[0]['id'] == stix_objs2[0]['id']
    assert len(resp) == 3

    resp = list(apply_common_filters(real_stix_objs2, [Filter("name", "=", "Malicious site hosting downloader")]))
    assert resp[0].id == real_stix_objs2[0].id
    assert len(resp) == 3


def test_filters7(stix_objs2, real_stix_objs2):
    # Test filtering on embedded property
    obsvd_data_obj = {
        "type": "observed-data",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 50,
        "objects": {
            "0": {
                "type": "file",
                "hashes": {
                    "SHA-256": "35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d92ad1b7100f",
                },
                "extensions": {
                    "pdf-ext": {
                        "version": "1.7",
                        "document_info_dict": {
                            "Title": "Sample document",
                            "Author": "Adobe Systems Incorporated",
                            "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
                            "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
                            "CreationDate": "20070412090123-02",
                        },
                        "pdfid0": "DFCE52BD827ECF765649852119D",
                        "pdfid1": "57A1E0F9ED2AE523E313C",
                    },
                },
            },
        },
    }

    stix_objects = list(stix_objs2) + [obsvd_data_obj]
    real_stix_objects = list(real_stix_objs2) + [parse(obsvd_data_obj)]

    resp = list(apply_common_filters(stix_objects, [Filter("objects.0.extensions.pdf-ext.version", ">", "1.2")]))
    assert resp[0]['id'] == stix_objects[3]['id']
    assert len(resp) == 1

    resp = list(apply_common_filters(real_stix_objects, [Filter("objects.0.extensions.pdf-ext.version", ">", "1.2")]))
    assert resp[0].id == real_stix_objects[3].id
    assert len(resp) == 1
