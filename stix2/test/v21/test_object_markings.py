import pytest

from stix2 import exceptions, markings
from stix2.v21 import TLP_AMBER, Malware

from .constants import FAKE_TIME, MALWARE_ID
from .constants import MALWARE_KWARGS as MALWARE_KWARGS_CONST
from .constants import MARKING_IDS

"""Tests for the Data Markings API."""

MALWARE_KWARGS = MALWARE_KWARGS_CONST.copy()
MALWARE_KWARGS.update({
    'id': MALWARE_ID,
    'created': FAKE_TIME,
    'modified': FAKE_TIME,
})


@pytest.mark.parametrize(
    "data", [
        (
            Malware(**MALWARE_KWARGS),
            Malware(
                object_marking_refs=[MARKING_IDS[0]],
                **MALWARE_KWARGS
            ),
            MARKING_IDS[0],
        ),
        (
            MALWARE_KWARGS,
            dict(
                object_marking_refs=[MARKING_IDS[0]],
                **MALWARE_KWARGS
            ),
            MARKING_IDS[0],
        ),
        (
            Malware(**MALWARE_KWARGS),
            Malware(
                object_marking_refs=[TLP_AMBER.id],
                **MALWARE_KWARGS
            ),
            TLP_AMBER,
        ),
    ],
)
def test_add_markings_one_marking(data):
    before = data[0]
    after = data[1]

    before = markings.add_markings(before, data[2], None)

    for m in before["object_marking_refs"]:
        assert m in after["object_marking_refs"]


def test_add_markings_multiple_marking():
    before = Malware(
        **MALWARE_KWARGS
    )

    after = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1]],
        **MALWARE_KWARGS
    )

    before = markings.add_markings(before, [MARKING_IDS[0], MARKING_IDS[1]], None)

    for m in before["object_marking_refs"]:
        assert m in after["object_marking_refs"]


def test_add_markings_combination():
    before = Malware(
        **MALWARE_KWARGS
    )
    after = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1]],
        granular_markings=[
            {
                "selectors": ["malware_types"],
                "marking_ref": MARKING_IDS[2],
            },
            {
                "selectors": ["name"],
                "marking_ref": MARKING_IDS[3],
            },
        ],
        **MALWARE_KWARGS
    )

    before = markings.add_markings(before, MARKING_IDS[0], None)
    before = markings.add_markings(before, MARKING_IDS[1], None)
    before = markings.add_markings(before, MARKING_IDS[2], "malware_types")
    before = markings.add_markings(before, MARKING_IDS[3], "name")

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]

    for m in before["object_marking_refs"]:
        assert m in after["object_marking_refs"]


@pytest.mark.parametrize(
    "data", [
        ([""]),
        (""),
        ([]),
        ([MARKING_IDS[0], 456]),
    ],
)
def test_add_markings_bad_markings(data):
    before = Malware(
        **MALWARE_KWARGS
    )
    with pytest.raises(exceptions.InvalidValueError):
        before = markings.add_markings(before, data, None)

    assert "object_marking_refs" not in before


GET_MARKINGS_TEST_DATA = \
    {
        "a": 333,
        "b": "value",
        "c": [
            17,
            "list value",
            {
                "g": "nested",
                "h": 45,
            },
        ],
        "x": {
            "y": [
                "hello",
                88,
            ],
            "z": {
                "foo1": "bar",
                "foo2": 65,
            },
        },
        "object_marking_refs": ["11"],
        "granular_markings": [
            {
                "marking_ref": "1",
                "selectors": ["a"],
            },
            {
                "marking_ref": "2",
                "selectors": ["c"],
            },
            {
                "marking_ref": "3",
                "selectors": ["c.[1]"],
            },
            {
                "marking_ref": "4",
                "selectors": ["c.[2]"],
            },
            {
                "marking_ref": "5",
                "selectors": ["c.[2].g"],
            },
            {
                "marking_ref": "6",
                "selectors": ["x"],
            },
            {
                "marking_ref": "7",
                "selectors": ["x.y"],
            },
            {
                "marking_ref": "8",
                "selectors": ["x.y.[1]"],
            },
            {
                "marking_ref": "9",
                "selectors": ["x.z"],
            },
            {
                "marking_ref": "10",
                "selectors": ["x.z.foo2"],
            },
        ],
    }


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_object_marking(data):
    assert set(markings.get_markings(data, None)) == set(["11"])


@pytest.mark.parametrize("data", [GET_MARKINGS_TEST_DATA])
def test_get_markings_object_and_granular_combinations(data):
    """Test multiple combinations for inherited and descendant markings."""
    assert set(markings.get_markings(data, "a", False, False)) == set(["1"])
    assert set(markings.get_markings(data, "a", True, False)) == set(["1", "11"])
    assert set(markings.get_markings(data, "a", True, True)) == set(["1", "11"])
    assert set(markings.get_markings(data, "a", False, True)) == set(["1"])

    assert set(markings.get_markings(data, "b", False, False)) == set([])
    assert set(markings.get_markings(data, "b", True, False)) == set(["11"])
    assert set(markings.get_markings(data, "b", True, True)) == set(["11"])
    assert set(markings.get_markings(data, "b", False, True)) == set([])

    assert set(markings.get_markings(data, "c", False, False)) == set(["2"])
    assert set(markings.get_markings(data, "c", True, False)) == set(["2", "11"])
    assert set(markings.get_markings(data, "c", True, True)) == set(["2", "3", "4", "5", "11"])
    assert set(markings.get_markings(data, "c", False, True)) == set(["2", "3", "4", "5"])

    assert set(markings.get_markings(data, "c.[0]", False, False)) == set([])
    assert set(markings.get_markings(data, "c.[0]", True, False)) == set(["2", "11"])
    assert set(markings.get_markings(data, "c.[0]", True, True)) == set(["2", "11"])
    assert set(markings.get_markings(data, "c.[0]", False, True)) == set([])

    assert set(markings.get_markings(data, "c.[1]", False, False)) == set(["3"])
    assert set(markings.get_markings(data, "c.[1]", True, False)) == set(["2", "3", "11"])
    assert set(markings.get_markings(data, "c.[1]", True, True)) == set(["2", "3", "11"])
    assert set(markings.get_markings(data, "c.[1]", False, True)) == set(["3"])

    assert set(markings.get_markings(data, "c.[2]", False, False)) == set(["4"])
    assert set(markings.get_markings(data, "c.[2]", True, False)) == set(["2", "4", "11"])
    assert set(markings.get_markings(data, "c.[2]", True, True)) == set(["2", "4", "5", "11"])
    assert set(markings.get_markings(data, "c.[2]", False, True)) == set(["4", "5"])

    assert set(markings.get_markings(data, "c.[2].g", False, False)) == set(["5"])
    assert set(markings.get_markings(data, "c.[2].g", True, False)) == set(["2", "4", "5", "11"])
    assert set(markings.get_markings(data, "c.[2].g", True, True)) == set(["2", "4", "5", "11"])
    assert set(markings.get_markings(data, "c.[2].g", False, True)) == set(["5"])

    assert set(markings.get_markings(data, "x", False, False)) == set(["6"])
    assert set(markings.get_markings(data, "x", True, False)) == set(["6", "11"])
    assert set(markings.get_markings(data, "x", True, True)) == set(["6", "7", "8", "9", "10", "11"])
    assert set(markings.get_markings(data, "x", False, True)) == set(["6", "7", "8", "9", "10"])

    assert set(markings.get_markings(data, "x.y", False, False)) == set(["7"])
    assert set(markings.get_markings(data, "x.y", True, False)) == set(["6", "7", "11"])
    assert set(markings.get_markings(data, "x.y", True, True)) == set(["6", "7", "8", "11"])
    assert set(markings.get_markings(data, "x.y", False, True)) == set(["7", "8"])

    assert set(markings.get_markings(data, "x.y.[0]", False, False)) == set([])
    assert set(markings.get_markings(data, "x.y.[0]", True, False)) == set(["6", "7", "11"])
    assert set(markings.get_markings(data, "x.y.[0]", True, True)) == set(["6", "7", "11"])
    assert set(markings.get_markings(data, "x.y.[0]", False, True)) == set([])

    assert set(markings.get_markings(data, "x.y.[1]", False, False)) == set(["8"])
    assert set(markings.get_markings(data, "x.y.[1]", True, False)) == set(["6", "7", "8", "11"])
    assert set(markings.get_markings(data, "x.y.[1]", True, True)) == set(["6", "7", "8", "11"])
    assert set(markings.get_markings(data, "x.y.[1]", False, True)) == set(["8"])

    assert set(markings.get_markings(data, "x.z", False, False)) == set(["9"])
    assert set(markings.get_markings(data, "x.z", True, False)) == set(["6", "9", "11"])
    assert set(markings.get_markings(data, "x.z", True, True)) == set(["6", "9", "10", "11"])
    assert set(markings.get_markings(data, "x.z", False, True)) == set(["9", "10"])

    assert set(markings.get_markings(data, "x.z.foo1", False, False)) == set([])
    assert set(markings.get_markings(data, "x.z.foo1", True, False)) == set(["6", "9", "11"])
    assert set(markings.get_markings(data, "x.z.foo1", True, True)) == set(["6", "9", "11"])
    assert set(markings.get_markings(data, "x.z.foo1", False, True)) == set([])

    assert set(markings.get_markings(data, "x.z.foo2", False, False)) == set(["10"])
    assert set(markings.get_markings(data, "x.z.foo2", True, False)) == set(["6", "9", "10", "11"])
    assert set(markings.get_markings(data, "x.z.foo2", True, True)) == set(["6", "9", "10", "11"])
    assert set(markings.get_markings(data, "x.z.foo2", False, True)) == set(["10"])


@pytest.mark.parametrize(
    "data", [
        (
            Malware(
                object_marking_refs=[MARKING_IDS[0]],
                **MALWARE_KWARGS
            ),
            Malware(**MALWARE_KWARGS),
        ),
        (
            dict(
                object_marking_refs=[MARKING_IDS[0]],
                **MALWARE_KWARGS
            ),
            MALWARE_KWARGS,
        ),
    ],
)
def test_remove_markings_object_level(data):
    before = data[0]
    after = data[1]

    before = markings.remove_markings(before, MARKING_IDS[0], None)

    assert 'object_marking_refs' not in before
    assert 'object_marking_refs' not in after

    modified = after['modified']
    after = markings.remove_markings(after, MARKING_IDS[0], None)
    modified == after['modified']


@pytest.mark.parametrize(
    "data", [
        (
            Malware(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            Malware(
                object_marking_refs=[MARKING_IDS[1]],
                **MALWARE_KWARGS
            ),
            [MARKING_IDS[0], MARKING_IDS[2]],
        ),
        (
            dict(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            dict(
                object_marking_refs=[MARKING_IDS[1]],
                **MALWARE_KWARGS
            ),
            [MARKING_IDS[0], MARKING_IDS[2]],
        ),
        (
            Malware(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], TLP_AMBER.id],
                **MALWARE_KWARGS
            ),
            Malware(
                object_marking_refs=[MARKING_IDS[1]],
                **MALWARE_KWARGS
            ),
            [MARKING_IDS[0], TLP_AMBER],
        ),
    ],
)
def test_remove_markings_multiple(data):
    before = data[0]
    after = data[1]

    before = markings.remove_markings(before, data[2], None)

    assert before['object_marking_refs'] == after['object_marking_refs']


def test_remove_markings_bad_markings():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
        **MALWARE_KWARGS
    )
    with pytest.raises(AssertionError) as excinfo:
        markings.remove_markings(before, [MARKING_IDS[4]], None)
    assert str(excinfo.value) == "Marking ['%s'] was not found in Malware!" % MARKING_IDS[4]


@pytest.mark.parametrize(
    "data", [
        (
            Malware(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            Malware(**MALWARE_KWARGS),
        ),
        (
            dict(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            MALWARE_KWARGS,
        ),
    ],
)
def test_clear_markings(data):
    before = data[0]
    after = data[1]

    before = markings.clear_markings(before, None)

    assert 'object_marking_refs' not in before
    assert 'object_marking_refs' not in after


def test_is_marked_object_and_granular_combinations():
    """Test multiple combinations for inherited and descendant markings."""
    test_sdo = \
        {
            "a": 333,
            "b": "value",
            "c": [
                17,
                "list value",
                {
                    "g": "nested",
                    "h": 45,
                },
            ],
            "x": {
                "y": [
                    "hello",
                    88,
                ],
                "z": {
                    "foo1": "bar",
                    "foo2": 65,
                },
            },
            "object_marking_refs": "11",
            "granular_markings": [
                {
                    "marking_ref": "1",
                    "selectors": ["a"],
                },
                {
                    "marking_ref": "2",
                    "selectors": ["c"],
                },
                {
                    "marking_ref": "3",
                    "selectors": ["c.[1]"],
                },
                {
                    "marking_ref": "4",
                    "selectors": ["c.[2]"],
                },
                {
                    "marking_ref": "5",
                    "selectors": ["c.[2].g"],
                },
                {
                    "marking_ref": "6",
                    "selectors": ["x"],
                },
                {
                    "marking_ref": "7",
                    "selectors": ["x.y"],
                },
                {
                    "marking_ref": "8",
                    "selectors": ["x.y.[1]"],
                },
                {
                    "marking_ref": "9",
                    "selectors": ["x.z"],
                },
                {
                    "marking_ref": "10",
                    "selectors": ["x.z.foo2"],
                },
            ],
        }

    assert markings.is_marked(test_sdo, ["1"], "a", False, False)
    assert markings.is_marked(test_sdo, ["1", "11"], "a", True, False)
    assert markings.is_marked(test_sdo, ["1", "11"], "a", True, True)
    assert markings.is_marked(test_sdo, ["1"], "a", False, True)

    assert markings.is_marked(test_sdo, "b", inherited=False, descendants=False) is False
    assert markings.is_marked(test_sdo, ["11"], "b", True, False)
    assert markings.is_marked(test_sdo, ["11"], "b", True, True)
    assert markings.is_marked(test_sdo, "b", inherited=False, descendants=True) is False

    assert markings.is_marked(test_sdo, ["2"], "c", False, False)
    assert markings.is_marked(test_sdo, ["2", "11"], "c", True, False)
    assert markings.is_marked(test_sdo, ["2", "3", "4", "5", "11"], "c", True, True)
    assert markings.is_marked(test_sdo, ["2", "3", "4", "5"], "c", False, True)

    assert markings.is_marked(test_sdo, "c.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_sdo, ["2", "11"], "c.[0]", True, False)
    assert markings.is_marked(test_sdo, ["2", "11"], "c.[0]", True, True)
    assert markings.is_marked(test_sdo, "c.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_sdo, ["3"], "c.[1]", False, False)
    assert markings.is_marked(test_sdo, ["2", "3", "11"], "c.[1]", True, False)
    assert markings.is_marked(test_sdo, ["2", "3", "11"], "c.[1]", True, True)
    assert markings.is_marked(test_sdo, ["3"], "c.[1]", False, True)

    assert markings.is_marked(test_sdo, ["4"], "c.[2]", False, False)
    assert markings.is_marked(test_sdo, ["2", "4", "11"], "c.[2]", True, False)
    assert markings.is_marked(test_sdo, ["2", "4", "5", "11"], "c.[2]", True, True)
    assert markings.is_marked(test_sdo, ["4", "5"], "c.[2]", False, True)

    assert markings.is_marked(test_sdo, ["5"], "c.[2].g", False, False)
    assert markings.is_marked(test_sdo, ["2", "4", "5", "11"], "c.[2].g", True, False)
    assert markings.is_marked(test_sdo, ["2", "4", "5", "11"], "c.[2].g", True, True)
    assert markings.is_marked(test_sdo, ["5"], "c.[2].g", False, True)

    assert markings.is_marked(test_sdo, ["6"], "x", False, False)
    assert markings.is_marked(test_sdo, ["6", "11"], "x", True, False)
    assert markings.is_marked(test_sdo, ["6", "7", "8", "9", "10", "11"], "x", True, True)
    assert markings.is_marked(test_sdo, ["6", "7", "8", "9", "10"], "x", False, True)

    assert markings.is_marked(test_sdo, ["7"], "x.y", False, False)
    assert markings.is_marked(test_sdo, ["6", "7", "11"], "x.y", True, False)
    assert markings.is_marked(test_sdo, ["6", "7", "8", "11"], "x.y", True, True)
    assert markings.is_marked(test_sdo, ["7", "8"], "x.y", False, True)

    assert markings.is_marked(test_sdo, "x.y.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_sdo, ["6", "7", "11"], "x.y.[0]", True, False)
    assert markings.is_marked(test_sdo, ["6", "7", "11"], "x.y.[0]", True, True)
    assert markings.is_marked(test_sdo, "x.y.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_sdo, ["8"], "x.y.[1]", False, False)
    assert markings.is_marked(test_sdo, ["6", "7", "8", "11"], "x.y.[1]", True, False)
    assert markings.is_marked(test_sdo, ["6", "7", "8", "11"], "x.y.[1]", True, True)
    assert markings.is_marked(test_sdo, ["8"], "x.y.[1]", False, True)

    assert markings.is_marked(test_sdo, ["9"], "x.z", False, False)
    assert markings.is_marked(test_sdo, ["6", "9", "11"], "x.z", True, False)
    assert markings.is_marked(test_sdo, ["6", "9", "10", "11"], "x.z", True, True)
    assert markings.is_marked(test_sdo, ["9", "10"], "x.z", False, True)

    assert markings.is_marked(test_sdo, "x.z.foo1", inherited=False, descendants=False) is False
    assert markings.is_marked(test_sdo, ["6", "9", "11"], "x.z.foo1", True, False)
    assert markings.is_marked(test_sdo, ["6", "9", "11"], "x.z.foo1", True, True)
    assert markings.is_marked(test_sdo, "x.z.foo1", inherited=False, descendants=True) is False

    assert markings.is_marked(test_sdo, ["10"], "x.z.foo2", False, False)
    assert markings.is_marked(test_sdo, ["6", "9", "10", "11"], "x.z.foo2", True, False)
    assert markings.is_marked(test_sdo, ["6", "9", "10", "11"], "x.z.foo2", True, True)
    assert markings.is_marked(test_sdo, ["10"], "x.z.foo2", False, True)

    assert markings.is_marked(test_sdo, ["11"], None, True, True)
    assert markings.is_marked(test_sdo, ["2"], None, True, True) is False


@pytest.mark.parametrize(
    "data", [
        (
            Malware(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            Malware(**MALWARE_KWARGS),
        ),
        (
            dict(
                object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
                **MALWARE_KWARGS
            ),
            MALWARE_KWARGS,
        ),
    ],
)
def test_is_marked_no_markings(data):
    marked = data[0]
    nonmarked = data[1]

    assert markings.is_marked(marked)
    assert markings.is_marked(nonmarked) is False


def test_set_marking():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
        **MALWARE_KWARGS
    )
    after = Malware(
        object_marking_refs=[MARKING_IDS[4], MARKING_IDS[5]],
        **MALWARE_KWARGS
    )

    before = markings.set_markings(before, [MARKING_IDS[4], MARKING_IDS[5]], None)

    for m in before["object_marking_refs"]:
        assert m in [MARKING_IDS[4], MARKING_IDS[5]]

    assert [MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]] not in before["object_marking_refs"]

    for x in before["object_marking_refs"]:
        assert x in after["object_marking_refs"]


@pytest.mark.parametrize(
    "data", [
        ([]),
        ([""]),
        (""),
        ([MARKING_IDS[4], 687]),
    ],
)
def test_set_marking_bad_input(data):
    before = Malware(
        object_marking_refs=[MARKING_IDS[0]],
        **MALWARE_KWARGS
    )
    after = Malware(
        object_marking_refs=[MARKING_IDS[0]],
        **MALWARE_KWARGS
    )
    with pytest.raises(exceptions.InvalidValueError):
        before = markings.set_markings(before, data, None)

    assert before == after
