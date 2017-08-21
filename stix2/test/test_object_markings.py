
import pytest

from stix2 import Malware, exceptions, markings

from .constants import FAKE_TIME, MALWARE_ID, MARKING_IDS
from .constants import MALWARE_KWARGS as MALWARE_KWARGS_CONST

"""Tests for the Data Markings API."""

MALWARE_KWARGS = MALWARE_KWARGS_CONST.copy()
MALWARE_KWARGS.update({
    'id': MALWARE_ID,
    'created': FAKE_TIME,
    'modified': FAKE_TIME,
})


def test_add_markings_one_marking():
    before = {
        "title": "test title",
        "description": "test description"
    }

    after = {
        "title": "test title",
        "description": "test description",
        "object_marking_refs": [MARKING_IDS[0]]
    }

    markings.add_markings(before, None, MARKING_IDS[0])

    assert before == after


def test_add_markings_multiple_marking():
    before = {
        "title": "test title",
        "description": "test description"
    }

    after = {
        "title": "test title",
        "description": "test description",
        "object_marking_refs": [MARKING_IDS[0], MARKING_IDS[1]]
    }

    markings.add_markings(before, None, [MARKING_IDS[0], MARKING_IDS[1]])

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
                "selectors": ["labels"],
                "marking_ref": MARKING_IDS[2]
            },
            {
                "selectors": ["name"],
                "marking_ref": MARKING_IDS[3]
            },
        ],
        **MALWARE_KWARGS
    )

    before = markings.add_markings(before, None, MARKING_IDS[0])
    before = markings.add_markings(before, None, MARKING_IDS[1])
    before = markings.add_markings(before, "labels", MARKING_IDS[2])
    before = markings.add_markings(before, "name", MARKING_IDS[3])

    for m in before["granular_markings"]:
        assert m in after["granular_markings"]

    for m in before["object_marking_refs"]:
        assert m in after["object_marking_refs"]


@pytest.mark.parametrize("data", [
    ([""]),
    (""),
    ([]),
    ([MARKING_IDS[0], 456])
])
def test_add_markings_bad_markings(data):
    before = Malware(
        **MALWARE_KWARGS
    )
    with pytest.raises(exceptions.InvalidValueError):
        before = markings.add_markings(before, None, data)

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
                "h": 45
            }
        ],
        "x": {
            "y": [
                "hello",
                88
            ],
            "z": {
                "foo1": "bar",
                "foo2": 65
            }
        },
        "object_marking_refs": ["11"],
        "granular_markings": [
            {
                "marking_ref": "1",
                "selectors": ["a"]
            },
            {
                "marking_ref": "2",
                "selectors": ["c"]
            },
            {
                "marking_ref": "3",
                "selectors": ["c.[1]"]
            },
            {
                "marking_ref": "4",
                "selectors": ["c.[2]"]
            },
            {
                "marking_ref": "5",
                "selectors": ["c.[2].g"]
            },
            {
                "marking_ref": "6",
                "selectors": ["x"]
            },
            {
                "marking_ref": "7",
                "selectors": ["x.y"]
            },
            {
                "marking_ref": "8",
                "selectors": ["x.y.[1]"]
            },
            {
                "marking_ref": "9",
                "selectors": ["x.z"]
            },
            {
                "marking_ref": "10",
                "selectors": ["x.z.foo2"]
            },
        ]
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


def test_remove_markings_object_level():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0]],
        **MALWARE_KWARGS
    )
    after = Malware(
        **MALWARE_KWARGS
    )

    before = markings.remove_markings(before, None, MARKING_IDS[0])

    assert 'object_marking_refs' not in before
    assert 'object_marking_refs' not in after


def test_remove_markings_multiple():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
        **MALWARE_KWARGS
    )
    after = Malware(
        object_marking_refs=[MARKING_IDS[1]],
        **MALWARE_KWARGS
    )

    before = markings.remove_markings(before, None, [MARKING_IDS[0], MARKING_IDS[2]])

    assert before['object_marking_refs'] == after['object_marking_refs']


def test_remove_markings_bad_markings():
    before = {
        "title": "test title",
        "description": "test description",
        "object_marking_refs": [MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]]
    }
    with pytest.raises(AssertionError):
        markings.remove_markings(before, None, [MARKING_IDS[4]])


def test_clear_markings():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
        **MALWARE_KWARGS
    )
    after = Malware(
        **MALWARE_KWARGS
    )

    before = markings.clear_markings(before, None)

    assert 'object_marking_refs' not in before
    assert 'object_marking_refs' not in after


def test_is_marked_object_and_granular_combinations():
    """Test multiple combinations for inherited and descendant markings."""
    test_tlo = \
        {
            "a": 333,
            "b": "value",
            "c": [
                17,
                "list value",
                {
                    "g": "nested",
                    "h": 45
                }
            ],
            "x": {
                "y": [
                    "hello",
                    88
                ],
                "z": {
                    "foo1": "bar",
                    "foo2": 65
                }
            },
            "object_marking_refs": "11",
            "granular_markings": [
                {
                    "marking_ref": "1",
                    "selectors": ["a"]
                },
                {
                    "marking_ref": "2",
                    "selectors": ["c"]
                },
                {
                    "marking_ref": "3",
                    "selectors": ["c.[1]"]
                },
                {
                    "marking_ref": "4",
                    "selectors": ["c.[2]"]
                },
                {
                    "marking_ref": "5",
                    "selectors": ["c.[2].g"]
                },
                {
                    "marking_ref": "6",
                    "selectors": ["x"]
                },
                {
                    "marking_ref": "7",
                    "selectors": ["x.y"]
                },
                {
                    "marking_ref": "8",
                    "selectors": ["x.y.[1]"]
                },
                {
                    "marking_ref": "9",
                    "selectors": ["x.z"]
                },
                {
                    "marking_ref": "10",
                    "selectors": ["x.z.foo2"]
                },
            ]
        }

    assert markings.is_marked(test_tlo, "a", ["1"], False, False)
    assert markings.is_marked(test_tlo, "a", ["1", "11"], True, False)
    assert markings.is_marked(test_tlo, "a", ["1", "11"], True, True)
    assert markings.is_marked(test_tlo, "a", ["1"], False, True)

    assert markings.is_marked(test_tlo, "b", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "b", ["11"], True, False)
    assert markings.is_marked(test_tlo, "b", ["11"], True, True)
    assert markings.is_marked(test_tlo, "b", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "c", ["2"], False, False)
    assert markings.is_marked(test_tlo, "c", ["2", "11"], True, False)
    assert markings.is_marked(test_tlo, "c", ["2", "3", "4", "5", "11"], True, True)
    assert markings.is_marked(test_tlo, "c", ["2", "3", "4", "5"], False, True)

    assert markings.is_marked(test_tlo, "c.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "c.[0]", ["2", "11"], True, False)
    assert markings.is_marked(test_tlo, "c.[0]", ["2", "11"], True, True)
    assert markings.is_marked(test_tlo, "c.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "c.[1]", ["3"], False, False)
    assert markings.is_marked(test_tlo, "c.[1]", ["2", "3", "11"], True, False)
    assert markings.is_marked(test_tlo, "c.[1]", ["2", "3", "11"], True, True)
    assert markings.is_marked(test_tlo, "c.[1]", ["3"], False, True)

    assert markings.is_marked(test_tlo, "c.[2]", ["4"], False, False)
    assert markings.is_marked(test_tlo, "c.[2]", ["2", "4", "11"], True, False)
    assert markings.is_marked(test_tlo, "c.[2]", ["2", "4", "5", "11"], True, True)
    assert markings.is_marked(test_tlo, "c.[2]", ["4", "5"], False, True)

    assert markings.is_marked(test_tlo, "c.[2].g", ["5"], False, False)
    assert markings.is_marked(test_tlo, "c.[2].g", ["2", "4", "5", "11"], True, False)
    assert markings.is_marked(test_tlo, "c.[2].g", ["2", "4", "5", "11"], True, True)
    assert markings.is_marked(test_tlo, "c.[2].g", ["5"], False, True)

    assert markings.is_marked(test_tlo, "x", ["6"], False, False)
    assert markings.is_marked(test_tlo, "x", ["6", "11"], True, False)
    assert markings.is_marked(test_tlo, "x", ["6", "7", "8", "9", "10", "11"], True, True)
    assert markings.is_marked(test_tlo, "x", ["6", "7", "8", "9", "10"], False, True)

    assert markings.is_marked(test_tlo, "x.y", ["7"], False, False)
    assert markings.is_marked(test_tlo, "x.y", ["6", "7", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.y", ["6", "7", "8", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.y", ["7", "8"], False, True)

    assert markings.is_marked(test_tlo, "x.y.[0]", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "x.y.[0]", ["6", "7", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.y.[0]", ["6", "7", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.y.[0]", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "x.y.[1]", ["8"], False, False)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["6", "7", "8", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["6", "7", "8", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.y.[1]", ["8"], False, True)

    assert markings.is_marked(test_tlo, "x.z", ["9"], False, False)
    assert markings.is_marked(test_tlo, "x.z", ["6", "9", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.z", ["6", "9", "10", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.z", ["9", "10"], False, True)

    assert markings.is_marked(test_tlo, "x.z.foo1", inherited=False, descendants=False) is False
    assert markings.is_marked(test_tlo, "x.z.foo1", ["6", "9", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.z.foo1", ["6", "9", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.z.foo1", inherited=False, descendants=True) is False

    assert markings.is_marked(test_tlo, "x.z.foo2", ["10"], False, False)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["6", "9", "10", "11"], True, False)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["6", "9", "10", "11"], True, True)
    assert markings.is_marked(test_tlo, "x.z.foo2", ["10"], False, True)


def test_set_marking():
    before = Malware(
        object_marking_refs=[MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]],
        **MALWARE_KWARGS
    )
    after = Malware(
        object_marking_refs=[MARKING_IDS[4], MARKING_IDS[5]],
        **MALWARE_KWARGS
    )

    before = markings.set_markings(before, None, [MARKING_IDS[4], MARKING_IDS[5]])

    for m in before["object_marking_refs"]:
        assert m in [MARKING_IDS[4], MARKING_IDS[5]]

    assert [MARKING_IDS[0], MARKING_IDS[1], MARKING_IDS[2]] not in before["object_marking_refs"]

    for x in before["object_marking_refs"]:
        assert x in after["object_marking_refs"]


@pytest.mark.parametrize("data", [
    ([]),
    ([""]),
    (""),
    ([MARKING_IDS[4], 687])
])
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
        before = markings.set_markings(before, None, data)

    assert before == after
