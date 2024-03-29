import datetime
import sys

import pytest

import stix2
from stix2.utils import (
    Precision, PrecisionConstraint, STIXdatetime, format_datetime,
    parse_into_datetime, to_enum,
)

_DT = datetime.datetime.utcnow()
# intentionally omit microseconds from the following.  We add it in as
# needed for each test.
_DT_STR = _DT.strftime("%Y-%m-%dT%H:%M:%S")


@pytest.mark.parametrize(
    "value, enum_type, enum_default, enum_expected", [
        ("second", Precision, None, Precision.SECOND),
        (
            "eXaCt", PrecisionConstraint, PrecisionConstraint.MIN,
            PrecisionConstraint.EXACT,
        ),
        (None, Precision, Precision.MILLISECOND, Precision.MILLISECOND),
        (Precision.ANY, Precision, None, Precision.ANY),
    ],
)
def test_to_enum(value, enum_type, enum_default, enum_expected):
    result = to_enum(value, enum_type, enum_default)
    assert result == enum_expected


@pytest.mark.parametrize(
    "value, err_type", [
        ("foo", KeyError),
        (1, TypeError),
        (PrecisionConstraint.EXACT, TypeError),
        (None, TypeError),
    ],
)
def test_to_enum_errors(value, err_type):
    with pytest.raises(err_type):
        to_enum(value, Precision)


@pytest.mark.xfail(
    sys.version_info[:2] == (3, 6), strict=True,
    reason="https://bugs.python.org/issue32404",
)
def test_stix_datetime_now():
    dt = STIXdatetime.utcnow()
    assert dt.precision is Precision.ANY
    assert dt.precision_constraint is PrecisionConstraint.EXACT


def test_stix_datetime():
    dt = datetime.datetime.utcnow()

    sdt = STIXdatetime(dt, precision=Precision.SECOND)
    assert sdt.precision is Precision.SECOND
    assert sdt == dt

    sdt = STIXdatetime(
        dt,
        precision_constraint=PrecisionConstraint.EXACT,
    )
    assert sdt.precision_constraint is PrecisionConstraint.EXACT
    assert sdt == dt


@pytest.mark.parametrize(
    "us, precision, precision_constraint, expected_truncated_us", [
        (123456, Precision.ANY, PrecisionConstraint.EXACT, 123456),
        (123456, Precision.SECOND, PrecisionConstraint.EXACT, 0),
        (123456, Precision.SECOND, PrecisionConstraint.MIN, 123456),
        (123456, Precision.MILLISECOND, PrecisionConstraint.EXACT, 123000),
        (123456, Precision.MILLISECOND, PrecisionConstraint.MIN, 123456),
        (1234, Precision.MILLISECOND, PrecisionConstraint.EXACT, 1000),
        (123, Precision.MILLISECOND, PrecisionConstraint.EXACT, 0),
    ],
)
def test_parse_datetime(
    us, precision, precision_constraint, expected_truncated_us,
):

    # complete the datetime string with microseconds
    dt_us_str = "{}.{:06d}Z".format(_DT_STR, us)

    sdt = parse_into_datetime(
        dt_us_str,
        precision=precision,
        precision_constraint=precision_constraint,
    )

    assert sdt.precision is precision
    assert sdt.precision_constraint is precision_constraint
    assert sdt.microsecond == expected_truncated_us


@pytest.mark.parametrize(
    "us, precision, precision_constraint, expected_us_str", [
        (123456, Precision.ANY, PrecisionConstraint.EXACT, ".123456"),
        (123456, Precision.SECOND, PrecisionConstraint.EXACT, ""),
        (123456, Precision.SECOND, PrecisionConstraint.MIN, ".123456"),
        (123456, Precision.MILLISECOND, PrecisionConstraint.EXACT, ".123"),
        (123456, Precision.MILLISECOND, PrecisionConstraint.MIN, ".123456"),
        (0, Precision.SECOND, PrecisionConstraint.MIN, ""),
        (0, Precision.MILLISECOND, PrecisionConstraint.MIN, ".000"),
        (0, Precision.MILLISECOND, PrecisionConstraint.EXACT, ".000"),
        (1000, Precision.MILLISECOND, PrecisionConstraint.EXACT, ".001"),
        (10000, Precision.MILLISECOND, PrecisionConstraint.EXACT, ".010"),
        (100000, Precision.MILLISECOND, PrecisionConstraint.EXACT, ".100"),
        (1000, Precision.ANY, PrecisionConstraint.EXACT, ".001"),
        (10000, Precision.ANY, PrecisionConstraint.EXACT, ".01"),
        (100000, Precision.ANY, PrecisionConstraint.EXACT, ".1"),
        (1001, Precision.MILLISECOND, PrecisionConstraint.MIN, ".001001"),
        (10010, Precision.MILLISECOND, PrecisionConstraint.MIN, ".01001"),
        (100100, Precision.MILLISECOND, PrecisionConstraint.MIN, ".1001"),
    ],
)
def test_format_datetime(us, precision, precision_constraint, expected_us_str):

    dt = _DT.replace(microsecond=us)
    expected_dt_str = "{}{}Z".format(_DT_STR, expected_us_str)

    sdt = STIXdatetime(
        dt,
        precision=precision,
        precision_constraint=precision_constraint,
    )
    s = format_datetime(sdt)
    assert s == expected_dt_str


def test_sdo_extra_precision():
    # add extra precision for "modified", ensure it's not lost
    identity_dict = {
        "type": "identity",
        "id": "identity--4a457eeb-6639-4aa3-be81-5930a3000c39",
        "created": "2015-12-21T19:59:11.000Z",
        "modified": "2015-12-21T19:59:11.0001Z",
        "name": "John Smith",
        "identity_class": "individual",
        "spec_version": "2.1",
    }

    identity_obj = stix2.parse(identity_dict)
    assert identity_obj.modified.microsecond == 100
    assert identity_obj.modified.precision is Precision.MILLISECOND
    assert identity_obj.modified.precision_constraint is PrecisionConstraint.MIN

    identity_str = identity_obj.serialize(pretty=True)

    # ensure precision is retained in JSON
    assert identity_str == """{
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--4a457eeb-6639-4aa3-be81-5930a3000c39",
    "created": "2015-12-21T19:59:11.000Z",
    "modified": "2015-12-21T19:59:11.0001Z",
    "name": "John Smith",
    "identity_class": "individual"
}"""
