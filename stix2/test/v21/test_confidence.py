import pytest

from stix2.confidence.scales import (
    admiralty_credibility_to_value, dni_to_value, none_low_med_high_to_value,
    value_to_admiralty_credibility, value_to_dni,
    value_to_none_low_medium_high, value_to_wep, value_to_zero_ten,
    wep_to_value, zero_ten_to_value,
)

CONFIDENCE_ERROR_STR = "STIX Confidence value cannot be determined for %s"
RANGE_ERROR_STR = "Range of values out of bounds: %s"


def _between(x, val, y):
    return x >= val >= y


def test_confidence_range_none_low_med_high():
    confidence_range = range(-1, 101)

    for val in confidence_range:
        if val < 0 or val > 100:
            with pytest.raises(ValueError) as excinfo:
                value_to_none_low_medium_high(val)

            assert str(excinfo.value) == RANGE_ERROR_STR % val
            continue

        if val == 0:
            assert value_to_none_low_medium_high(val) == "None"
        elif _between(29, val, 1):
            assert value_to_none_low_medium_high(val) == "Low"
        elif _between(69, val, 30):
            assert value_to_none_low_medium_high(val) == "Med"
        elif _between(100, val, 70):
            assert value_to_none_low_medium_high(val) == "High"


@pytest.mark.parametrize(
    "scale_value,result", [
        ("None", 0),
        ("Low", 15),
        ("Med", 50),
        ("High", 85),
    ],
)
def test_confidence_scale_valid_none_low_med_high(scale_value, result):
    val = none_low_med_high_to_value(scale_value)
    assert val == result


@pytest.mark.parametrize(
    "scale_value", [
        "Super",
        "none",
        "",
    ],
)
def test_confidence_scale_invalid_none_low_med_high(scale_value):
    with pytest.raises(ValueError) as excinfo:
        none_low_med_high_to_value(scale_value)

    assert str(excinfo.value) == CONFIDENCE_ERROR_STR % scale_value


def test_confidence_range_zero_ten():
    confidence_range = range(-1, 101)

    for val in confidence_range:
        if val < 0 or val > 100:
            with pytest.raises(ValueError) as excinfo:
                value_to_zero_ten(val)

            assert str(excinfo.value) == RANGE_ERROR_STR % val
            continue

        if _between(4, val, 0):
            assert value_to_zero_ten(val) == "0"
        elif _between(14, val, 5):
            assert value_to_zero_ten(val) == "1"
        elif _between(24, val, 15):
            assert value_to_zero_ten(val) == "2"
        elif _between(34, val, 25):
            assert value_to_zero_ten(val) == "3"
        elif _between(44, val, 35):
            assert value_to_zero_ten(val) == "4"
        elif _between(54, val, 45):
            assert value_to_zero_ten(val) == "5"
        elif _between(64, val, 55):
            assert value_to_zero_ten(val) == "6"
        elif _between(74, val, 65):
            assert value_to_zero_ten(val) == "7"
        elif _between(84, val, 75):
            assert value_to_zero_ten(val) == "8"
        elif _between(94, val, 85):
            assert value_to_zero_ten(val) == "9"
        elif _between(100, val, 95):
            assert value_to_zero_ten(val) == "10"


@pytest.mark.parametrize(
    "scale_value,result", [
        ("0", 0),
        ("1", 10),
        ("2", 20),
        ("3", 30),
        ("4", 40),
        ("5", 50),
        ("6", 60),
        ("7", 70),
        ("8", 80),
        ("9", 90),
        ("10", 100),
    ],
)
def test_confidence_scale_valid_zero_ten(scale_value, result):
    val = zero_ten_to_value(scale_value)
    assert val == result


@pytest.mark.parametrize(
    "scale_value", [
        "11",
        8,
        "",
    ],
)
def test_confidence_scale_invalid_zero_ten(scale_value):
    with pytest.raises(ValueError) as excinfo:
        zero_ten_to_value(scale_value)

    assert str(excinfo.value) == CONFIDENCE_ERROR_STR % scale_value


def test_confidence_range_admiralty_credibility():
    confidence_range = range(-1, 101)

    for val in confidence_range:
        if val < 0 or val > 100:
            with pytest.raises(ValueError) as excinfo:
                value_to_admiralty_credibility(val)

            assert str(excinfo.value) == RANGE_ERROR_STR % val
            continue

        if _between(19, val, 0):
            assert value_to_admiralty_credibility(val) == "5 - Improbable"
        elif _between(39, val, 20):
            assert value_to_admiralty_credibility(val) == "4 - Doubtful"
        elif _between(59, val, 40):
            assert value_to_admiralty_credibility(val) == "3 - Possibly True"
        elif _between(79, val, 60):
            assert value_to_admiralty_credibility(val) == "2 - Probably True"
        elif _between(100, val, 80):
            assert value_to_admiralty_credibility(val) == "1 - Confirmed by other sources"


@pytest.mark.parametrize(
    "scale_value,result", [
        ("5 - Improbable", 10),
        ("4 - Doubtful", 30),
        ("3 - Possibly True", 50),
        ("2 - Probably True", 70),
        ("1 - Confirmed by other sources", 90),
    ],
)
def test_confidence_scale_valid_admiralty_credibility(scale_value, result):
    val = admiralty_credibility_to_value(scale_value)
    assert val == result


@pytest.mark.parametrize(
    "scale_value", [
        "5 - improbable",
        "6 - Truth cannot be judged",
        "",
    ],
)
def test_confidence_scale_invalid_admiralty_credibility(scale_value):
    with pytest.raises(ValueError) as excinfo:
        admiralty_credibility_to_value(scale_value)

    assert str(excinfo.value) == CONFIDENCE_ERROR_STR % scale_value


def test_confidence_range_wep():
    confidence_range = range(-1, 101)

    for val in confidence_range:
        if val < 0 or val > 100:
            with pytest.raises(ValueError) as excinfo:
                value_to_wep(val)

            assert str(excinfo.value) == RANGE_ERROR_STR % val
            continue

        if val == 0:
            assert value_to_wep(val) == "Impossible"
        elif _between(19, val, 1):
            assert value_to_wep(val) == "Highly Unlikely/Almost Certainly Not"
        elif _between(39, val, 20):
            assert value_to_wep(val) == "Unlikely/Probably Not"
        elif _between(59, val, 40):
            assert value_to_wep(val) == "Even Chance"
        elif _between(79, val, 60):
            assert value_to_wep(val) == "Likely/Probable"
        elif _between(99, val, 80):
            assert value_to_wep(val) == "Highly likely/Almost Certain"
        elif val == 100:
            assert value_to_wep(val) == "Certain"


@pytest.mark.parametrize(
    "scale_value,result", [
        ("Impossible", 0),
        ("Highly Unlikely/Almost Certainly Not", 10),
        ("Unlikely/Probably Not", 30),
        ("Even Chance", 50),
        ("Likely/Probable", 70),
        ("Highly likely/Almost Certain", 90),
        ("Certain", 100),
    ],
)
def test_confidence_scale_valid_wep(scale_value, result):
    val = wep_to_value(scale_value)
    assert val == result


@pytest.mark.parametrize(
    "scale_value", [
        "Unlikely / Probably Not",
        "Almost certain",
        "",
    ],
)
def test_confidence_scale_invalid_wep(scale_value):
    with pytest.raises(ValueError) as excinfo:
        wep_to_value(scale_value)

    assert str(excinfo.value) == CONFIDENCE_ERROR_STR % scale_value


def test_confidence_range_dni():
    confidence_range = range(-1, 101)

    for val in confidence_range:
        if val < 0 or val > 100:
            with pytest.raises(ValueError) as excinfo:
                value_to_dni(val)

            assert str(excinfo.value) == RANGE_ERROR_STR % val
            continue

        if _between(9, val, 0):
            assert value_to_dni(val) == "Almost No Chance / Remote"
        elif _between(19, val, 10):
            assert value_to_dni(val) == "Very Unlikely / Highly Improbable"
        elif _between(39, val, 20):
            assert value_to_dni(val) == "Unlikely / Improbable"
        elif _between(59, val, 40):
            assert value_to_dni(val) == "Roughly Even Chance / Roughly Even Odds"
        elif _between(79, val, 60):
            assert value_to_dni(val) == "Likely / Probable"
        elif _between(89, val, 80):
            assert value_to_dni(val) == "Very Likely / Highly Probable"
        elif _between(100, val, 90):
            assert value_to_dni(val) == "Almost Certain / Nearly Certain"


@pytest.mark.parametrize(
    "scale_value,result", [
        ("Almost No Chance / Remote", 5),
        ("Very Unlikely / Highly Improbable", 15),
        ("Unlikely / Improbable", 30),
        ("Roughly Even Chance / Roughly Even Odds", 50),
        ("Likely / Probable", 70),
        ("Very Likely / Highly Probable", 85),
        ("Almost Certain / Nearly Certain", 95),
    ],
)
def test_confidence_scale_valid_dni(scale_value, result):
    val = dni_to_value(scale_value)
    assert val == result


@pytest.mark.parametrize(
    "scale_value", [
        "Almost Certain/Nearly Certain",
        "Almost Certain / nearly Certain",
        "",
    ],
)
def test_confidence_scale_invalid_none_dni(scale_value):
    with pytest.raises(ValueError) as excinfo:
        dni_to_value(scale_value)

    assert str(excinfo.value) == CONFIDENCE_ERROR_STR % scale_value
