"""Classes to aid in working with the STIX 2 patterning language.
"""

import base64
import binascii
import re


def escape_quotes_and_backslashes(s):
    return s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")


class _Constant(object):
    pass


class StringConstant(_Constant):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "'%s'" % escape_quotes_and_backslashes(self.value)


class TimestampConstant(_Constant):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return "t'%s'" % escape_quotes_and_backslashes(self.value)


class IntegerConstant(_Constant):
    def __init__(self, value):
        try:
            self.value = int(value)
        except Exception:
            raise ValueError("must be an integer.")

    def __str__(self):
        return "%s" % self.value


class FloatConstant(_Constant):
    def __init__(self, value):
        try:
            self.value = float(value)
        except Exception:
            raise ValueError("must be an float.")

    def __str__(self):
        return "%s" % self.value


class BooleanConstant(_Constant):
    def __init__(self, value):
        if isinstance(value, bool):
            self.value = value

        trues = ['true', 't']
        falses = ['false', 'f']
        try:
            if value.lower() in trues:
                self.value = True
            if value.lower() in falses:
                self.value = False
        except AttributeError:
            if value == 1:
                self.value = True
            if value == 0:
                self.value = False

        raise ValueError("must be a boolean value.")

    def __str__(self):
        return "%s" % self.value


_HASH_REGEX = {
    "MD5": ("^[a-fA-F0-9]{32}$", "MD5"),
    "MD6": ("^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}$", "MD6"),
    "RIPEMD160": ("^[a-fA-F0-9]{40}$", "RIPEMD-160"),
    "SHA1": ("^[a-fA-F0-9]{40}$", "SHA-1"),
    "SHA224": ("^[a-fA-F0-9]{56}$", "SHA-224"),
    "SHA256": ("^[a-fA-F0-9]{64}$", "SHA-256"),
    "SHA384": ("^[a-fA-F0-9]{96}$", "SHA-384"),
    "SHA512": ("^[a-fA-F0-9]{128}$", "SHA-512"),
    "SHA3224": ("^[a-fA-F0-9]{56}$", "SHA3-224"),
    "SHA3256": ("^[a-fA-F0-9]{64}$", "SHA3-256"),
    "SHA3384": ("^[a-fA-F0-9]{96}$", "SHA3-384"),
    "SHA3512": ("^[a-fA-F0-9]{128}$", "SHA3-512"),
    "SSDEEP": ("^[a-zA-Z0-9/+:.]{1,128}$", "ssdeep"),
    "WHIRLPOOL": ("^[a-fA-F0-9]{128}$", "WHIRLPOOL"),
}


class HashConstant(StringConstant):
    def __init__(self, value, type):
        key = type.upper().replace('-', '')
        if key in _HASH_REGEX:
            vocab_key = _HASH_REGEX[key][1]
            if not re.match(_HASH_REGEX[key][0], value):
                raise ValueError("'%s' is not a valid %s hash" % (value, vocab_key))
            self.value = value


class BinaryConstant(_Constant):

    def __init__(self, value):
        try:
            base64.b64decode(value)
            self.value = value
        except (binascii.Error, TypeError):
            raise ValueError("must contain a base64 encoded string")

    def __str__(self):
        return "b'%s'" % self.value


class HexConstant(_Constant):
    def __init__(self, value):
        if not re.match('^([a-fA-F0-9]{2})+$', value):
            raise ValueError("must contain an even number of hexadecimal characters")
        self.value = value

    def __str__(self):
        return "h'%s'" % self.value


class ListConstant(_Constant):
    def __init__(self, values):
        self.value = values

    def __str__(self):
        return "(" + ", ".join([("%s" % x) for x in self.value]) + ")"


def make_constant(value):
    if isinstance(value, str):
        return StringConstant(value)
    elif isinstance(value, int):
        return IntegerConstant(value)
    elif isinstance(value, float):
        return FloatConstant(value)
    elif isinstance(value, list):
        return ListConstant(value)
    elif isinstance(value, bool):
        return BooleanConstant(value)
    else:
        raise ValueError("Unable to create a constant from %s" % value)


class _ObjectPathComponent(object):
    @staticmethod
    def create_ObjectPathComponent(component_name):
        if component_name.endswith("_ref"):
            return ReferenceObjectPathComponent(component_name)
        elif component_name.find("[") != -1:
            parse1 = component_name.split("[")
            return ListObjectPathComponent(parse1[0], parse1[1][:-1])
        else:
            return BasicObjectPathComponent(component_name)


class BasicObjectPathComponent(_ObjectPathComponent):
    def __init__(self, property_name, is_key=False):
        self.property_name = property_name
        # TODO: set is_key to True if this component is a dictionary key
        # self.is_key = is_key

    def __str__(self):
        return self.property_name


class ListObjectPathComponent(_ObjectPathComponent):
    def __init__(self, property_name, index):
        self.property_name = property_name
        self.index = index

    def __str__(self):
        return "%s[%s]" % (self.property_name, self.index)


class ReferenceObjectPathComponent(_ObjectPathComponent):
    def __init__(self, reference_property_name):
        self.property_name = reference_property_name

    def __str__(self):
        return self.property_name


class ObjectPath(object):
    def __init__(self, object_type_name, property_path):
        self.object_type_name = object_type_name
        self.property_path = [x if isinstance(x, _ObjectPathComponent) else
                              _ObjectPathComponent.create_ObjectPathComponent(x)
                              for x in property_path]

    def __str__(self):
        return "%s:%s" % (self.object_type_name, ".".join(["%s" % x for x in self.property_path]))

    def merge(self, other):
        self.property_path.extend(other.property_path)
        return self

    @staticmethod
    def make_object_path(lhs):
        path_as_parts = lhs.split(":")
        return ObjectPath(path_as_parts[0], path_as_parts[1].split("."))


class _PatternExpression(object):

    @staticmethod
    def escape_quotes_and_backslashes(s):
        return s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")


class _ComparisonExpression(_PatternExpression):
    def __init__(self, operator, lhs, rhs, negated=False):
        if operator == "=" and isinstance(rhs, ListConstant):
            self.operator = "IN"
        else:
            self.operator = operator
        if isinstance(lhs, ObjectPath):
            self.lhs = lhs
        else:
            self.lhs = ObjectPath.make_object_path(lhs)
        if isinstance(rhs, _Constant):
            self.rhs = rhs
        else:
            self.rhs = make_constant(rhs)
        self.negated = negated
        self.root_type = self.lhs.object_type_name

    def __str__(self):
        # if isinstance(self.rhs, list):
        #     final_rhs = []
        #     for r in self.rhs:
        #         final_rhs.append("'" + self.escape_quotes_and_backslashes("%s" % r) + "'")
        #     rhs_string = "(" + ", ".join(final_rhs) + ")"
        # else:
        #     rhs_string = self.rhs
        if self.negated:
            return "%s NOT %s %s" % (self.lhs, self.operator, self.rhs)
        else:
            return "%s %s %s" % (self.lhs, self.operator, self.rhs)


class EqualityComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(EqualityComparisonExpression, self).__init__("=", lhs, rhs, negated)


class GreaterThanComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanComparisonExpression, self).__init__(">", lhs, rhs, negated)


class LessThanComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanComparisonExpression, self).__init__("<", lhs, rhs, negated)


class GreaterThanEqualComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanEqualComparisonExpression, self).__init__(">=", lhs, rhs, negated)


class LessThanEqualComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanEqualComparisonExpression, self).__init__("<=", lhs, rhs, negated)


class InComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(InComparisonExpression, self).__init__("IN", lhs, rhs, negated)


class LikeComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LikeComparisonExpression, self).__init__("LIKE", lhs, rhs, negated)


class MatchesComparisonExpression(_ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(MatchesComparisonExpression, self).__init__("MATCHES", lhs, rhs, negated)


class IsSubsetComparisonExpression(_ComparisonExpression):
        def __init__(self, lhs, rhs, negated=False):
            super(IsSubsetComparisonExpression, self).__init__("ISSUBSET", lhs, rhs, negated)


class IsSupersetComparisonExpression(_ComparisonExpression):
        def __init__(self, lhs, rhs, negated=False):
            super(IsSupersetComparisonExpression, self).__init__("ISSUPERSET", lhs, rhs, negated)


class _BooleanExpression(_PatternExpression):
    def __init__(self, operator, operands):
        self.operator = operator
        self.operands = []
        for arg in operands:
            if not hasattr(self, "root_type"):
                self.root_type = arg.root_type
            elif self.root_type and (self.root_type != arg.root_type) and operator == "AND":
                raise ValueError("All operands to an 'AND' expression must have the same object type")
            elif self.root_type and (self.root_type != arg.root_type):
                self.root_type = None
            self.operands.append(arg)

    def __str__(self):
        sub_exprs = []
        for o in self.operands:
            sub_exprs.append("%s" % o)
        return (" " + self.operator + " ").join(sub_exprs)


class AndBooleanExpression(_BooleanExpression):
    def __init__(self, operands):
        super(AndBooleanExpression, self).__init__("AND", operands)


class OrBooleanExpression(_BooleanExpression):
    def __init__(self, operands):
        super(OrBooleanExpression, self).__init__("OR", operands)


class ObservationExpression(_PatternExpression):
    def __init__(self, operand):
        self.operand = operand

    def __str__(self):
        return "[%s]" % self.operand


class _CompoundObservationExpression(_PatternExpression):
    def __init__(self, operator, operands):
        self.operator = operator
        self.operands = operands

    def __str__(self):
        sub_exprs = []
        for o in self.operands:
            sub_exprs.append("%s" % o)
        return (" " + self.operator + " ").join(sub_exprs)


class AndObservationExpression(_CompoundObservationExpression):
    def __init__(self, operands):
        super(AndObservationExpression, self).__init__("AND", operands)


class OrObservationExpression(_CompoundObservationExpression):
    def __init__(self, operands):
        super(OrObservationExpression, self).__init__("OR", operands)


class FollowedByObservationExpression(_CompoundObservationExpression):
    def __init__(self, operands):
        super(FollowedByObservationExpression, self).__init__("FOLLOWEDBY", operands)


class ParentheticalExpression(_PatternExpression):
    def __init__(self, exp):
        self.expression = exp
        if hasattr(exp, "root_type"):
            self.root_type = exp.root_type

    def __str__(self):
        return "(%s)" % self.expression


class _ExpressionQualifier(_PatternExpression):
    pass


class RepeatQualifier(_ExpressionQualifier):
    def __init__(self, times_to_repeat):
        if isinstance(times_to_repeat, IntegerConstant):
            self.times_to_repeat = times_to_repeat
        elif isinstance(times_to_repeat, int):
            self.times_to_repeat = IntegerConstant(times_to_repeat)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % times_to_repeat)

    def __str__(self):
        return "REPEATS %s TIMES" % self.times_to_repeat


class WithinQualifier(_ExpressionQualifier):
    def __init__(self, number_of_seconds):
        if isinstance(number_of_seconds, IntegerConstant):
            self.number_of_seconds = number_of_seconds
        elif isinstance(number_of_seconds, int):
            self.number_of_seconds = IntegerConstant(number_of_seconds)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % number_of_seconds)

    def __str__(self):
        return "WITHIN %s SECONDS" % self.number_of_seconds


class StartStopQualifier(_ExpressionQualifier):
    def __init__(self, start_time, stop_time):
        if isinstance(start_time, IntegerConstant):
            self.start_time = start_time
        elif isinstance(start_time, int):
            self.start_time = IntegerConstant(start_time)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % start_time)
        if isinstance(stop_time, IntegerConstant):
            self.stop_time = stop_time
        elif isinstance(stop_time, int):
            self.stop_time = IntegerConstant(stop_time)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % stop_time)

    def __str__(self):
        return "START %s STOP %s" % (self.start_time, self.stop_time)


class QualifiedObservationExpression(_PatternExpression):
    def __init__(self, observation_expression, qualifier):
        self.observation_expression = observation_expression
        self.qualifier = qualifier

    def __str__(self):
        return "%s %s" % (self.observation_expression, self.qualifier)
