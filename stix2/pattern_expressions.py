from .constants import Constant, IntegerConstant, ListConstant, make_constant
from .object_path import ObjectPath


class PatternExpression(object):

    @staticmethod
    def escape_quotes_and_backslashes(s):
        return s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")


class ComparisonExpression(PatternExpression):
    def __init__(self, operator, lhs, rhs, negated=False):
        if operator == "=" and isinstance(rhs, ListConstant):
            self.operator = "IN"
        else:
            self.operator = operator
        if isinstance(lhs, ObjectPath):
            self.lhs = lhs
        else:
            self.lhs = ObjectPath.make_object_path(lhs)
        if isinstance(rhs, Constant):
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


class EqualityComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(EqualityComparisonExpression, self).__init__("=", lhs, rhs, negated)


class GreaterThanComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanComparisonExpression, self).__init__(">", lhs, rhs, negated)


class LessThanComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanComparisonExpression, self).__init__("<", lhs, rhs, negated)


class GreaterThanEqualComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(GreaterThanComparisonExpression, self).__init__(">=", lhs, rhs, negated)


class LessThanEqualComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LessThanComparisonExpression, self).__init__("<=", lhs, rhs, negated)


class InComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(InComparisonExpression, self).__init__("IN", lhs, rhs, negated)


class LikeComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(LikeComparisonExpression, self).__init__("LIKE", lhs, rhs, negated)


class MatchesComparisonExpression(ComparisonExpression):
    def __init__(self, lhs, rhs, negated=False):
        super(MatchesComparisonExpression, self).__init__("MATCHES", lhs, rhs, negated)


class IsSubsetComparisonExpression(ComparisonExpression):
        def __init__(self, lhs, rhs, negated=False):
            super(IsSubsetComparisonExpression, self).__init__("ISSUBSET", lhs, rhs, negated)


class IsSupersetComparisonExpression(ComparisonExpression):
        def __init__(self, lhs, rhs, negated=False):
            super(IsSupersetComparisonExpression, self).__init__("ISSUPERSET", lhs, rhs, negated)


class BooleanExpression(PatternExpression):
    def __init__(self, operator, operands):
        self.operator = operator
        self.operands = []
        for arg in operands:
            if not hasattr(self, "root_type"):
                self.root_type = arg.root_type
            elif self.root_type and (self.root_type != arg.root_type) and operator == "AND":
                raise ValueError("This expression cannot have a mixed root type")
            elif self.root_type and (self.root_type != arg.root_type):
                self.root_type = None
            self.operands.append(arg)

    def __str__(self):
        sub_exprs = []
        for o in self.operands:
            sub_exprs.append("%s" % o)
        return (" " + self.operator + " ").join(sub_exprs)


class AndBooleanExpression(BooleanExpression):
    def __init__(self, operands):
        super(AndBooleanExpression, self).__init__("AND", operands)


class OrBooleanExpression(BooleanExpression):
    def __init__(self, operands):
        super(OrBooleanExpression, self).__init__("OR", operands)


class ObservableExpression(PatternExpression):
    def __init__(self, operand):
        self.operand = operand

    def __str__(self):
        return "[%s]" % self.operand


class CompoundObservableExpression(PatternExpression):
    def __init__(self, operator, operands):
        self.operator = operator
        self.operands = operands

    def __str__(self):
        sub_exprs = []
        for o in self.operands:
            sub_exprs.append("%s" % o)
        return (" " + self.operator + " ").join(sub_exprs)


class AndObservableExpression(CompoundObservableExpression):
    def __init__(self, operands):
        super(AndObservableExpression, self).__init__("AND", operands)


class OrObservableExpression(CompoundObservableExpression):
    def __init__(self, operands):
        super(OrObservableExpression, self).__init__("OR", operands)


class FollowedByObservableExpression(CompoundObservableExpression):
    def __init__(self, operands):
        super(FollowedByObservableExpression, self).__init__("FOLLOWEDBY", operands)


class ParentheticalExpression(PatternExpression):
    def __init__(self, exp):
        self.expression = exp
        if hasattr(exp, "root_type"):
            self.root_type = exp.root_type

    def __str__(self):
        return "(%s)" % self.expression


class ExpressionQualifier(PatternExpression):
    pass


class RepeatQualifier(ExpressionQualifier):
    def __init__(self, times_to_repeat):
        if isinstance(times_to_repeat, IntegerConstant):
            self.times_to_repeat = times_to_repeat
        elif isinstance(times_to_repeat, int):
            self.times_to_repeat = IntegerConstant(times_to_repeat)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % times_to_repeat)

    def __str__(self):
        return "REPEATS %s TIMES" % self.times_to_repeat


class WithinQualifier(ExpressionQualifier):
    def __init__(self, number_of_seconds):
        if isinstance(number_of_seconds, IntegerConstant):
            self.number_of_seconds = number_of_seconds
        elif isinstance(number_of_seconds, int):
            self.number_of_seconds = IntegerConstant(number_of_seconds)
        else:
            raise ValueError("%s is not a valid argument for a Within Qualifier" % number_of_seconds)

    def __str__(self):
        return "WITHIN %s SECONDS" % self.number_of_seconds


class StartStopQualifier(ExpressionQualifier):
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


class QualifiedObservationExpression(PatternExpression):
    def __init__(self, observation_expression, qualifier):
        self.observation_expression = observation_expression
        self.qualifier = qualifier

    def __str__(self):
        return "%s %s" % (self.observation_expression, self.qualifier)
