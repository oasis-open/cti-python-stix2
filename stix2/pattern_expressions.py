from .constants import ListConstant, make_constant


class PatternExpression(object):

    @staticmethod
    def get_root_from_object_path(lhs):
        path_as_parts = lhs.split(":")
        return path_as_parts[0]

    @staticmethod
    def escape_quotes_and_backslashes(s):
        return s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")


class ComparisonExpression(PatternExpression):
    def __init__(self, operator, lhs, rhs, negated=False):
        if operator == "=" and isinstance(rhs, ListConstant):
            self.operator = "IN"
        else:
            self.operator = operator
        self.lhs = lhs
        if isinstance(rhs, str):
            self.rhs = make_constant(rhs)
        else:
            self.rhs = rhs
        self.negated = negated
        self.root_type = self.get_root_from_object_path(lhs)

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


# TODO: ISASUBSET, ISSUPERSET


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
        self.times_to_repeat = times_to_repeat

    def __str__(self):
        return "REPEATS %s TIMES" % self.times_to_repeat


class WithinQualifier(ExpressionQualifier):
    def __init__(self, number_of_seconds):
        self.number_of_seconds = number_of_seconds

    def __str__(self):
        return "WITHIN %s SECONDS" % self.number_of_seconds


class StartStopQualifier(ExpressionQualifier):
    def __init__(self, start_time, stop_time):
        self.start_time = start_time
        self.stop_time = stop_time

    def __str__(self):
        return "START %s STOP %s" % (self.start_time, self.stop_time)


class QualifiedObservationExpression(PatternExpression):
    def __init__(self, observation_expression, qualifier):
        self.observation_expression = observation_expression
        self.qualifier = qualifier

    def __str__(self):
        return "%s %s" % (self.observation_expression, self.qualifier)
