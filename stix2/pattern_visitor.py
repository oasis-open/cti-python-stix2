import importlib
import inspect

from antlr4 import CommonTokenStream, InputStream
import six
from stix2patterns.grammars.STIXPatternLexer import STIXPatternLexer
from stix2patterns.grammars.STIXPatternParser import (
    STIXPatternParser, TerminalNode,
)
from stix2patterns.grammars.STIXPatternVisitor import STIXPatternVisitor
from stix2patterns.validator import STIXPatternErrorListener

from .patterns import *
from .patterns import _BooleanExpression

# flake8: noqa F405


def collapse_lists(lists):
    result = []
    for c in lists:
        if isinstance(c, list):
            result.extend(c)
        else:
            result.append(c)
    return result


def remove_terminal_nodes(parse_tree_nodes):
    values = []
    for x in parse_tree_nodes:
        if not isinstance(x, TerminalNode):
            values.append(x)
    return values


# This class defines a complete generic visitor for a parse tree produced by STIXPatternParser.


class STIXPatternVisitorForSTIX2(STIXPatternVisitor):
    classes = {}

    def __init__(self, module_suffix, module_name):
        if module_suffix and module_name:
            self.module_suffix = module_suffix
            if not STIXPatternVisitorForSTIX2.classes:
                module = importlib.import_module(module_name)
                for k, c in inspect.getmembers(module, inspect.isclass):
                    STIXPatternVisitorForSTIX2.classes[k] = c
        else:
            self.module_suffix = None
        super(STIXPatternVisitor, self).__init__()

    def get_class(self, class_name):
        if class_name in STIXPatternVisitorForSTIX2.classes:
            return STIXPatternVisitorForSTIX2.classes[class_name]
        else:
            return None

    def instantiate(self, klass_name, *args):
        klass_to_instantiate = None
        if self.module_suffix:
            klass_to_instantiate = self.get_class(klass_name + "For" + self.module_suffix)
        if not klass_to_instantiate:
            # use the classes in python_stix2
            klass_to_instantiate = globals()[klass_name]
        return klass_to_instantiate(*args)

    # Visit a parse tree produced by STIXPatternParser#pattern.
    def visitPattern(self, ctx):
        children = self.visitChildren(ctx)
        return children[0]

    # Visit a parse tree produced by STIXPatternParser#observationExpressions.
    def visitObservationExpressions(self, ctx):
        children = self.visitChildren(ctx)
        if len(children) == 1:
            return children[0]
        else:
            return FollowedByObservationExpression([children[0], children[2]])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionOr.
    def visitObservationExpressionOr(self, ctx):
        children = self.visitChildren(ctx)
        if len(children) == 1:
            return children[0]
        else:
            return self.instantiate("OrObservationExpression", [children[0], children[2]])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionAnd.
    def visitObservationExpressionAnd(self, ctx):
        children = self.visitChildren(ctx)
        if len(children) == 1:
            return children[0]
        else:
            return self.instantiate("AndObservationExpression", [children[0], children[2]])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionRepeated.
    def visitObservationExpressionRepeated(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("QualifiedObservationExpression", children[0], children[1])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionSimple.
    def visitObservationExpressionSimple(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("ObservationExpression", children[1])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionCompound.
    def visitObservationExpressionCompound(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("ObservationExpression", children[1])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionWithin.
    def visitObservationExpressionWithin(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("QualifiedObservationExpression", children[0], children[1])

    # Visit a parse tree produced by STIXPatternParser#observationExpressionStartStop.
    def visitObservationExpressionStartStop(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("QualifiedObservationExpression", children[0], children[1])

    # Visit a parse tree produced by STIXPatternParser#comparisonExpression.
    def visitComparisonExpression(self, ctx):
        children = self.visitChildren(ctx)
        if len(children) == 1:
            return children[0]
        else:
            if isinstance(children[0], _BooleanExpression):
                children[0].operands.append(children[2])
                return children[0]
            else:
                return self.instantiate("OrBooleanExpression", [children[0], children[2]])

    # Visit a parse tree produced by STIXPatternParser#comparisonExpressionAnd.
    def visitComparisonExpressionAnd(self, ctx):
        # TODO: NOT
        children = self.visitChildren(ctx)
        if len(children) == 1:
            return children[0]
        else:
            if isinstance(children[0], _BooleanExpression):
                children[0].operands.append(children[2])
                return children[0]
            else:
                return self.instantiate("AndBooleanExpression", [children[0], children[2]])

    # Visit a parse tree produced by STIXPatternParser#propTestEqual.
    def visitPropTestEqual(self, ctx):
        children = self.visitChildren(ctx)
        operator = children[1].symbol.type
        negated = operator != STIXPatternParser.EQ
        return self.instantiate(
            "EqualityComparisonExpression", children[0], children[3 if len(children) > 3 else 2],
            negated,
        )

    # Visit a parse tree produced by STIXPatternParser#propTestOrder.
    def visitPropTestOrder(self, ctx):
        children = self.visitChildren(ctx)
        operator = children[1].symbol.type
        if operator == STIXPatternParser.GT:
            return self.instantiate(
                "GreaterThanComparisonExpression", children[0],
                children[3 if len(children) > 3 else 2], False,
            )
        elif operator == STIXPatternParser.LT:
            return self.instantiate(
                "LessThanComparisonExpression", children[0],
                children[3 if len(children) > 3 else 2], False,
            )
        elif operator == STIXPatternParser.GE:
            return self.instantiate(
                "GreaterThanEqualComparisonExpression", children[0],
                children[3 if len(children) > 3 else 2], False,
            )
        elif operator == STIXPatternParser.LE:
            return self.instantiate(
                "LessThanEqualComparisonExpression", children[0],
                children[3 if len(children) > 3 else 2], False,
            )

    # Visit a parse tree produced by STIXPatternParser#propTestSet.
    def visitPropTestSet(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("InComparisonExpression", children[0], children[3 if len(children) > 3 else 2], False)

    # Visit a parse tree produced by STIXPatternParser#propTestLike.
    def visitPropTestLike(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("LikeComparisonExpression", children[0], children[3 if len(children) > 3 else 2], False)

    # Visit a parse tree produced by STIXPatternParser#propTestRegex.
    def visitPropTestRegex(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate(
            "MatchesComparisonExpression", children[0], children[3 if len(children) > 3 else 2],
            False,
        )

    # Visit a parse tree produced by STIXPatternParser#propTestIsSubset.
    def visitPropTestIsSubset(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("IsSubsetComparisonExpression", children[0], children[3 if len(children) > 3 else 2])

    # Visit a parse tree produced by STIXPatternParser#propTestIsSuperset.
    def visitPropTestIsSuperset(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("IsSupersetComparisonExpression", children[0], children[3 if len(children) > 3 else 2])

    # Visit a parse tree produced by STIXPatternParser#propTestParen.
    def visitPropTestParen(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("ParentheticalExpression", children[1])

    # Visit a parse tree produced by STIXPatternParser#startStopQualifier.
    def visitStartStopQualifier(self, ctx):
        children = self.visitChildren(ctx)
        return StartStopQualifier(children[1], children[3])

    # Visit a parse tree produced by STIXPatternParser#withinQualifier.
    def visitWithinQualifier(self, ctx):
        children = self.visitChildren(ctx)
        return WithinQualifier(children[1])

    # Visit a parse tree produced by STIXPatternParser#repeatedQualifier.
    def visitRepeatedQualifier(self, ctx):
        children = self.visitChildren(ctx)
        return RepeatQualifier(children[1])

    # Visit a parse tree produced by STIXPatternParser#objectPath.
    def visitObjectPath(self, ctx):
        children = self.visitChildren(ctx)
        flat_list = collapse_lists(children[2:])
        property_path = []
        i = 0
        while i < len(flat_list):
            current = flat_list[i]
            if i == len(flat_list)-1:
                property_path.append(current)
                break
            next = flat_list[i+1]
            if isinstance(next, TerminalNode):
                property_path.append(self.instantiate("ListObjectPathComponent", current.property_name, next.getText()))
                i += 2
            else:
                property_path.append(current)
                i += 1
        return self.instantiate("ObjectPath", children[0].getText(), property_path)

    # Visit a parse tree produced by STIXPatternParser#objectType.
    def visitObjectType(self, ctx):
        children = self.visitChildren(ctx)
        return children[0]

    # Visit a parse tree produced by STIXPatternParser#firstPathComponent.
    def visitFirstPathComponent(self, ctx):
        children = self.visitChildren(ctx)
        step = children[0].getText()
        # if step.endswith("_ref"):
        #     return stix2.ReferenceObjectPathComponent(step)
        # else:
        return self.instantiate("BasicObjectPathComponent", step, False)

    # Visit a parse tree produced by STIXPatternParser#indexPathStep.
    def visitIndexPathStep(self, ctx):
        children = self.visitChildren(ctx)
        return children[1]

    # Visit a parse tree produced by STIXPatternParser#pathStep.
    def visitPathStep(self, ctx):
        return collapse_lists(self.visitChildren(ctx))

    # Visit a parse tree produced by STIXPatternParser#keyPathStep.
    def visitKeyPathStep(self, ctx):
        children = self.visitChildren(ctx)
        if isinstance(children[1], StringConstant):
            # special case for hashes
            return children[1].value
        else:
            return self.instantiate("BasicObjectPathComponent", children[1].getText(), True)

    # Visit a parse tree produced by STIXPatternParser#setLiteral.
    def visitSetLiteral(self, ctx):
        children = self.visitChildren(ctx)
        return self.instantiate("ListConstant", remove_terminal_nodes(children))

    # Visit a parse tree produced by STIXPatternParser#primitiveLiteral.
    def visitPrimitiveLiteral(self, ctx):
        children = self.visitChildren(ctx)
        return children[0]

    # Visit a parse tree produced by STIXPatternParser#orderableLiteral.
    def visitOrderableLiteral(self, ctx):
        children = self.visitChildren(ctx)
        return children[0]

    def visitTerminal(self, node):
        if node.symbol.type == STIXPatternParser.IntPosLiteral or node.symbol.type == STIXPatternParser.IntNegLiteral:
            return IntegerConstant(node.getText())
        elif node.symbol.type == STIXPatternParser.FloatPosLiteral or node.symbol.type == STIXPatternParser.FloatNegLiteral:
            return FloatConstant(node.getText())
        elif node.symbol.type == STIXPatternParser.HexLiteral:
            return HexConstant(node.getText(), from_parse_tree=True)
        elif node.symbol.type == STIXPatternParser.BinaryLiteral:
            return BinaryConstant(node.getText(), from_parse_tree=True)
        elif node.symbol.type == STIXPatternParser.StringLiteral:
            return StringConstant(node.getText().strip('\''), from_parse_tree=True)
        elif node.symbol.type == STIXPatternParser.BoolLiteral:
            return BooleanConstant(node.getText())
        elif node.symbol.type == STIXPatternParser.TimestampLiteral:
            return TimestampConstant(node.getText())
        else:
            return node

    def aggregateResult(self, aggregate, nextResult):
        if aggregate:
            aggregate.append(nextResult)
        elif nextResult:
            aggregate = [nextResult]
        return aggregate


def create_pattern_object(pattern, module_suffix="", module_name=""):
    """
    Validates a pattern against the STIX Pattern grammar.  Error messages are
    returned in a list.  The test passed if the returned list is empty.
    """

    start = ''
    if isinstance(pattern, six.string_types):
        start = pattern[:2]
        pattern = InputStream(pattern)

    if not start:
        start = pattern.readline()[:2]
        pattern.seek(0)

    parseErrListener = STIXPatternErrorListener()

    lexer = STIXPatternLexer(pattern)
    # it always adds a console listener by default... remove it.
    lexer.removeErrorListeners()

    stream = CommonTokenStream(lexer)

    parser = STIXPatternParser(stream)
    parser.buildParseTrees = True
    # it always adds a console listener by default... remove it.
    parser.removeErrorListeners()
    parser.addErrorListener(parseErrListener)

    # To improve error messages, replace "<INVALID>" in the literal
    # names with symbolic names.  This is a hack, but seemed like
    # the simplest workaround.
    for i, lit_name in enumerate(parser.literalNames):
        if lit_name == u"<INVALID>":
            parser.literalNames[i] = parser.symbolicNames[i]

    tree = parser.pattern()
    builder = STIXPatternVisitorForSTIX2(module_suffix, module_name)
    return builder.visit(tree)
