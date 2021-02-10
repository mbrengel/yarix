#!/usr/bin/env python3

import ast
import re
import subprocess
import sys
import malindex

import networkx as nx
from sympy import Symbol
from sympy.logic.boolalg import And, Or, Not, to_cnf, to_dnf
import yara
import yaramod
import timeout_decorator


class FormulaBuilder(yaramod.ObservingVisitor):
    def __init__(self):
        super().__init__()
        self.ret = []
        self.symcnt = 0
        self.symmapping = {}

    def newsym(self, expr):
        self.symcnt += 1
        self.symmapping[self.symcnt-1] = expr
        return "x{}".format(self.symcnt-1)

    def visit_StringExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_StringWildcardExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_StringAtExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_StringInRangeExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_StringCountExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_StringOffsetExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_StringLengthExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_NotExpression(self, expr):
        self.ret.append("~")
        expr.operand.accept(self)

    def visit_UnaryMinusExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.operand.accept(self)

    def visit_BitwiseNotExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.operand.accept(self)

    def visit_AndExpression(self, expr):
        expr.left_operand.accept(self)
        self.ret.append(" & ")
        expr.right_operand.accept(self)

    def visit_OrExpression(self, expr):
        expr.left_operand.accept(self)
        self.ret.append(" | ")
        expr.right_operand.accept(self)

    def visit_LtExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_GtExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_LeExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_GeExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_EqExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_NeqExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_ContainsExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_MatchesExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_PlusExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_MinusExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_MultiplyExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_DivideExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ModuloExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseXorExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseAndExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_BitwiseOrExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ShiftLeftExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ShiftRightExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.left_operand.accept(self)
        expr.right_operand.accept(self)

    def visit_ForIntExpression(self, expr):
        expr.body.accept(self)
        #self.ret.append(self.newsym(expr))

    def visit_ForStringExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_OfExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_SetExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_RangeExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        self.low.accept(self)
        self.high.accept(self)

    def visit_IdExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_StructAccessExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.structure.accept(self)

    def visit_ArrayAccessExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.array.accept(self)
        expr.accessor.accept(self)

    def visit_FunctionCallExpression(self, expr):
        self.ret.append(self.newsym(expr))

    def visit_BoolLiteralExpression(self, expr):
        if expr.text == "true":
            self.ret.append("True")
        else:
            self.ret.append("False")

    def visit_StringLiteralExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_IntLiteralExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_DoubleLiteralExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_FilesizeExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_EntrypointExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_AllExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_AnyExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_ThemExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))

    def visit_ParenthesesExpression(self, expr):
        self.ret.append("(")
        expr.enclosed_expr.accept(self)
        self.ret.append(")")

    def visit_IntFunctionExpression(self, expr):
        # should never be visited
        raise Exception("implement for {}".format(type(expr)))
        expr.argument.accept(self)

    def visit_RegexpExpression(self, expr):
        self.ret.append(self.newsym(expr))


class YaraString():
    def __init__(self, s, is_regex, is_hex, is_wide, is_ascii, is_nocase):
        self.s = s
        self.is_regex = is_regex
        self.is_hex = is_hex
        self.is_wide = is_wide
        self.is_ascii = is_ascii
        self.is_nocase = is_nocase
    
    def __str__(self):
        return self.s.__str__()


class Formulae():
    def __init__(self, formulae):
        def parse_cnfdnf(f, t):
            if t == "cnf":
                t = (And, Or)
            elif t == "dnf":
                t = (Or, And)
            if not isinstance(f, t[0]):
                if isinstance(f, Symbol):
                    return [(f,)]
                else:
                    return [tuple(f.args)]
            ret = []
            for a in f.args:
                if not isinstance(a, t[1]):
                    ret.append((a,))
                else:
                    ret.append(tuple(a.args))
            return ret
        self.formulae = formulae
        self.cnf = to_cnf(formulae, simplify=False)
        self.cnf_parsed = parse_cnfdnf(self.cnf, "cnf")
        self.dnf = to_dnf(formulae, simplify=False)
        self.dnf_parsed = parse_cnfdnf(self.dnf, "dnf")


def condition2formula(condition):
    builder = FormulaBuilder()
    builder.observe(condition)
    for i in range(builder.symcnt):
        exec("{0}=Symbol(\"{0}\")".format("x" + str(i)))
    formula = eval("".join(builder.ret))
    return Formulae(formula), builder.symmapping


def get_fixed_strings(r):
    # convert regex to graph
    G = nx.MultiDiGraph()
    cmd = ["./src/tools/util/regex2dfa", "-r", r]
    s = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.decode("utf-8")
    end = None
    for l in s.splitlines():
        items = l.split("\t")
        if len(items) == 4:
            a, b, i, o = map(int, items)
            G.add_edge(a, b, label=(i).to_bytes(length=1, byteorder="big"))
        else:
            assert len(items) == 1
            end = int(items[0])
            break
    assert end is not None

    # convenciente function
    def get_edges(u):
        ret = []
        for v in G[u]:
            for i in G[u][v]:
                ret.append((u, v, G[u][v][i]["label"]))
        return ret

    # get relevant nodes
    start = 0
    dom = nx.immediate_dominators(G, start)
    relevant = [end]
    node = end
    while node != start:
        node = dom[node]
        relevant.append(node)
    relevant = relevant[::-1]

    # get fixed strings starting from relevant nodes
    # idea: check if a node has only one edge, collect the label and continue
    # until a branch is discovered
    strs = {}
    seen = set()
    for node in relevant:
        strs[node] = []
        edges = get_edges(node)
        while len(edges) == 1:
            u, v, l = edges[0]
            if u in seen or u == end:
                break
            seen.add(u)
            strs[node].append(l)
            edges = get_edges(v)
    return list(set([b"".join(l) for l in sorted(strs.values(), key=len, reverse=True) if len(l) > 0]))


def get_hex_streaks(hexstring):
    depth = [0, 0]
    streaks, currstreak, currb = [], bytearray(), bytearray()
    for c in hexstring:
        c = chr(c).upper().encode()
        if c == b" ":
            continue
        elif c in b"0123456789ABCDEF":
            if depth == [0, 0]:
                currb.append(int(c, 16))
                if len(currb) == 2:
                    currstreak.append(currb[0] << 4 | currb[1])
                    currb = bytearray()
        elif c in b"[]()?-|":
            currb = bytearray()
            if len(currstreak) > 0:
                streaks.append(currstreak)
                currstreak = bytearray()
            if c == b"(":
                depth[0] += 1
            elif c == b")":
                depth[0] -= 1
            elif c == b"[":
                depth[1] += 1
            elif c == b"]":
                depth[1] -= 1
        else:
            raise Exception("unknown character: {}".format(c))
    if len(currstreak) > 0:
        streaks.append(currstreak)
    return set(map(bytes, streaks))


def stringmap(rule, identifier, cache={}):
    if rule not in cache:
        cache[rule] = {}
        for s in rule.strings:
            cache[rule][s.identifier[1:]] = YaraString(s.pure_text, s.is_regexp, s.is_hex, s.is_wide, s.is_ascii, s.is_nocase)
    return cache[rule][identifier[1:]]


def simplify_expression_(rule, expr, containsexpr=False):
    nonrecursive = [
        yaramod.StringExpression, yaramod.StringAtExpression, yaramod.StringCountExpression,
        yaramod.StringOffsetExpression, yaramod.StringInRangeExpression
    ]

    binary_recursive = [
        yaramod.LtExpression, yaramod.LeExpression, yaramod.EqExpression,
        yaramod.GeExpression, yaramod.GtExpression, yaramod.MinusExpression
    ]

    undoable = [
        yaramod.IntLiteralExpression, yaramod.IntFunctionExpression, yaramod.FunctionCallExpression,
        yaramod.FilesizeExpression, yaramod.StructAccessExpression, yaramod.ForIntExpression
    ]

    texpr = type(expr)
    if texpr == yaramod.EqExpression:
        tlexpr = type(expr.left_operand)
        trexpr = type(expr.right_operand)
        if tlexpr == yaramod.StructAccessExpression and trexpr in (yaramod.IntLiteralExpression, yaramod.StructAccessExpression):
            fieldsz = {
                "pe.machine": 2,
                "pe.number_of_sections": 2,
            }
            if expr.left_operand.text in fieldsz.keys():
                fieldsz = fieldsz[expr.left_operand.text]
                if trexpr == yaramod.StructAccessExpression:
                    fieldval = {
                        "pe.MACHINE_I386": 0x14c
                    }[expr.right_operand.text]
                    fieldval = YaraString(fieldval.to_bytes(fieldsz, "little"), False, False, False, True, False)
                    return (1, [fieldval])
                elif trexpr == yaramod.IntLiteralExpression:
                    return (1, [YaraString(ast.literal_eval(expr.right_operand.value).to_bytes(fieldsz, "little"), False, False, False, True, False)])
    elif texpr == yaramod.FunctionCallExpression:
        f = expr.function
        if expr.function.text == "pe.exports":
            return (1, [YaraString(expr.arguments[0].value.encode(), False, False, False, True, False)])
    if texpr in nonrecursive:
        return (1, [stringmap(rule, expr.id)])
    elif texpr in binary_recursive:
        l, r = expr.left_operand, expr.right_operand
        (nl, l), (nr, r) = simplify_expression_(rule, l), simplify_expression_(rule, r)
        return (nl + nr, l + r)
    elif texpr in undoable:
        return (0, [])
    elif texpr == yaramod.StringLiteralExpression:
        if containsexpr:
            return (1, [YaraString(expr.value.encode(), False, False, True, True, True)])
        else:
            return (0, [])
    elif texpr == yaramod.StringWildcardExpression:
        ret = []
        regex = expr.id.replace("*", ".*").replace("$", "\\$")
        for s in rule.strings:
            if re.match(regex, s.identifier):
                ret.append(stringmap(rule, s.identifier))
        return (len(ret), ret)
    elif texpr == yaramod.SetExpression:
        ret = list(set.union(*[set(simplify_expression_(rule, e)[1]) for e in expr.elements]))
        return (len(ret), ret)
    elif texpr == yaramod.ThemExpression:
        return (len(rule.strings), [YaraString(s.pure_text, s.is_regexp, s.is_hex, s.is_wide, s.is_ascii, s.is_nocase) for s in rule.strings])
    elif texpr == yaramod.OfExpression:
        v, s = expr.variable, expr.iterated_set
        tv, ts = type(v), type(s)
        _, ids = simplify_expression_(rule, s)
        if tv == yaramod.IntLiteralExpression:
            n = int(v.value)
        elif tv == yaramod.AllExpression:
            n = len(ids)
        elif tv == yaramod.AnyExpression:
            n = 1
        else:
            raise Exception()
        return (n, ids)
    elif texpr == yaramod.ContainsExpression:
        return simplify_expression_(rule, expr.right_operand, containsexpr=True)

    raise Exception("Unknown {} {}".format(expr.text, type(expr)))


def mkwide(s):
    ret = bytearray()
    for c in s:
        ret.append(c)
        ret.append(0)
    return bytes(ret)


def simplify_expression(rule, expr, lowerbound=4):
    i, l = simplify_expression_(rule, expr)
    l2 = []
    isnocase = set()
    for s in l:
        if s.is_regex:
            foo = list(set(get_fixed_strings(s.s)))
            if s.is_ascii:
                l2.append(foo)
                if s.is_nocase:
                    isnocase.add(tuple(foo))
            if s.is_wide:
                l2.append([mkwide(x) for x in foo])
                if s.is_nocase:
                    isnocase.add(tuple([mkwide(x) for x in foo]))
        elif s.is_hex:
            foo = list(set(get_hex_streaks(s.s)))
            if s.is_ascii:
                l2.append(foo)
                if s.is_nocase:
                    isnocase.add(tuple(foo))
            if s.is_wide:
                l2.append([mkwide(x) for x in foo])
                if s.is_nocase:
                    isnocase.add(tuple([mkwide(x) for x in foo]))
        else:
            if s.is_wide:
                l2.append([mkwide(s.s)])
                if s.is_nocase:
                    isnocase.add(tuple([mkwide(s.s)]))
            if s.is_ascii:
                l2.append([s.s])
                if s.is_nocase:
                    isnocase.add(tuple([s.s]))
    l3 = [[x for x in sl if len(x) >= lowerbound] for sl in l2]
    l3 = list(sl for sl in l3 if len(sl) > 0)
    i = max(0, i - (len(l2) - len(l3)))
    assert i <= len(l3)
    return i, l3, isnocase


@timeout_decorator.timeout(240)
def evaluate_rule(rule, index, lowerbound=4, groupwidth=None, tau=None):
    f, mapping = condition2formula(rule.condition)
    xvals = {str(x) for clause in f.cnf_parsed for x in clause}
    exprres = {}
    cache = {}
    for i in mapping:
        n, l, isnocase = simplify_expression(rule, mapping[i], lowerbound=lowerbound)
        if "~x{}".format(i) in xvals:
            n = 0
        if n == 0:
            exprres[i] = None
        else:
            cnt = {}
            exprres[i] = set()
            for sl in l:
                sl = tuple(sl)
                if sl not in cache:
                    if sl in isnocase:
                        a = max(sl, key=len).lower()
                        localgrams = {a[i:i+lowerbound] for i in range(len(a) - lowerbound + 1)}
                        cache[sl] = set()
                        for x in localgrams:
                            seen = set()
                            for tmpidx in range(16 if lowerbound == 4 else 8):
                                x2 = bytes((x[hanbo] - 32 if x[hanbo] !=  0 else x[hanbo]) if tmpidx & (1 << hanbo) else x[hanbo] for hanbo in range(lowerbound))
                                if x2 in seen:
                                    continue
                                seen.add(x2)
                                if lowerbound == 4:
                                    cache[sl] |= index.get_posting_list(x2, groupwidth=groupwidth, tau=tau)
                                else:
                                    assert lowerbound == 3
                                    cache[sl] |= index.get_posting_list_n3(x2)
                    else:
                        cache[sl] = None
                        for a in sl:
                            if cache[sl] is not None and len(cache[sl]) == 0:
                                break
                            localgrams = {a[i:i+lowerbound] for i in range(len(a) - lowerbound + 1)}
                            if lowerbound == 4:
                                if cache[sl] is None:
                                    cache[sl] = index.get_posting_list(localgrams, groupwidth=groupwidth, tau=tau)
                                else:
                                    cache[sl] &= index.get_posting_list(localgrams, groupwidth=groupwidth, tau=tau)
                            else:
                                assert lowerbound == 3
                                if cache[sl] is None:
                                    cache[sl] = index.get_posting_list_n3(localgrams)
                                else:
                                    cache[sl] &= index.get_posting_list_n3(localgrams)
                for fid in cache[sl]:
                    if fid not in cnt:
                        cnt[fid] = 1
                    else:
                        cnt[fid] += 1
                    if cnt[fid] == n:
                        exprres[i].add(fid)
    dnflen = sum(len(x) for x in f.dnf_parsed)
    cnflen = sum(len(x) for x in f.cnf_parsed)
    if dnflen < cnflen:
        ret = set()
        for clause in f.dnf_parsed:
            curr = None
            for i in [int(str(x)[2+str(x).find("~"):]) for x in clause]:
                # intersection
                if exprres[i] is not None:
                    if curr is None:
                        curr = set(exprres[i])
                    else:
                        curr &= exprres[i]
            # union
            if curr is None:
                return None
            else:
                ret |= curr
    else:
        ret = None
        for clause in f.cnf_parsed:
            curr = set()
            for i in [int(str(x)[2+str(x).find("~"):]) for x in clause]:
                # union
                if exprres[i] is None:
                    curr = None
                    break
                else:
                    curr |= exprres[i]
            # intersection
            if curr is not None:
                if ret is None:
                    ret = set(curr)
                else:
                    ret &= curr
    return ret

def seqyarascan(paths, rule):
    rule = yara.compile(source="import \"pe\"\nimport \"elf\"\n" + rule.text)
    for p in paths:
        if rule.match(p):
            yield p
