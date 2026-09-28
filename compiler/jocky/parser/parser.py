"""Recursive-descent parser: JOCKY source -> AST.

Grammar (EBNF)::

    program     = "investigation" IDENT "{" { item } "}" EOF ;
    item        = "title" STRING
                | "targets" "[" STRING { "," STRING } [ "," ] "]"
                | "window" ( "last" DURATION | "from" STRING "to" STRING )
                | "let" IDENT "=" pipeline
                | "preserve" IDENT [ "with" "content" ]
                | "emit" "finding" IDENT [ "as" STRING ] [ "severity" LEVEL ] ;
    pipeline    = source { "|" stage } ;
    source      = "observe" ENTITY
                | "join" IDENT "," IDENT "on" keys [ "within" DURATION ]
                | "sequence" IDENT "->" IDENT { "->" IDENT } "on" keys "within" DURATION
                | IDENT ;
    stage       = "filter" expr | "select" field { "," field } | "within" DURATION ;
    keys        = field { "," field } ;
    expr        = and_expr { "or" and_expr } ;
    and_expr    = not_expr { "and" not_expr } ;
    not_expr    = "not" not_expr | "(" expr ")" | predicate ;
    predicate   = field ( CMP literal
                        | ( "contains" | "startswith" | "endswith" | "like" ) STRING
                        | [ "not" ] "in" ( list | "cidr" "(" STRING ")" ) ) ;
    field       = IDENT { "." IDENT } ;
    literal     = STRING | INT | "true" | "false" | "null" ;

Syntax errors are recovered at statement boundaries so that one run reports
every malformed statement.
"""
from __future__ import annotations

from ..ast import nodes as A
from ..errors import CompileError, Diagnostic, Span
from .lexer import Token, tokenize

ITEM_KEYWORDS = ("title", "targets", "window", "let", "preserve", "emit")
CMP_OPS = ("==", "!=", "<", "<=", ">", ">=")
STR_OPS = ("contains", "startswith", "endswith", "like")
SEVERITIES = ("info", "low", "medium", "high", "critical")
RESERVED = {
    "and", "or", "not", "in", "true", "false", "null",
    "investigation", "title", "targets", "window", "let", "preserve", "emit",
    "observe", "join", "sequence", "filter", "select", "within", "on", "finding",
}


class _SyntaxError(Exception):
    def __init__(self, diag: Diagnostic):
        self.diag = diag


class Parser:
    def __init__(self, source: str):
        self.source = source
        self.tokens = tokenize(source)
        self.pos = 0
        self.diagnostics: list[Diagnostic] = []

    # ---- token helpers -------------------------------------------------------
    @property
    def tok(self) -> Token:
        return self.tokens[self.pos]

    def peek(self, offset: int = 1) -> Token:
        return self.tokens[min(self.pos + offset, len(self.tokens) - 1)]

    def advance(self) -> Token:
        t = self.tokens[self.pos]
        if t.kind != "EOF":
            self.pos += 1
        return t

    def _describe(self, t: Token) -> str:
        if t.kind == "EOF":
            return "end of input"
        if t.kind == "STRING":
            return f'string "{t.text}"'
        return f"'{t.text}'"

    def fail(self, expected: str, hint: str | None = None, tok: Token | None = None) -> _SyntaxError:
        t = tok or self.tok
        return _SyntaxError(Diagnostic("error", "E0100", f"expected {expected}, found {self._describe(t)}",
                                       t.span, hint))

    def expect_word(self, word: str, hint: str | None = None) -> Token:
        if not self.tok.is_word(word):
            raise self.fail(f"'{word}'", hint)
        return self.advance()

    def expect_sym(self, sym: str, hint: str | None = None) -> Token:
        if not self.tok.is_sym(sym):
            raise self.fail(f"'{sym}'", hint)
        return self.advance()

    def expect_ident(self, what: str = "an identifier", hint: str | None = None) -> Token:
        if self.tok.kind != "IDENT" or self.tok.text in RESERVED:
            raise self.fail(what, hint)
        return self.advance()

    def expect_kind(self, kind: str, what: str, hint: str | None = None) -> Token:
        if self.tok.kind != kind:
            raise self.fail(what, hint)
        return self.advance()

    # ---- program -------------------------------------------------------------
    def parse(self) -> A.Investigation:
        try:
            start = self.expect_word("investigation", "a JOCKY file starts with `investigation <name> {`")
            name = self.expect_ident("investigation name")
            self.expect_sym("{")
        except _SyntaxError as e:
            raise CompileError([e.diag])
        inv = A.Investigation(name=name.text, title=None, targets=None, window=None, statements=[])
        while not self.tok.is_sym("}") and self.tok.kind != "EOF":
            start_pos = self.pos
            try:
                self.parse_item(inv)
            except _SyntaxError as e:
                self.diagnostics.append(e.diag)
                self.recover(start_pos)
        end = self.tok
        if not self.tok.is_sym("}"):
            self.diagnostics.append(self.fail("'}' closing the investigation").diag)
        else:
            self.advance()
            if self.tok.kind != "EOF":
                self.diagnostics.append(self.fail("end of input", "only one investigation per file").diag)
        inv.span = Span.join(start.span, end.span)
        if self.diagnostics:
            raise CompileError(self.diagnostics)
        return inv

    def recover(self, start_pos: int) -> None:
        """Skip to the next token that can start a statement."""
        if self.pos == start_pos:
            self.advance()
        while self.tok.kind != "EOF" and not self.tok.is_sym("}"):
            if self.tok.kind == "IDENT" and self.tok.text in ITEM_KEYWORDS:
                if not self.tokens[self.pos - 1].is_sym("|", "."):
                    return
            self.advance()

    def parse_item(self, inv: A.Investigation) -> None:
        t = self.tok
        if t.is_word("title"):
            self.advance()
            s = self.expect_kind("STRING", "a quoted title", 'e.g. title "PowerShell dropper"')
            inv.title = s.value
        elif t.is_word("targets"):
            self.advance()
            self.expect_sym("[", 'targets are a list, e.g. targets ["WIN-01", "UBUNTU-01"]')
            items = [self.expect_kind("STRING", "a quoted target id").value]
            while self.tok.is_sym(","):
                self.advance()
                if self.tok.is_sym("]"):
                    break
                items.append(self.expect_kind("STRING", "a quoted target id").value)
            self.expect_sym("]")
            inv.targets = items
        elif t.is_word("window"):
            self.advance()
            if self.tok.is_word("last"):
                self.advance()
                d = self.parse_duration("a duration after 'last'")
                inv.window = A.Window("last", d, None, None, Span.join(t.span, d.span))
            elif self.tok.is_word("from"):
                self.advance()
                s = self.expect_kind("STRING", "a start timestamp", 'e.g. window from "2026-09-20T00:00:00Z" to "..."')
                self.expect_word("to")
                e = self.expect_kind("STRING", "an end timestamp")
                inv.window = A.Window("range", None, s.value, e.value, Span.join(t.span, e.span))
            else:
                raise self.fail("'last' or 'from'", "e.g. window last 24h")
        elif t.is_word("let"):
            inv.statements.append(self.parse_let())
        elif t.is_word("preserve"):
            self.advance()
            target = self.parse_ref("binding to preserve")
            with_content = False
            end = target.span
            if self.tok.is_word("with"):
                self.advance()
                end = self.expect_word("content", "only `preserve <binding> with content` is supported").span
                with_content = True
            inv.statements.append(A.Preserve(target, with_content, Span.join(t.span, end)))
        elif t.is_word("emit"):
            self.advance()
            self.expect_word("finding", "e.g. emit finding chain severity high")
            target = self.parse_ref("binding to emit")
            title, severity, end = None, "medium", target.span
            while self.tok.is_word("as", "severity"):
                if self.tok.is_word("as"):
                    self.advance()
                    s = self.expect_kind("STRING", "a quoted finding title")
                    title, end = s.value, s.span
                else:
                    self.advance()
                    lvl = self.expect_ident("a severity level", "one of: " + ", ".join(SEVERITIES))
                    if lvl.text not in SEVERITIES:
                        raise _SyntaxError(Diagnostic("error", "E0101", f"unknown severity '{lvl.text}'",
                                                      lvl.span, "one of: " + ", ".join(SEVERITIES)))
                    severity, end = lvl.text, lvl.span
            inv.statements.append(A.Emit(target, severity, title, Span.join(t.span, end)))
        else:
            raise self.fail("a statement (" + ", ".join(ITEM_KEYWORDS) + ")")

    def parse_let(self) -> A.Let:
        start = self.advance()
        name = self.expect_ident("a binding name after 'let'")
        self.expect_sym("=", "e.g. let shells = observe Process")
        pipe = self.parse_pipeline()
        return A.Let(name.text, pipe, Span.join(start.span, pipe.span), name.span)

    def parse_ref(self, what: str) -> A.Ref:
        t = self.expect_ident(what)
        return A.Ref(t.text, t.span)

    def parse_duration(self, what: str) -> A.Duration:
        t = self.expect_kind("DURATION", what, "durations look like 30s, 20m, 24h, 7d")
        return A.Duration(t.text, t.value, t.span)

    def parse_pipeline(self) -> A.Pipeline:
        source = self.parse_source()
        stages: list = []
        end = source.span
        while self.tok.is_sym("|"):
            self.advance()
            st = self.parse_stage()
            stages.append(st)
            end = st.span
        return A.Pipeline(source, stages, Span.join(source.span, end))

    def parse_keys(self) -> list[A.FieldRef]:
        keys = [self.parse_field()]
        while self.tok.is_sym(","):
            self.advance()
            keys.append(self.parse_field())
        return keys

    def parse_source(self):
        t = self.tok
        if t.is_word("observe"):
            self.advance()
            ent = self.expect_ident("an entity type", "entities: Process, File, NetworkConnection, User, Event")
            return A.Observe(ent.text, Span.join(t.span, ent.span))
        if t.is_word("join"):
            self.advance()
            left = self.parse_ref("left join input")
            self.expect_sym(",", "e.g. join shells, drops on host, pid within 20m")
            right = self.parse_ref("right join input")
            self.expect_word("on", "join needs keys, e.g. `on host, pid`")
            keys = self.parse_keys()
            within = None
            end = keys[-1].span
            if self.tok.is_word("within"):
                self.advance()
                within = self.parse_duration("a duration after 'within'")
                end = within.span
            return A.Join(left, right, keys, within, Span.join(t.span, end))
        if t.is_word("sequence"):
            self.advance()
            steps = [self.parse_ref("first sequence step")]
            if not self.tok.is_sym("->"):
                raise self.fail("'->'", "a sequence needs at least two steps, e.g. sequence a -> b on host, pid within 20m")
            while self.tok.is_sym("->"):
                self.advance()
                steps.append(self.parse_ref("next sequence step"))
            self.expect_word("on", "sequence needs keys, e.g. `on host, pid`")
            keys = self.parse_keys()
            if not self.tok.is_word("within"):
                raise self.fail("'within'", "a sequence must be bounded in time, e.g. `within 20m`")
            self.advance()
            within = self.parse_duration("a duration after 'within'")
            return A.Sequence(steps, keys, within, Span.join(t.span, within.span))
        if t.kind == "IDENT" and t.text not in RESERVED and t.text not in ITEM_KEYWORDS:
            self.advance()
            return A.Ref(t.text, t.span)
        raise self.fail("'observe', 'join', 'sequence' or a binding name")

    def parse_stage(self):
        t = self.tok
        if t.is_word("filter"):
            self.advance()
            e = self.parse_expr()
            return A.Filter(e, Span.join(t.span, e.span))
        if t.is_word("select"):
            self.advance()
            flds = self.parse_keys()
            return A.Select(flds, Span.join(t.span, flds[-1].span))
        if t.is_word("within"):
            self.advance()
            d = self.parse_duration("a duration after 'within'")
            return A.Within(d, Span.join(t.span, d.span))
        raise self.fail("a pipeline stage ('filter', 'select' or 'within')")

    # ---- expressions ---------------------------------------------------------
    def parse_expr(self):
        left = self.parse_and()
        if not self.tok.is_word("or"):
            return left
        args = [left]
        while self.tok.is_word("or"):
            self.advance()
            args.append(self.parse_and())
        return A.BoolOp("or", args, Span.join(args[0].span, args[-1].span))

    def parse_and(self):
        left = self.parse_not()
        if not self.tok.is_word("and"):
            return left
        args = [left]
        while self.tok.is_word("and"):
            self.advance()
            args.append(self.parse_not())
        return A.BoolOp("and", args, Span.join(args[0].span, args[-1].span))

    def parse_not(self):
        t = self.tok
        if t.is_word("not"):
            self.advance()
            inner = self.parse_not()
            return A.Not(inner, Span.join(t.span, inner.span))
        if t.is_sym("("):
            self.advance()
            e = self.parse_expr()
            self.expect_sym(")")
            return e
        return self.parse_predicate()

    def parse_field(self) -> A.FieldRef:
        first = self.expect_ident("a field name")
        parts, end = [first.text], first.span
        while self.tok.is_sym("."):
            self.advance()
            nxt = self.expect_ident("a field name after '.'")
            parts.append(nxt.text)
            end = nxt.span
        return A.FieldRef(parts, Span.join(first.span, end))

    def parse_literal(self) -> A.Literal:
        t = self.tok
        if t.kind == "STRING":
            self.advance()
            return A.Literal(t.value, "str", t.span)
        if t.kind == "INT":
            self.advance()
            return A.Literal(t.value, "int", t.span)
        if t.is_word("true", "false"):
            self.advance()
            return A.Literal(t.text == "true", "bool", t.span)
        if t.is_word("null"):
            self.advance()
            return A.Literal(None, "null", t.span)
        raise self.fail("a literal (string, integer, true, false or null)")

    def parse_predicate(self):
        fld = self.parse_field()
        t = self.tok
        if t.kind == "SYM" and t.text in CMP_OPS:
            self.advance()
            lit = self.parse_literal()
            return A.Compare(fld, t.text, lit, Span.join(fld.span, lit.span))
        if t.kind == "SYM" and t.text == "=":
            raise self.fail("a comparison operator", "use '==' for equality", t)
        if t.is_word(*STR_OPS):
            self.advance()
            s = self.expect_kind("STRING", f"a quoted pattern after '{t.text}'")
            return A.Compare(fld, t.text, A.Literal(s.value, "str", s.span), Span.join(fld.span, s.span))
        negated = False
        if t.is_word("not"):
            self.advance()
            negated = True
            if not self.tok.is_word("in"):
                raise self.fail("'in' after 'not'")
        if self.tok.is_word("in"):
            self.advance()
            if self.tok.is_word("cidr"):
                self.advance()
                self.expect_sym("(")
                c = self.expect_kind("STRING", 'a CIDR string, e.g. cidr("10.0.0.0/8")')
                close = self.expect_sym(")")
                node = A.InCidr(fld, A.Literal(c.value, "str", c.span), Span.join(fld.span, close.span))
            else:
                self.expect_sym("[", 'e.g. name in ["powershell.exe", "pwsh"]')
                values = [self.parse_literal()]
                while self.tok.is_sym(","):
                    self.advance()
                    if self.tok.is_sym("]"):
                        break
                    values.append(self.parse_literal())
                close = self.expect_sym("]")
                node = A.InList(fld, values, Span.join(fld.span, close.span))
            return A.Not(node, node.span) if negated else node
        raise self.fail("an operator (==, !=, <, <=, >, >=, in, not in, contains, startswith, endswith, like)")


def parse(source: str) -> A.Investigation:
    return Parser(source).parse()
