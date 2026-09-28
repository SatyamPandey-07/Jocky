"""Tokenizer for JOCKY source."""
from __future__ import annotations

from dataclasses import dataclass

from ..errors import CompileError, Diagnostic, Span

DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

SYMBOLS = [
    "->", "==", "!=", "<=", ">=",
    "{", "}", "[", "]", "(", ")", ",", "|", "=", "<", ">", ".",
]


@dataclass(frozen=True)
class Token:
    kind: str  # IDENT STRING INT DURATION SYM EOF
    text: str
    value: object
    span: Span

    def is_word(self, *words: str) -> bool:
        return self.kind == "IDENT" and self.text in words

    def is_sym(self, *syms: str) -> bool:
        return self.kind == "SYM" and self.text in syms


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    i, line, col = 0, 1, 1
    n = len(source)

    def err(msg: str, l: int, c: int, hint: str | None = None) -> CompileError:
        return CompileError([Diagnostic("error", "E0001", msg, Span(l, c, l, c + 1), hint)])

    while i < n:
        ch = source[i]
        if ch == "\n":
            i += 1
            line += 1
            col = 1
            continue
        if ch in " \t\r":
            i += 1
            col += 1
            continue
        if ch == "#" or source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        start_line, start_col = line, col
        if ch == '"':
            i += 1
            col += 1
            buf: list[str] = []
            while True:
                if i >= n or source[i] == "\n":
                    raise err("unterminated string literal", start_line, start_col,
                              'close the string with a matching "')
                c = source[i]
                if c == '"':
                    i += 1
                    col += 1
                    break
                if c == "\\":
                    if i + 1 >= n:
                        raise err("unterminated escape sequence", line, col)
                    esc = source[i + 1]
                    mapped = {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(esc)
                    if mapped is None:
                        raise err(f"unknown escape sequence \\{esc}", line, col,
                                  'supported escapes: \\n \\t \\" \\\\')
                    buf.append(mapped)
                    i += 2
                    col += 2
                    continue
                buf.append(c)
                i += 1
                col += 1
            text = "".join(buf)
            tokens.append(Token("STRING", text, text, Span(start_line, start_col, line, col)))
            continue
        if ch.isdigit():
            j = i
            while j < n and source[j].isdigit():
                j += 1
            k = j
            while k < n and (source[k].isalpha() or source[k] == "_"):
                k += 1
            digits = source[i:j]
            suffix = source[j:k]
            if suffix:
                if suffix not in DURATION_UNITS:
                    raise err(f"invalid duration unit '{suffix}' in '{digits}{suffix}'",
                              start_line, start_col, "use one of: s, m, h, d (e.g. 20m, 24h)")
                seconds = int(digits) * DURATION_UNITS[suffix]
                text = digits + suffix
                tokens.append(Token("DURATION", text, seconds,
                                    Span(start_line, start_col, line, col + (k - i))))
            else:
                tokens.append(Token("INT", digits, int(digits),
                                    Span(start_line, start_col, line, col + (j - i))))
            col += k - i
            i = k
            continue
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            text = source[i:j]
            tokens.append(Token("IDENT", text, text, Span(start_line, start_col, line, col + (j - i))))
            col += j - i
            i = j
            continue
        for sym in SYMBOLS:
            if source.startswith(sym, i):
                tokens.append(Token("SYM", sym, sym, Span(line, col, line, col + len(sym))))
                i += len(sym)
                col += len(sym)
                break
        else:
            raise err(f"unexpected character {ch!r}", line, col)
    tokens.append(Token("EOF", "", None, Span(line, col, line, col)))
    return tokens
