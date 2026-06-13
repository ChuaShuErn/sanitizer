#!/usr/bin/env python3
"""sanitize_ddl.py — strip company IP from PostgreSQL / Oracle DDL.

Replaces every business-meaningful identifier (schemas, tables, columns, indexes,
constraints, sequences, views, functions, triggers, types, enum values, partitions,
tablespaces, roles, domains) with deterministic generic placeholders, strips comments
and string-literal defaults, and guts function / procedure bodies — while preserving the
structural skeleton (data types, NULL/NOT NULL, key/constraint *types*, FK relationships,
index methods, partitioning, etc.) so the sanitized DDL stays valid, re-executable SQL.

Parsing is done with sqlglot; a segment-aware regex/tokenizer fallback handles statements
sqlglot can only parse as an opaque ``Command`` (Oracle TABLESPACE/STORAGE/partition-def
tables, PG DOMAIN, PL/SQL blocks, …) and anything that raises ``ParseError``.

Usage:
    python sanitize_ddl.py input.sql -o sanitized.sql -m mapping.json
    python sanitize_ddl.py ./ddl_dir/ -o ./out_dir/ -m mapping.json     # batch
    cat schema.sql | python sanitize_ddl.py - -o sanitized.sql -m mapping.json
    python sanitize_ddl.py input.sql --dialect oracle -o out.sql -m mapping.json
    python sanitize_ddl.py new.sql --use-mapping mapping.json -o out.sql -m mapping2.json
    python sanitize_ddl.py --demo
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

try:
    import sqlglot
    from sqlglot import exp
    from sqlglot.errors import ParseError
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: sqlglot is required. Install it with:  pip install sqlglot\n"
    )
    raise

# sqlglot logs a warning for every statement it falls back to Command on; we handle
# those deliberately via the fallback path, so silence the noise.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

DIALECTS = ("postgres", "oracle")
BODY_PLACEHOLDER = "/* sanitized — logic removed */"

# ---------------------------------------------------------------------------
# Category / placeholder configuration
# ---------------------------------------------------------------------------
# Ordered so the mapping.json reads naturally; every category is its own namespace.
PREFIX = {
    "schemas": "schema",
    "tables": "table",
    "columns": "col",
    "indexes": "idx",
    "constraints": "cstr",
    "sequences": "seq",
    "views": "view",
    "materialized_views": "mview",
    "functions": "func",
    "triggers": "trig",
    "types": "type",
    "domains": "domain",
    "enum_values": "val",
    "string_defaults": "default_val",
    "partitions": "part",
    "tablespaces": "tspace",
    "roles": "role",
    "ctes": "cte",
}
CATEGORIES = tuple(PREFIX)

# Placeholders look like ``table_001`` / ``default_val_007``. Used by the leak scanner.
PLACEHOLDER_RE = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in PREFIX.values()) + r")_\d{3,}$",
    re.IGNORECASE,
)

# Roles / grantees that are never IP.
SAFE_ROLES = {"PUBLIC", "CURRENT_USER", "SESSION_USER", "CURRENT_ROLE"}

# String literals that are structural / functional, not business data.
SAFE_LITERALS = {
    "plpgsql", "sql", "plperl", "plpython3u", "c", "internal",
    "t", "f", "true", "false", "yes", "no", "on", "off",
    "utc", "gmt",
    "{}", "[]", "{ }", "()",   # empty JSON / array / composite container defaults
}

# Identifier token shape for the fallback tokenizer. Uses a Unicode letter class
# ([^\W\d] = letter/underscore, not a digit) so accented / non-ASCII identifiers stay whole.
_WORD_RE = re.compile(r'"(?:[^"]|"")*"|[^\W\d][\w$#]*', re.UNICODE)

# Curated structural keywords / type spellings / storage & clause words that are NEVER
# business identifiers and must be kept verbatim by the fallback tokenizer.
_STRUCTURAL_KEYWORDS = {
    # type spellings
    "INTEGER", "INT", "SMALLINT", "BIGINT", "NUMBER", "NUMERIC", "DECIMAL", "FLOAT",
    "REAL", "DOUBLE", "PRECISION", "BOOLEAN", "BOOL", "BIT",
    "CHAR", "CHARACTER", "VARCHAR", "VARCHAR2", "NVARCHAR2", "NCHAR", "NVARCHAR",
    "TEXT", "CLOB", "NCLOB", "BLOB", "BYTEA", "RAW", "LONG", "BFILE",
    "DATE", "TIME", "TIMESTAMP", "TIMESTAMPTZ", "INTERVAL", "DATETIME",
    "JSON", "JSONB", "UUID", "XML", "MONEY", "SERIAL", "BIGSERIAL", "SMALLSERIAL",
    "VARYING", "ZONE", "WITH", "WITHOUT", "PLS_INTEGER", "BINARY_INTEGER",
    "BINARY_FLOAT", "BINARY_DOUBLE", "ROWID", "UROWID",
    # DDL structure
    "CREATE", "TABLE", "VIEW", "INDEX", "SEQUENCE", "TRIGGER", "FUNCTION",
    "PROCEDURE", "PACKAGE", "BODY", "TYPE", "DOMAIN", "SCHEMA", "MATERIALIZED",
    "OR", "REPLACE", "IF", "NOT", "EXISTS", "AS", "IS", "ON", "TO", "FROM", "INTO",
    "PRIMARY", "FOREIGN", "KEY", "UNIQUE", "CHECK", "CONSTRAINT", "REFERENCES",
    "DEFAULT", "NULL", "CASCADE", "RESTRICT", "ACTION", "SET", "DELETE", "UPDATE",
    "GENERATED", "ALWAYS", "BY", "IDENTITY", "USING", "WHERE", "AND", "OR", "IN", "VALUES",
    "PARTITION", "SUBPARTITION", "RANGE", "LIST", "HASH", "LESS", "THAN", "MAXVALUE",
    "INHERITS", "LIKE", "EXCLUDE", "DEFERRABLE", "INITIALLY", "DEFERRED", "IMMEDIATE",
    "ENUM", "RETURNS", "RETURN", "LANGUAGE", "BEGIN", "END", "DECLARE", "ROW", "EACH",
    "BEFORE", "AFTER", "INSTEAD", "OF", "FOR", "STATEMENT", "WHEN", "OWNED", "OPTION",
    "ALTER", "ADD", "COLUMN", "MODIFY", "RENAME", "GRANT", "REVOKE", "SELECT", "INSERT",
    "EXECUTE", "USAGE", "ONLY", "COLLATE", "STORED", "VIRTUAL", "CONCURRENTLY", "VALUE",
    "OBJECT", "VARRAY", "NESTED", "ENABLE", "DISABLE", "VALIDATE", "NOVALIDATE",
    # query clause keywords (appear in view / mview bodies that hit the fallback)
    "GROUP", "ORDER", "CLUSTER", "HAVING", "LIMIT", "OFFSET", "FETCH", "OVER", "CONNECT",
    "MINUS", "UNION", "INTERSECT", "EXCEPT", "ALL", "DISTINCT", "ROWS", "NULLS", "FIRST",
    "LAST", "ASC", "DESC", "JOIN", "INNER", "OUTER", "LEFT", "RIGHT", "FULL", "CROSS",
    "WINDOW", "WITHIN", "FILTER", "LATERAL", "PIVOT", "UNPIVOT",
    # Oracle / PG storage & physical-attribute keywords
    "TABLESPACE", "STORAGE", "INITIAL", "NEXT", "PCTFREE", "PCTUSED", "INITRANS",
    "MAXTRANS", "MAXEXTENTS", "MINEXTENTS", "PCTINCREASE", "FREELISTS", "FREELIST",
    "GROUPS", "BUFFER_POOL", "MAXSIZE", "FLASH_CACHE", "CELL_FLASH_CACHE", "KEEP",
    "RECYCLE", "UNLIMITED", "LOGGING", "NOLOGGING", "COMPRESS", "NOCOMPRESS",
    "ORGANIZATION", "OVERFLOW", "INCLUDING", "PARALLEL", "NOPARALLEL", "MONITORING",
    "NOMONITORING", "RESULT_CACHE", "FILLFACTOR", "GLOBAL", "LOCAL", "BITMAP", "BTREE",
    "GIN", "GIST", "BRIN", "SPGIST", "REVERSE", "DESC", "SORT", "NOSORT",
    "TEMP", "TEMPORARY", "UNLOGGED", "EDITIONABLE", "NONEDITIONABLE", "FORCE", "NOFORCE",
    "MOVEMENT", "LOB", "STORE", "SECUREFILE", "BASICFILE", "CHUNK", "RETENTION",
    "PCTVERSION", "ROWDEPENDENCIES", "NOROWDEPENDENCIES", "SEGMENT", "CREATION",
    "INMEMORY", "FLASHBACK", "ARCHIVE", "SUPPLEMENTAL", "CHAINING", "DEPENDENT",
    "DEALLOCATE", "UNUSED", "ALLOCATE", "EXTENT", "DATAFILE", "DICTIONARY", "MAPPING",
    # sequence options
    "INCREMENT", "START", "CACHE", "NOCACHE", "CYCLE", "NOCYCLE", "MINVALUE",
    "NOMINVALUE", "NOMAXVALUE", "ORDER", "NOORDER", "RESTART",
    # default-value functions / literals that must be preserved as-is
    "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME", "LOCALTIMESTAMP",
    "SYSDATE", "SYSTIMESTAMP", "NOW", "TRUE", "FALSE", "UNKNOWN",
}


def _keywords_from_sqlglot():
    words = set()
    for name in ("postgres", "oracle"):
        try:
            tok = sqlglot.Dialect.get_or_raise(name).tokenizer_class
            for kw in tok.KEYWORDS:
                w = str(kw).upper()
                if re.fullmatch(r"[A-Z_][A-Z0-9_]*", w):
                    words.add(w)
        except Exception:
            pass
    for t in exp.DataType.Type:
        words.add(t.name.upper())
    return words


# Narrow set used by the fallback to decide what to KEEP — sqlglot keywords + type names +
# the curated structural set, but deliberately NOT builtin function names (RANK, COUNT, HOST,
# SUM, …) which are perfectly plausible business column names and must be sanitizable.
_FALLBACK_KEEP = _keywords_from_sqlglot() | _STRUCTURAL_KEYWORDS

# Broad set used only by the verify allow-list (so kept builtin functions don't warn).
RESERVED_AND_TYPES = set(_FALLBACK_KEEP)
try:
    RESERVED_AND_TYPES.update(n.upper() for n in exp.FUNCTION_BY_NAME)
except Exception:
    pass

# Output placeholder tokens, used to undo sqlglot's uppercasing of function-call names.
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"\b(?:" + "|".join(sorted((p.upper() for p in PREFIX.values()), key=len, reverse=True))
    + r")_\d{3,}\b")


def fold(name: str, dialect: str) -> str:
    """Dialect case-folding for *unquoted* identifiers (PG→lower, Oracle→upper)."""
    return name.upper() if dialect == "oracle" else name.lower()


def canon_key(raw: str, quoted: bool, dialect: str, strict_quoting: bool = False) -> str:
    """Canonical lookup key for the mapping.

    Unquoted names fold per dialect (so ``MyTable`` == ``mytable`` in PG). A quoted name
    collapses into the unquoted bucket only when its content already equals the folded
    form (so PG ``"mytable"`` == ``mytable`` but ``"MyTable"`` stays distinct); ``--strict
    -quoting`` keeps every quoted name in its own case-sensitive bucket.
    """
    folded = fold(raw, dialect)
    if not quoted:
        return "U:" + folded
    if not strict_quoting and raw == folded:
        return "U:" + folded
    return "Q:" + raw


# ---------------------------------------------------------------------------
# Mapping allocator — single source of truth, guarantees completeness
# ---------------------------------------------------------------------------
class MappingError(Exception):
    """Raised when a --use-mapping file cannot be read or parsed."""


class Mapping:
    def __init__(self, strict_quoting: bool = False):
        self.strict_quoting = strict_quoting
        self.fwd = {c: {} for c in CATEGORIES}   # canon_key -> placeholder
        self.rev = {c: {} for c in CATEGORIES}   # placeholder -> first-seen original
        self.keys = {c: {} for c in CATEGORIES}  # placeholder -> canon_key (for reload)
        self.counter = {c: 0 for c in CATEGORIES}

    def name_for(self, category: str, raw: str, *, quoted: bool, dialect: str,
                 value: bool = False) -> str:
        """Return the deterministic placeholder for ``raw`` in ``category`` (idempotent)."""
        if value:
            key = "V:" + raw  # enum values / string data: case-sensitive, no folding
        else:
            key = canon_key(raw, quoted, dialect, self.strict_quoting)
        bucket = self.fwd[category]
        if key in bucket:
            return bucket[key]
        self.counter[category] += 1
        ph = f"{PREFIX[category]}_{self.counter[category]:03d}"
        bucket[key] = ph
        self.rev[category][ph] = raw
        self.keys[category][ph] = key
        return ph

    # -- persistence --------------------------------------------------------
    def to_json(self) -> dict:
        out = {}
        for c in CATEGORIES:
            if self.rev[c]:
                out[c] = dict(self.rev[c])
        # Hidden block: lets --use-mapping rebuild lookup keys exactly (incl. quoted).
        out["_keys"] = {c: self.keys[c] for c in CATEGORIES if self.keys[c]}
        out["_meta"] = {"strict_quoting": self.strict_quoting}
        return out

    def dump(self, path) -> None:
        text = json.dumps(self.to_json(), indent=2, ensure_ascii=False) + "\n"
        Path(path).write_text(text, encoding="utf-8")

    @classmethod
    def load(cls, path):
        try:
            data = json.loads(Path(path).read_bytes().decode("utf-8-sig"))
        except FileNotFoundError:
            raise MappingError(f"--use-mapping file not found: {path}")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MappingError(f"--use-mapping file is not valid JSON ({path}): {exc}")
        if not isinstance(data, dict):
            raise MappingError(f"--use-mapping file must contain a JSON object: {path}")
        m = cls(strict_quoting=data.get("_meta", {}).get("strict_quoting", False))
        keys = data.get("_keys", {}) if isinstance(data.get("_keys"), dict) else {}
        for c in CATEGORIES:
            rev = data.get(c, {})
            if not isinstance(rev, dict):
                continue
            for ph, original in rev.items():
                original = str(original)
                m.rev[c][ph] = original
                key = (keys.get(c) or {}).get(ph)
                if key is None:
                    # Best-effort reconstruction when _keys is absent.
                    key = "V:" + original if c in ("enum_values", "string_defaults") else "U:" + original
                m.keys[c][ph] = key
                m.fwd[c][key] = ph
                mnum = re.search(r"(\d+)$", str(ph))
                if mnum:
                    m.counter[c] = max(m.counter[c], int(mnum.group(1)))
        return m

    def counts(self) -> dict:
        return {c: len(self.rev[c]) for c in CATEGORIES if self.rev[c]}


# ---------------------------------------------------------------------------
# Segment scanner — one state machine shared by gut/split/fallback
# ---------------------------------------------------------------------------
def scan_segments(text: str):
    """Yield ``(kind, start, end)`` spans covering ``text`` exactly once.

    kind ∈ {code, sstring, dquote, dollar, line_comment, block_comment}. Handles ``''``
    doubled quotes, PG ``E'\\''`` escapes, Oracle ``q'[..]'`` alt-quoting, ``""`` quoted
    identifiers, ``$tag$..$tag$`` dollar blocks, ``-- ..`` and ``/* .. */`` comments.
    """
    i, n = 0, len(text)
    code_start = 0
    Q_CLOSE = {"[": "]", "{": "}", "(": ")", "<": ">"}

    def flush_code(upto):
        if upto > code_start:
            return ("code", code_start, upto)
        return None

    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        # line comment
        if two == "--":
            seg = flush_code(i)
            if seg:
                yield seg
            j = text.find("\n", i)
            j = n if j == -1 else j
            yield ("line_comment", i, j)
            i = code_start = j
            continue
        # block comment
        if two == "/*":
            seg = flush_code(i)
            if seg:
                yield seg
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            yield ("block_comment", i, j)
            i = code_start = j
            continue
        # double-quoted identifier
        if ch == '"':
            seg = flush_code(i)
            if seg:
                yield seg
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            yield ("dquote", i, j)
            i = code_start = j
            continue
        # Oracle q'[ .. ]' / q'( .. )' etc. (only when 'q' is at a token boundary, so it
        # isn't the tail of an identifier like "uniq").
        if (ch in "qQ" and i + 2 < n and text[i + 1] == "'"
                and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$#"))):
            opener = text[i + 2]
            closer = Q_CLOSE.get(opener, opener)
            term = closer + "'"
            j = text.find(term, i + 3)
            j = n if j == -1 else j + 2
            seg = flush_code(i)
            if seg:
                yield seg
            yield ("sstring", i, j)
            i = code_start = j
            continue
        # ordinary single-quoted string (with optional E prefix already in code)
        if ch == "'":
            seg = flush_code(i)
            if seg:
                yield seg
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\" and j + 1 < n:  # PG backslash escape (E'..')
                    j += 2
                    continue
                if c == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            yield ("sstring", i, j)
            i = code_start = j
            continue
        # dollar-quoted block  $tag$ ... $tag$
        if ch == "$":
            m = re.match(r"\$[A-Za-z_]\w*\$|\$\$", text[i:])
            if m:
                tag = m.group(0)
                seg = flush_code(i)
                if seg:
                    yield seg
                j = text.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                yield ("dollar", i, j)
                i = code_start = j
                continue
        i += 1
    seg = flush_code(n)
    if seg:
        yield seg


# ---------------------------------------------------------------------------
# Dialect detection
# ---------------------------------------------------------------------------
_ORACLE_SIGNALS = [
    (r"\bVARCHAR2\b", 3), (r"\bNVARCHAR2\b", 3), (r"\bNUMBER\s*\(", 2),
    (r"\bCLOB\b", 2), (r"\bNCLOB\b", 2), (r"\bPACKAGE\b", 3), (r"\bPLS_INTEGER\b", 3),
    (r"\bBINARY_INTEGER\b", 3), (r"\bDUAL\b", 3), (r"\bSYSDATE\b", 2),
    (r"\bROWNUM\b", 3), (r"\bNOCOPY\b", 3), (r"q'\[", 3), (r":=", 1),
    (r"^\s*/\s*$", 2), (r"\bTABLESPACE\b", 1), (r"\bORGANIZATION\s+INDEX\b", 3),
    (r"\bVARRAY\b", 3), (r"\bAS\s+OBJECT\b", 3),
]
_POSTGRES_SIGNALS = [
    (r"\$[A-Za-z_]*\$", 3), (r"\bSERIAL\b", 3), (r"\bBIGSERIAL\b", 3),
    (r"\bSMALLSERIAL\b", 3), (r"\bJSONB\b", 3), (r"\bBYTEA\b", 3),
    (r"\bplpgsql\b", 3), (r"\bINHERITS\b", 3), (r"::", 1), (r"\bUUID\b", 1),
    (r"\bTEXT\b", 1), (r"\bBOOLEAN\b", 1), (r"\bGIN\b", 2), (r"\bGIST\b", 2),
    (r"\bDOMAIN\b", 2), (r"\bWITH\s+TIME\s+ZONE\b", 1),
]


def detect_dialect(text: str) -> str:
    """Score-based dialect verdict from dialect-proof tokens (outside strings/comments)."""
    code = "".join(text[s:e] for k, s, e in scan_segments(text) if k in ("code", "dquote"))
    o = sum(w for pat, w in _ORACLE_SIGNALS
            if re.search(pat, code, re.IGNORECASE | re.MULTILINE))
    p = sum(w for pat, w in _POSTGRES_SIGNALS
            if re.search(pat, code, re.IGNORECASE | re.MULTILINE))
    if o == 0 and p == 0:
        sys.stderr.write("[WARN] Could not detect dialect; defaulting to postgres.\n")
        return "postgres"
    return "oracle" if o > p else "postgres"


# ---------------------------------------------------------------------------
# Body gutting (pre-parse, pre-split)
# ---------------------------------------------------------------------------
_PLSQL_HEAD_RE = re.compile(
    r"\bCREATE\b(?:\s+OR\s+REPLACE)?(?:\s+(?:EDITIONABLE|NONEDITIONABLE))?\s+"
    r"(?:PROCEDURE|FUNCTION|PACKAGE(?:\s+BODY)?|TYPE\s+BODY|TRIGGER)\b",
    re.IGNORECASE,
)


def gut_bodies(text: str, dialect: str):
    """Replace executable bodies with sentinels *before* splitting/parsing.

    Returns ``(new_text, restores)`` where ``restores`` maps a sentinel string to its
    final replacement. PG dollar-quoted bodies become a string-literal sentinel (keeps the
    statement parseable so the signature can be AST-sanitized); Oracle PL/SQL bodies are
    replaced inline with the body-removed comment (those statements go to the fallback).
    """
    restores = {}
    counter = 0

    # --- PG: dollar-quoted bodies -> string-literal sentinel ---------------
    segs = list(scan_segments(text))
    pieces, last = [], 0
    for kind, s, e in segs:
        if kind == "dollar":
            pieces.append(text[last:s])
            sentinel = f"SQLSANBODY{counter}"
            restores[f"'{sentinel}'"] = f"$${BODY_PLACEHOLDER}$$"
            restores[sentinel] = BODY_PLACEHOLDER  # belt-and-suspenders
            pieces.append(f"'{sentinel}'")
            counter += 1
            last = e
    pieces.append(text[last:])
    text = "".join(pieces)

    # --- Oracle: PL/SQL bodies -> inline comment ---------------------------
    if dialect == "oracle":
        text, counter = _gut_oracle_plsql(text, restores, counter)
    return text, restores


def _stmt_bounds_oracle(text, start):
    """End offset (exclusive) of an Oracle statement beginning at ``start``: the next lone
    ``/`` line, else the trailing ``;`` of a top-level END, else end-of-text."""
    slash = re.search(r"(?m)^[ \t]*/[ \t]*$", text[start:])
    if slash:
        return start + slash.start(), start + slash.end()
    # No slash terminator: stop at a blank line followed by another CREATE, else EOF.
    nxt = re.search(r";\s*\n\s*\n", text[start:])
    if nxt:
        return start + nxt.start() + 1, start + nxt.end()
    return len(text), len(text)


def _gut_oracle_plsql(text, restores, counter):
    out, pos = [], 0
    for m in _PLSQL_HEAD_RE.finditer(text):
        if m.start() < pos:
            continue
        head_start = m.start()
        body_end, stmt_end = _stmt_bounds_oracle(text, head_start)
        chunk = text[head_start:body_end]
        # Body begins at the first top-level IS/AS (proc/func/pkg) or BEGIN/DECLARE.
        bm = re.search(r"\b(IS|AS|BEGIN|DECLARE)\b", chunk, re.IGNORECASE)
        out.append(text[pos:head_start])
        if bm:
            keyword = bm.group(1).upper()
            sig = chunk[:bm.end()]
            out.append(sig)
            out.append(f"\n  {BODY_PLACEHOLDER}\n")
        else:
            out.append(chunk)
            out.append(f"\n  {BODY_PLACEHOLDER}\n")
        pos = body_end
    out.append(text[pos:])
    return "".join(out), counter


def restore_bodies(text, restores):
    for sentinel, repl in restores.items():
        text = text.replace(sentinel, repl)
    return text


# ---------------------------------------------------------------------------
# Statement splitting
# ---------------------------------------------------------------------------
def split_statements(text, dialect):
    """Split into ``(stmt_text, terminator)`` pairs respecting strings/comments/dollar
    blocks (via ``scan_segments``). Splits on ``;`` in code and, for Oracle, on a lone
    ``/`` line."""
    # Collect all delimiter positions across code segments, then split in position order so
    # a lone Oracle '/' that follows a ';' is consumed (not prepended to the next statement).
    cuts = []  # (delimiter_start, next_stmt_start, terminator)
    for kind, s, e in scan_segments(text):
        if kind != "code":
            continue
        chunk = text[s:e]
        for mm in re.finditer(r";", chunk):
            p = s + mm.start()
            cuts.append((p, p + 1, ";"))
        if dialect == "oracle":
            for lm in re.finditer(r"(?m)^[ \t]*/[ \t]*$", chunk):
                cuts.append((s + lm.start(), s + lm.end(), "\n/"))
    cuts.sort()
    stmts = []
    start = 0
    for p, nxt, term in cuts:
        if p < start:
            continue
        seg = text[start:p]
        if seg.strip():
            stmts.append((seg, term))
        start = nxt  # advance even when seg is empty, so the delimiter is consumed
    tail = text[start:]
    if tail.strip():
        stmts.append((tail, ";"))
    return [(t, term) for t, term in stmts if t.strip()]


# ---------------------------------------------------------------------------
# AST classification
# ---------------------------------------------------------------------------
def collect_aliases(root):
    """Return (plain_aliases, cte_names) for a parsed statement, folded-lower for lookup."""
    plain, ctes = set(), set()
    for node in root.walk():
        if isinstance(node, exp.TableAlias):
            name = node.this
            if isinstance(name, exp.Identifier):
                name = name.this
            if name:
                (ctes if isinstance(node.parent, exp.CTE) else plain).add(str(name).lower())
    return plain, ctes


def classify_table_name(table: "exp.Table", aliases):
    """Category for ``table.this`` given the Table's role in the tree (or None to keep it)."""
    name = (table.this.this if isinstance(table.this, exp.Identifier) else table.this)
    if name and str(name).lower().endswith("_ops"):
        return None  # operator class in an index (e.g. text_pattern_ops): structural, not IP
    if name and str(name).lower() in aliases[1]:
        return "ctes"
    gp = table.parent
    if isinstance(gp, exp.UserDefinedFunction):
        return "functions"
    if isinstance(gp, exp.Create):
        return _create_kind_category(gp)
    if isinstance(gp, exp.Schema) and isinstance(gp.parent, exp.Create):
        return _create_kind_category(gp.parent)
    return "tables"


def _create_kind_category(create: "exp.Create") -> str:
    kind = (create.kind or "").upper()
    if kind == "VIEW":
        return "materialized_views" if create.find(exp.MaterializedProperty) else "views"
    return {
        "TABLE": "tables", "SEQUENCE": "sequences", "SCHEMA": "schemas",
        "TYPE": "types", "DOMAIN": "domains", "INDEX": "indexes",
        "FUNCTION": "functions", "PROCEDURE": "functions", "TRIGGER": "triggers",
    }.get(kind, "tables")


def classify_identifier(idnode: "exp.Identifier", aliases):
    """Map an Identifier to a category, or None to leave it untouched (aliases/keywords)."""
    p = idnode.parent
    ak = idnode.arg_key
    folded = str(idnode.this).lower()

    if isinstance(p, exp.TableAlias):
        return "ctes" if isinstance(p.parent, exp.CTE) else None
    if isinstance(p, (exp.CollateColumnConstraint, exp.Collate)):
        return None  # collation names (en_US, C, POSIX, …) are standard, not IP
    if isinstance(p, exp.Table):
        if ak in ("db", "catalog"):
            return "schemas"
        if ak == "this":
            return classify_table_name(p, aliases)
        return None
    if isinstance(p, exp.Column):
        if ak == "this":
            return "columns"
        if ak == "table":
            if folded in aliases[0]:
                return None
            if folded in aliases[1]:
                return "ctes"
            return "tables"
        if ak in ("db", "catalog"):
            return "schemas"
        return None
    if isinstance(p, exp.ColumnDef) and ak == "this":
        return "columns"
    if isinstance(p, exp.Index) and ak == "this":
        return "indexes"
    if isinstance(p, exp.Constraint) and ak == "this":
        return "constraints"
    if isinstance(p, exp.Create) and ak == "this":
        return _create_kind_category(p)
    if isinstance(p, exp.GrantPrincipal):
        return None if str(idnode.this).upper() in SAFE_ROLES else "roles"
    if isinstance(p, (exp.PrimaryKey, exp.ForeignKey)) and ak == "expressions":
        return "columns"
    if isinstance(p, exp.Schema) and ak == "expressions":
        return "columns"
    if isinstance(p, exp.DataType):  # user-defined type reference (kind=Identifier)
        return "types"
    if isinstance(p, exp.PartitionedByProperty) or isinstance(p, exp.Partition):
        return "partitions"
    if isinstance(p, exp.Dot) and ak == "this":
        # schema/package qualifier of a qualified function call, e.g. audit.log_change()
        return "schemas"
    return "columns"  # safe default: sanitize rather than leak


# ---------------------------------------------------------------------------
# AST sanitization
# ---------------------------------------------------------------------------
def _sanitize_qualified(name: str, dialect, mapping, last_cat: str) -> str:
    """Sanitize a (possibly schema-qualified) name held inside a string literal, e.g. the
    ``'schema.seq'`` argument of ``nextval`` — each dotted segment mapped in its own
    category so it stays consistent with the corresponding CREATE statement."""
    parts = name.split(".")
    out = []
    for i, part in enumerate(parts):
        quoted = part.startswith('"') and part.endswith('"')
        raw = part[1:-1] if quoted else part
        cat = last_cat if i == len(parts) - 1 else "schemas"
        ph = mapping.name_for(cat, raw, quoted=quoted, dialect=dialect)
        out.append(f'"{ph}"' if quoted else ph)
    return ".".join(out)


def sanitize_ast(root, dialect, mapping):
    aliases = collect_aliases(root)

    # Drop COMMENT ON statements entirely.
    if isinstance(root, exp.Comment):
        return ""

    # 1) identifiers
    for idnode in list(root.find_all(exp.Identifier)):
        category = classify_identifier(idnode, aliases)
        if category is None:
            continue
        raw, quoted = str(idnode.this), bool(idnode.quoted)
        # A user-defined type reference that names a previously-declared DOMAIN must reuse
        # the domain placeholder (the CREATE DOMAIN goes through the fallback as a domain).
        if category == "types":
            key = canon_key(raw, quoted, dialect, mapping.strict_quoting)
            if key in mapping.fwd["domains"]:
                category = "domains"
        ph = mapping.name_for(category, raw, quoted=quoted, dialect=dialect)
        idnode.set("this", ph)

    # 2) function-call / sequence references stored as Anonymous(this=<str>)
    for fn in list(root.find_all(exp.Anonymous)):
        fname = str(fn.this)
        low = fname.lower()
        if low in ("nextval", "currval", "setval"):
            for lit in fn.find_all(exp.Literal):
                if lit.is_string:
                    lit.set("this", _sanitize_qualified(lit.this, dialect, mapping, "sequences"))
            continue
        if fname.upper() in RESERVED_AND_TYPES:
            continue
        fn.set("this", mapping.name_for("functions", fname, quoted=False, dialect=dialect))

    # 3) gut function / procedure bodies that sqlglot parsed structurally
    if isinstance(root, exp.Create) and (root.kind or "").upper() in ("FUNCTION", "PROCEDURE"):
        if root.args.get("expression") is not None:
            root.set("expression", exp.Heredoc(this=f" {BODY_PLACEHOLDER} "))

    # 4) string literals (DEFAULT / enum / CHECK data)
    scrub_literals(root, dialect, mapping)

    # 5) clear any stray attached comments, then regenerate
    for node in root.walk():
        if node.comments:
            node.comments = None
    sql = root.sql(dialect=dialect, comments=False)
    # sqlglot upper-cases unknown function-call names (Anonymous), so a call site renders
    # FUNC_001 while the declaration/mapping key is func_001 — re-lower placeholder tokens
    # so the output spelling always matches the mapping.
    return _PLACEHOLDER_TOKEN_RE.sub(lambda m: m.group(0).lower(), sql)


def _string_literal_category(lit: "exp.Literal"):
    """Category for a string literal to sanitize, or None to keep it.

    All non-trivial string data is business IP, so the default is to sanitize: strings
    under a column DEFAULT become ``string_defaults`` and every other data string (enum
    members, CHECK / IN lists, partial-index and view WHERE comparisons, …) becomes
    ``enum_values``. Numbers, empty strings, structural/functional strings (language names,
    booleans, timezones) and sequence-name arguments of nextval/currval/setval are kept.
    """
    if not lit.is_string:
        return None
    val = lit.this
    if val == "" or str(val).lower() in SAFE_LITERALS:
        return None
    under_default = False
    node = lit.parent
    while node is not None:
        if isinstance(node, exp.Anonymous) and str(node.this).lower() in (
                "nextval", "currval", "setval"):
            return None  # sequence name, handled separately
        if isinstance(node, exp.DefaultColumnConstraint):
            under_default = True
        node = node.parent
    return "string_defaults" if under_default else "enum_values"


def scrub_literals(root, dialect, mapping):
    for lit in list(root.find_all(exp.Literal)):
        cat = _string_literal_category(lit)
        if cat is None:
            continue
        ph = mapping.name_for(cat, lit.this, quoted=False, dialect=dialect, value=True)
        lit.set("this", ph)
        lit.set("is_string", True)


# ---------------------------------------------------------------------------
# Fallback sanitizer (statements sqlglot can only parse as Command / ParseError)
# ---------------------------------------------------------------------------
_FALLBACK_KW_CATEGORY = {
    "TABLE": "tables", "INTO": "tables", "FROM": "tables", "JOIN": "tables",
    "UPDATE": "tables", "REFERENCES": "tables", "ON": "tables", "INDEX": "indexes",
    "CONSTRAINT": "constraints", "SEQUENCE": "sequences", "VIEW": "views",
    "DOMAIN": "domains", "TYPE": "types", "TRIGGER": "triggers", "PROCEDURE": "functions",
    "FUNCTION": "functions", "PACKAGE": "functions", "SCHEMA": "schemas",
    "TABLESPACE": "tablespaces", "PARTITION": "partitions", "SUBPARTITION": "partitions",
    "TO": "roles",
}


_SENTINEL_RE = re.compile(r"^SQLSANBODY\d+$", re.IGNORECASE)
# Constraint keywords that can open a table-level constraint where a column name would sit.
_CONSTRAINT_STARTERS = {"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "LIKE",
                        "EXCLUDE", "KEY"}
# After these keywords the next token is a type / language name and must be kept verbatim.
_KEEP_NEXT_KEYWORDS = {"RETURNS", "RETURN", "LANGUAGE"}
# Keywords that introduce a parenthesised column list (every identifier inside → columns).
_COLLIST_OPENERS = {"KEY", "UNIQUE", "CHECK", "EXCLUDE"}
# Ordering / operator words that may sit inside a key column list and must be kept.
_COLLIST_KEEP = {"ASC", "DESC", "NULLS", "FIRST", "LAST", "WITH", "AND", "OR", "IN",
                 "USING", "NOT"}
# Structural keywords that are NEVER an object/column name, even right after a context
# keyword (e.g. the `DELETE`/`UPDATE` of an FK action, `OVERFLOW` after ORGANIZATION INDEX).
_NEVER_IDENTIFIER = {"DELETE", "UPDATE", "CASCADE", "RESTRICT", "ACTION", "SET", "NULL",
                     "NO", "MOVEMENT", "OVERFLOW", "ENABLE", "DISABLE", "VALIDATE",
                     "NOVALIDATE", "USING", "WITH", "ROW", "STORE", "LOB", "SEGMENT",
                     "CREATION", "INITIALLY", "DEFERRED", "IMMEDIATE", "DEFERRABLE"}


class _FbState:
    __slots__ = ("prev_kw", "materialized", "depth", "coldef_depth", "coldef_done",
                 "at_name_slot", "keep_next", "is_create_table", "is_create_index",
                 "expect_collist", "collist_depth", "expect_ref_table")

    def __init__(self, materialized, is_create_table, is_create_index):
        self.prev_kw = None         # last category-setting keyword for the next identifier
        self.materialized = materialized
        self.is_create_table = is_create_table
        self.is_create_index = is_create_index
        self.depth = 0              # current () nesting
        self.coldef_depth = None    # depth of the CREATE TABLE column list (None = outside)
        self.coldef_done = False    # the column list has already been seen (don't re-enter)
        self.at_name_slot = False   # next identifier is a column name in the column list
        self.keep_next = False      # keep the next token verbatim (return type / language)
        self.expect_collist = False  # the next '(' opens a key/index column list
        self.collist_depth = None   # depth of the active key column list (None = outside)
        self.expect_ref_table = False  # we just saw REFERENCES; collist follows the table


def fallback_sanitize(stmt_text, dialect, mapping):
    """Segment-aware tokenizer for statements sqlglot can only parse as ``Command`` /
    ``ParseError`` (Oracle TABLESPACE/STORAGE/partition-def tables & indexes, PG DOMAIN,
    PL/SQL signatures, …). Every business identifier in a code span is replaced via the
    shared mapping — including names that happen to spell a keyword/type, when they sit in
    an identifier or key-list position — strings (incl. Oracle ``q'[..]'``) become data
    placeholders, comments are dropped (except the body marker), and dollar blocks become
    the gutted-body comment. Designed so no business token survives."""
    out = []
    is_ct = bool(re.match(r"\s*CREATE\b[^(;]*?\bTABLE\b", stmt_text, re.IGNORECASE | re.DOTALL))
    is_ci = bool(re.match(r"\s*CREATE\b[^(;]*?\bINDEX\b", stmt_text, re.IGNORECASE | re.DOTALL))
    st = _FbState(bool(re.search(r"\bMATERIALIZED\s+VIEW\b", stmt_text, re.IGNORECASE)),
                  is_ct, is_ci)
    for kind, s, e in scan_segments(stmt_text):
        span = stmt_text[s:e]
        if kind in ("line_comment", "block_comment"):
            if BODY_PLACEHOLDER in span:
                out.append(span)            # keep the body-removed marker
            continue                        # otherwise strip the comment
        if kind == "dollar":
            out.append(f"$${BODY_PLACEHOLDER}$$")
            continue
        if kind == "sstring":
            out.append(_fallback_string(span, dialect, mapping))
            continue
        if kind == "dquote":
            inner = span[1:-1].replace('""', '"')
            in_collist = st.collist_depth is not None and st.depth >= st.collist_depth
            cat = "columns" if in_collist else _slot_category(st, False)
            out.append('"' + mapping.name_for(cat, inner, quoted=True, dialect=dialect) + '"')
            st.prev_kw = None
            st.at_name_slot = False
            continue
        out.append(_fallback_code(span, dialect, mapping, st))
    return "".join(out)


def _is_q_quote(span):
    return bool(re.match(r"[qQ]'", span))


def _fallback_string(span, dialect, mapping):
    # Oracle q'[ .. ]' / q'{ .. }' / q'X..X' alt-quoting: extract and sanitize the content.
    if _is_q_quote(span) and len(span) >= 5:
        inner = span[3:-2]
        if inner == "" or inner.lower() in SAFE_LITERALS:
            return span
        ph = mapping.name_for("string_defaults", inner, quoted=False, dialect=dialect, value=True)
        return f"'{ph}'"
    if not span.startswith("'"):
        return span
    terminated = span.endswith("'") and len(span) >= 2
    inner = (span[1:-1] if terminated else span[1:]).replace("''", "'")
    if inner == "" or inner.lower() in SAFE_LITERALS or _SENTINEL_RE.match(inner):
        return span if terminated else f"'{inner}'"
    ph = mapping.name_for("string_defaults", inner, quoted=False, dialect=dialect, value=True)
    return f"'{ph}'"  # also re-closes an unterminated literal, so its content can't escape


def _fallback_category(prev_kw, materialized):
    if prev_kw == "VIEW" and materialized:
        return "materialized_views"
    return _FALLBACK_KW_CATEGORY.get(prev_kw, "columns")


def _slot_category(st, followed_by_dot):
    if followed_by_dot:
        return "schemas"
    if st.at_name_slot and st.coldef_depth is not None:
        return "columns"
    return _fallback_category(st.prev_kw, st.materialized)


def _fallback_code(span, dialect, mapping, st):
    result = []
    i, n = 0, len(span)
    while i < n:
        ch = span[i]
        # structural punctuation drives column-list / name-slot tracking
        if ch == "(":
            st.depth += 1
            if (st.is_create_table and not st.coldef_done
                    and st.coldef_depth is None and st.depth == 1):
                st.coldef_depth = 1   # the first depth-1 paren is the column list only
                st.at_name_slot = True
            elif st.expect_collist and st.collist_depth is None:
                st.collist_depth = st.depth   # PK/UNIQUE/FK/CHECK/INDEX key column list
                st.expect_collist = False
            result.append(ch)
            i += 1
            continue
        if ch == ")":
            if st.collist_depth is not None and st.depth == st.collist_depth:
                st.collist_depth = None
            if st.coldef_depth is not None and st.depth == st.coldef_depth:
                st.coldef_depth = None
                st.coldef_done = True   # a STORAGE/PARTITION (...) later is not a column list
                st.at_name_slot = False
            st.depth -= 1
            result.append(ch)
            i += 1
            continue
        if ch == ",":
            if st.coldef_depth is not None and st.depth == st.coldef_depth:
                st.at_name_slot = True
            result.append(ch)
            i += 1
            continue
        m = _WORD_RE.match(span, i)
        if not m:
            result.append(ch)
            i += 1
            continue
        token = m.group(0)
        start = i
        i = m.end()
        # a letter run glued to a preceding digit is a numeric unit suffix (64K / 1M / hex)
        if start > 0 and span[start - 1].isdigit():
            result.append(token)
            continue
        followed_by_dot = span[i:i + 1] == "."
        # the column context spans the whole key-list / CHECK subtree (incl. function args)
        in_collist = st.collist_depth is not None and st.depth >= st.collist_depth

        if token.startswith('"'):
            inner = token[1:-1].replace('""', '"')
            cat = "columns" if in_collist and not followed_by_dot else _slot_category(st, followed_by_dot)
            result.append('"' + mapping.name_for(cat, inner, quoted=True, dialect=dialect) + '"')
            if not followed_by_dot:
                st.prev_kw = None
                st.at_name_slot = False
            continue

        upper = token.upper()

        if st.keep_next:                       # return type / language name
            st.keep_next = False
            st.prev_kw = None
            st.at_name_slot = False
            result.append(token)
            continue
        if _SENTINEL_RE.match(upper):          # gutted-body sentinel: inert
            result.append(token)
            st.at_name_slot = False
            continue
        if upper in _KEEP_NEXT_KEYWORDS:
            st.keep_next = True
            st.at_name_slot = False
            result.append(token)
            continue

        # inside a key/index/reference column list (incl. CHECK exprs): every identifier is a
        # column — this is where keyword-spelled names like value/cache/comment would leak —
        # except ordering words, structural keywords, opclasses, and function calls (name + '(').
        if in_collist:
            followed_by_paren = bool(re.match(r"\s*\(", span[i:]))
            if (upper in _COLLIST_KEEP or upper in _FALLBACK_KW_CATEGORY
                    or upper.endswith("_OPS") or followed_by_paren):
                result.append(token)
                continue
            cat = "schemas" if followed_by_dot else "columns"
            result.append(mapping.name_for(cat, token, quoted=False, dialect=dialect))
            continue

        # column-name slot inside a CREATE TABLE column list
        if st.at_name_slot and st.coldef_depth is not None and st.depth == st.coldef_depth:
            if upper in _CONSTRAINT_STARTERS:
                st.at_name_slot = False
                if upper in _COLLIST_OPENERS:
                    st.expect_collist = True
                st.prev_kw = "CONSTRAINT" if upper == "CONSTRAINT" else None
                result.append(token)
                continue
            cat = "schemas" if followed_by_dot else "columns"
            result.append(mapping.name_for(cat, token, quoted=False, dialect=dialect))
            if not followed_by_dot:
                st.at_name_slot = False
            continue

        # keywords that introduce a key column list (PRIMARY KEY / UNIQUE / CHECK / EXCLUDE)
        if upper in _COLLIST_OPENERS:
            st.expect_collist = True
            result.append(token)
            continue

        # PARTITION/SUBPARTITION: a `BY (...)` clause introduces key COLUMNS, not a name
        if upper in ("PARTITION", "SUBPARTITION"):
            if re.match(r"\s+BY\b", span[i:], re.IGNORECASE):
                st.prev_kw = None
                st.expect_collist = True
            else:
                st.prev_kw = upper
            result.append(token)
            continue

        # ON: distinguish an FK referential action (ON DELETE/UPDATE …) from `ON <table>`
        if upper == "ON":
            nxt = re.match(r"\s+(\w+)", span[i:])
            if nxt and nxt.group(1).upper() in ("DELETE", "UPDATE", "COMMIT"):
                result.append(token)      # FK action / temp-table clause: keep, no context
                continue
            st.prev_kw = "ON"
            result.append(token)
            continue

        if upper in _FALLBACK_KW_CATEGORY:
            if upper == "REFERENCES":
                st.expect_ref_table = True
            st.prev_kw = upper
            result.append(token)
            continue

        # In an identifier-expected position (right after a context keyword, or a dotted
        # qualifier) sanitize even keyword/type-spelled names — that's where leaks hide —
        # unless the token is a structural keyword that is never a name.
        if st.prev_kw is not None or followed_by_dot:
            if upper in _NEVER_IDENTIFIER:
                st.prev_kw = None
                result.append(token)
                continue
            cat = _slot_category(st, followed_by_dot)
            result.append(mapping.name_for(cat, token, quoted=False, dialect=dialect))
            if not followed_by_dot:
                # after the table that follows REFERENCES / in CREATE INDEX, a key list comes
                if cat == "tables" and (st.expect_ref_table or st.is_create_index):
                    st.expect_collist = True
                    st.expect_ref_table = False
                st.prev_kw = None
            continue

        # otherwise: keep genuine structural keywords/types, sanitize everything else
        if upper in _FALLBACK_KEEP:
            result.append(token)
            continue
        result.append(mapping.name_for("columns", token, quoted=False, dialect=dialect))
    return "".join(result)


# ---------------------------------------------------------------------------
# Per-statement routing
# ---------------------------------------------------------------------------
def sanitize_statement(stmt_text, dialect, mapping):
    if not stmt_text.strip():
        return ""
    # Oracle PL/SQL (gutted to a signature + comment) can become *partly* AST-parseable and
    # would then be regenerated with PostgreSQL `$$` body syntax — keep it on the text
    # fallback so the Oracle signature + body-removed comment is preserved verbatim.
    if dialect == "oracle" and _PLSQL_HEAD_RE.search(stmt_text):
        return fallback_sanitize(stmt_text, dialect, mapping)
    try:
        tree = sqlglot.parse_one(stmt_text, read=dialect, error_level="raise")
    except ParseError:
        return fallback_sanitize(stmt_text, dialect, mapping)
    except Exception:
        return fallback_sanitize(stmt_text, dialect, mapping)
    if tree is None:
        return ""
    if isinstance(tree, exp.Command) or tree.find(exp.Command) is not None:
        return fallback_sanitize(stmt_text, dialect, mapping)
    try:
        return sanitize_ast(tree, dialect, mapping)
    except Exception:
        return fallback_sanitize(stmt_text, dialect, mapping)


def sanitize_text(text, dialect, mapping):
    text2, restores = gut_bodies(text, dialect)
    parts = []
    for stmt_text, term in split_statements(text2, dialect):
        leading = stmt_text[:len(stmt_text) - len(stmt_text.lstrip())]
        san = sanitize_statement(stmt_text, dialect, mapping)
        if san.strip() == "":
            continue
        parts.append(leading.lstrip("\n") + san.strip() + term)
    out = "\n".join(p for p in parts if p.strip())
    out = restore_bodies(out, restores)
    if out and not out.endswith("\n"):
        out += "\n"
    return out


# ---------------------------------------------------------------------------
# Leak verification
# ---------------------------------------------------------------------------
def verify_pass(output, mapping, dialect, strict=False):
    """Return (warnings, leaks). ``leaks`` = original business tokens that survived
    (the hard failure); ``warnings`` = tokens that look unsanitized but aren't confirmed."""
    warnings, leaks = [], []
    # 1) raw-substring backstop: no stored original may appear in the output.
    #    Identifiers are matched as whole words; data values (enum/string defaults) are
    #    matched in their quoted-literal form to avoid common-word false positives.
    for c in CATEGORIES:
        is_value = c in ("enum_values", "string_defaults")
        for ph, original in mapping.rev[c].items():
            if not original or len(original) < 3:
                continue
            if is_value:
                needle = original.replace("'", "''")
                if f"'{needle}'" in output:
                    leaks.append(original)
                continue
            # An original whose spelling IS a SQL keyword/type (a column named "date",
            # "number", "user") legitimately reappears as that keyword in the output, so a
            # raw match is the keyword, not a leak. The AST path always renames such
            # identifiers; only the regex fallback can't tell them apart (documented limit).
            if original.upper() in RESERVED_AND_TYPES:
                continue
            if re.search(r"(?<![A-Za-z0-9_$#])" + re.escape(original) + r"(?![A-Za-z0-9_$#])",
                         output, re.IGNORECASE):
                leaks.append(original)

    # 2) allow-list scan: re-parse each statement independently (so one un-parseable
    #    Oracle PL/SQL skeleton doesn't disable the scan for the whole file) and flag any
    #    identifier that is neither a placeholder nor a known-safe keyword/alias.
    for stmt_text, _term in split_statements(output, dialect):
        try:
            tree = sqlglot.parse_one(stmt_text, read=dialect, error_level="raise")
        except Exception:
            continue
        if tree is None or isinstance(tree, exp.Command):
            continue
        aliases = collect_aliases(tree)
        for idnode in tree.find_all(exp.Identifier):
            tok = str(idnode.this)
            if PLACEHOLDER_RE.match(tok) or tok.upper() in RESERVED_AND_TYPES or len(tok) <= 2:
                continue
            # If the classifier would intentionally KEEP this identifier (alias, collation,
            # operator class, …) it isn't a leak. Otherwise an un-placeholdered identifier
            # means something slipped through -> warn.
            if classify_identifier(idnode, aliases) is not None:
                warnings.append(tok)

    return sorted(set(warnings)), sorted(set(leaks))


# ---------------------------------------------------------------------------
# Schema summary — a dense, self-contained markdown topology built ONLY from the
# sanitized output (placeholder names), suitable for a Claude Project knowledge base.
# ---------------------------------------------------------------------------
class _TableInfo:
    __slots__ = ("name", "columns", "pk", "fks_out", "unique", "indexes")

    def __init__(self, name):
        self.name = name
        self.columns = []   # (name, type, not_null, default|None, identity_sql|None)
        self.pk = []        # pk column names, in order
        self.fks_out = []   # (local_cols, target_table, target_cols)
        self.unique = []    # list of column-name lists
        self.indexes = []   # (index_name, method, [cols])


class SchemaModel:
    def __init__(self):
        self.tables = {}    # name -> _TableInfo
        self.views = {}     # name -> (sources, joincols, materialized)
        self.types = {}     # name -> [values]
        self.func_count = 0

    def table(self, name):
        if name not in self.tables:
            self.tables[name] = _TableInfo(name)
        return self.tables[name]


def _node_table_name(node):
    """Bare placeholder name (last segment) of a Table/Schema/Identifier node."""
    if isinstance(node, exp.Schema):
        node = node.this
    if isinstance(node, exp.Table):
        return node.this.name if node.this is not None else None
    if isinstance(node, exp.Identifier):
        return node.name
    return None


def _natural_key(name):
    m = re.match(r"([A-Za-z_]+?)_?(\d+)$", name or "")
    return (m.group(1), int(m.group(2))) if m else (name or "", 0)


def _fmt_cols(cols):
    cols = list(cols)
    return cols[0] if len(cols) == 1 else "(" + ", ".join(cols) + ")"


def _reduce_for_parse(text):
    """Truncate a statement after the first balanced top-level ``(...)`` group so that an
    Oracle TABLESPACE/STORAGE table (which sqlglot returns as a Command) reduces to a
    parseable ``CREATE TABLE name (...)`` / ``CREATE INDEX … (cols)`` core."""
    depth, opened = 0, False
    for kind, s, e in scan_segments(text):
        if kind != "code":
            continue
        for j in range(s, e):
            ch = text[j]
            if ch == "(":
                depth += 1
                opened = True
            elif ch == ")":
                depth -= 1
                if depth == 0 and opened:
                    return text[:j + 1]
    return None


def _ref_target(reference):
    this = reference.this if isinstance(reference, exp.Reference) else reference
    if isinstance(this, exp.Schema):
        return _node_table_name(this.this), [i.name for i in this.expressions]
    if isinstance(this, exp.Table):
        return _node_table_name(this), []
    return None, []


def _ingest_constraint_expr(e, ti):
    if isinstance(e, exp.ForeignKey):
        local = [i.name for i in e.expressions]
        ref = e.args.get("reference")
        if ref is not None:
            tgt, tcols = _ref_target(ref)
            if tgt:
                ti.fks_out.append((local, tgt, tcols))
    elif isinstance(e, exp.PrimaryKey):
        ti.pk.extend(i.name for i in e.expressions)
    elif isinstance(e, exp.UniqueColumnConstraint):
        cols = [i.name for i in e.this.expressions] if isinstance(e.this, exp.Schema) else []
        if cols:
            ti.unique.append(cols)


def _ingest_table(tree, dialect, model):
    schema = tree.this
    if isinstance(schema, exp.Schema):
        tname, exprs = _node_table_name(schema.this), schema.expressions
    else:
        tname, exprs = _node_table_name(schema), []
    if not tname:
        return
    ti = model.table(tname)
    for cd in exprs:
        if isinstance(cd, exp.ColumnDef):
            ctype = cd.kind.sql(dialect=dialect) if cd.kind else ""
            not_null = identity = default = None
            not_null = False
            for c in cd.constraints:
                k = c.kind
                if isinstance(k, exp.NotNullColumnConstraint):
                    not_null = True
                elif isinstance(k, exp.DefaultColumnConstraint):
                    default = k.this.sql(dialect=dialect)
                elif isinstance(k, exp.GeneratedAsIdentityColumnConstraint):
                    identity = k.sql(dialect=dialect)
                elif isinstance(k, exp.PrimaryKeyColumnConstraint):
                    ti.pk.append(cd.name)
                elif isinstance(k, exp.UniqueColumnConstraint):
                    ti.unique.append([cd.name])
                elif isinstance(k, exp.Reference):
                    tgt, tcols = _ref_target(k)
                    if tgt:
                        ti.fks_out.append(([cd.name], tgt, tcols))
            ti.columns.append((cd.name, ctype, not_null, default, identity))
        elif isinstance(cd, exp.PrimaryKey):
            ti.pk.extend(i.name for i in cd.expressions)
        elif isinstance(cd, exp.Constraint):
            for e in cd.expressions:
                _ingest_constraint_expr(e, ti)
        elif isinstance(cd, (exp.ForeignKey, exp.PrimaryKey, exp.UniqueColumnConstraint)):
            _ingest_constraint_expr(cd, ti)


def _ingest_index(tree, model):
    idx = tree.this
    if not isinstance(idx, exp.Index):
        return
    tbl = _node_table_name(idx.args.get("table"))
    if not tbl:
        return
    method, cols = "BTREE", []
    params = idx.args.get("params")
    if params is not None:
        using = params.args.get("using")
        if using is not None:
            method = (using.name if hasattr(using, "name") else str(using)).upper()
        for c in params.args.get("columns", []) or []:
            col = c.find(exp.Column)
            if col is not None:
                cols.append(col.name)
    model.table(tbl).indexes.append((idx.name, method, cols))


def _ingest_view(tree, model):
    vname = _node_table_name(tree.this)
    if not vname:
        return
    sel = tree.expression
    sources, seen, joincols = [], set(), set()
    if sel is not None:
        for t in sel.find_all(exp.Table):
            nm = _node_table_name(t)
            if nm and nm not in seen:
                seen.add(nm)
                sources.append(nm)
        for j in sel.find_all(exp.Join):
            on = j.args.get("on")
            if on is not None:
                joincols.update(c.name for c in on.find_all(exp.Column))
    model.views[vname] = (sources, sorted(joincols, key=_natural_key),
                          tree.find(exp.MaterializedProperty) is not None)


def _ingest_type(tree, model):
    tname = _node_table_name(tree.this)
    dt = tree.expression
    if tname and isinstance(dt, exp.DataType) and dt.this == exp.DataType.Type.ENUM:
        model.types[tname] = [l.name for l in dt.expressions if isinstance(l, exp.Literal)]


def collect_schema(output, dialect, model):
    """Populate ``model`` from sanitized SQL ``output`` (placeholder names only)."""
    for stmt_text, _term in split_statements(output, dialect):
        tree = None
        try:
            tree = sqlglot.parse_one(stmt_text, read=dialect, error_level="raise")
        except Exception:
            tree = None
        if tree is None or isinstance(tree, exp.Command):
            reduced = _reduce_for_parse(stmt_text)
            if reduced:
                try:
                    tree = sqlglot.parse_one(reduced, read=dialect, error_level="raise")
                except Exception:
                    tree = None
        if not isinstance(tree, exp.Create) or isinstance(tree, exp.Command):
            if re.match(r"\s*CREATE\b.*\b(PROCEDURE|FUNCTION)\b", stmt_text, re.IGNORECASE | re.DOTALL):
                model.func_count += 1
            continue
        kind = (tree.kind or "").upper()
        if kind == "TABLE":
            _ingest_table(tree, dialect, model)
        elif kind == "INDEX":
            _ingest_index(tree, model)
        elif kind == "VIEW":
            _ingest_view(tree, model)
        elif kind == "TYPE":
            _ingest_type(tree, model)
        elif kind in ("FUNCTION", "PROCEDURE"):
            model.func_count += 1


def _pk_line(ti):
    if not ti.pk:
        return None
    if len(ti.pk) > 1:
        return f"PK: {_fmt_cols(ti.pk)}"
    col = ti.pk[0]
    for (cname, ctype, _nn, _df, identity) in ti.columns:
        if cname == col:
            bits = [b for b in (ctype, identity) if b]
            return f"PK: {col}" + (f" ({', '.join(bits)})" if bits else "")
    return f"PK: {col}"


def render_summary(model, mapping):
    lines = []
    fks_in = {name: [] for name in model.tables}
    total_fk = 0
    for tname, ti in model.tables.items():
        for local, tgt, tcols in ti.fks_out:
            total_fk += 1
            if tgt in fks_in:
                fks_in[tgt].append((tname, local, tcols))
    total_cols = sum(len(ti.columns) for ti in model.tables.values())
    total_idx = sum(len(ti.indexes) for ti in model.tables.values())
    n_mviews = sum(1 for v in model.views.values() if v[2])
    n_views = len(model.views) - n_mviews
    n_funcs = max(model.func_count, len(mapping.rev.get("functions", {})))

    lines.append("# Schema Summary")
    lines.append("")
    lines.append("Sanitized structural overview (placeholder names only). Self-contained: it "
                 "describes the full schema topology without the DDL.")
    lines.append("")
    lines.append("## Overview")
    lines.append(f"- Tables: {len(model.tables)}")
    lines.append(f"- Views: {n_views}")
    if n_mviews:
        lines.append(f"- Materialized views: {n_mviews}")
    lines.append(f"- Functions/procedures: {n_funcs}")
    if model.types:
        lines.append(f"- Custom types: {len(model.types)}")
    lines.append(f"- Total columns: {total_cols}")
    lines.append(f"- Foreign keys: {total_fk}")
    lines.append(f"- Indexes: {total_idx}")
    lines.append("")

    for tname in sorted(model.tables, key=_natural_key):
        ti = model.tables[tname]
        lines.append(f"## {tname} ({len(ti.columns)} columns)")
        pk = _pk_line(ti)
        if pk:
            lines.append(pk)
        pkset = set(ti.pk)
        colbits = []
        for (cname, ctype, nn, default, _identity) in ti.columns:
            if cname in pkset:
                continue
            bit = f"{cname} {ctype}".strip()
            if nn:
                bit += " NOT NULL"
            if default is not None:
                bit += f" DEFAULT {default}"
            colbits.append(bit)
        if colbits:
            lines.append("Columns: " + ", ".join(colbits))
        if ti.fks_out:
            lines.append("FKs out: " + ", ".join(
                f"{_fmt_cols(local)} → {tgt}" + (f".{_fmt_cols(tcols)}" if tcols else "")
                for (local, tgt, tcols) in ti.fks_out))
        if fks_in.get(tname):
            default_tgt = ti.pk[0] if ti.pk else "?"
            lines.append("FKs in: " + ", ".join(
                f"{src}.{_fmt_cols(local)} → {_fmt_cols(tcols) if tcols else default_tgt}"
                for (src, local, tcols) in fks_in[tname]))
        if ti.indexes:
            lines.append("Indexes: " + ", ".join(
                f"{iname} {method}({', '.join(cols)})" for (iname, method, cols) in ti.indexes))
        if ti.unique:
            lines.append("Unique: " + ", ".join(_fmt_cols(u) for u in ti.unique))
        lines.append("")

    lines.append("## Relationships")
    for tname in sorted(model.tables, key=_natural_key):
        targets = sorted({tgt for (_l, tgt, _c) in model.tables[tname].fks_out}, key=_natural_key)
        lines.append(f"{tname} → {', '.join(targets) if targets else '(none)'}")
    lines.append("")

    if model.views:
        lines.append("## Views")
        for vname in sorted(model.views, key=_natural_key):
            sources, joincols, mat = model.views[vname]
            label = ("[materialized] " if mat else "") + "reads " + (
                ", ".join(sources) if sources else "(none)")
            if joincols:
                label += f" (joined on {', '.join(joincols)})"
            lines.append(f"{vname}: {label}")
        lines.append("")

    if model.types:
        lines.append("## Custom Types")
        for tname in sorted(model.types, key=_natural_key):
            lines.append(f"{tname}: {', '.join(model.types[tname])}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def build_summary(outputs, mapping):
    """outputs: iterable of (output_sql, dialect). Returns the combined summary markdown."""
    model = SchemaModel()
    for output, dialect in outputs:
        collect_schema(output, dialect, model)
    return render_summary(model, mapping)


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------
def _decode(data: bytes) -> str:
    """Decode SQL bytes tolerantly: UTF-8, then latin-1, finally replacement — never raise.
    Strips a leading UTF-8 BOM so it can't corrupt the first identifier."""
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace").lstrip("﻿")


def _read_text(path: Path) -> str:
    return _decode(path.read_bytes())


def iter_inputs(input_arg):
    """Yield (name, text). Handles '-' (stdin), a file, or a directory of .sql files.
    Files that can't be read are skipped with a [WARN] rather than aborting a batch."""
    if input_arg == "-":
        yield ("<stdin>", _decode(sys.stdin.buffer.read()))
        return
    path = Path(input_arg)
    if path.is_dir():
        files = sorted(path.glob("*.sql"))
        if not files:
            sys.stderr.write(f"[WARN] No .sql files found in {path}\n")
        for f in files:
            try:
                yield (f.name, _read_text(f))
            except OSError as exc:
                sys.stderr.write(f"[WARN] Skipping {f.name}: {exc}\n")
        return
    yield (path.name, _read_text(path))


def write_output(output_arg, name, content, is_batch):
    if output_arg == "-" or output_arg is None:
        sys.stdout.write(content)
        return
    out = Path(output_arg)
    if is_batch:
        out.mkdir(parents=True, exist_ok=True)
        target = out / name
        target.write_text(content, encoding="utf-8")
        return target
    if out.is_dir():
        target = out / name
        target.write_text(content, encoding="utf-8")
        return target
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content, encoding="utf-8")
    return out


def print_summary(mapping):
    counts = mapping.counts()
    order = ["tables", "columns", "indexes", "constraints", "views",
             "materialized_views", "functions", "triggers", "sequences", "types",
             "domains", "schemas", "roles", "partitions", "tablespaces", "enum_values"]
    labels = {
        "tables": "tables", "columns": "columns", "indexes": "indexes",
        "constraints": "constraints", "views": "views",
        "materialized_views": "materialized views", "functions": "functions",
        "triggers": "triggers", "sequences": "sequences", "types": "types",
        "domains": "domains", "schemas": "schemas", "roles": "roles",
        "partitions": "partitions", "tablespaces": "tablespaces",
        "enum_values": "enum values",
    }
    bits = [f"{counts[c]} {labels[c]}" for c in order if counts.get(c)]
    sys.stderr.write("Sanitized: " + ", ".join(bits) + "\n")


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
DEMO_SQL = """\
-- Demo schema: BGP peering platform (entirely fictional)
CREATE SCHEMA ix_platform;

CREATE TYPE ix_platform.session_status_enum AS ENUM ('ACTIVE', 'PENDING', 'DISABLED');

CREATE SEQUENCE ix_platform.peering_session_id_seq START WITH 1 INCREMENT BY 1;

CREATE TABLE ix_platform.peer (
    peer_id       BIGINT PRIMARY KEY,
    asn_number    INTEGER NOT NULL,
    peer_name     VARCHAR(255) NOT NULL,            -- the customer's org name
    contact_email VARCHAR(320),
    is_active     BOOLEAN DEFAULT true
);

CREATE TABLE ix_platform.peering_session (
    session_id    BIGINT DEFAULT nextval('ix_platform.peering_session_id_seq') PRIMARY KEY,
    peer_id       BIGINT NOT NULL,
    status        VARCHAR(20) DEFAULT 'PENDING_REVIEW' NOT NULL,
    "Created At"  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    bandwidth_mbps NUMERIC(10,2),
    CONSTRAINT fk_session_peer FOREIGN KEY (peer_id)
        REFERENCES ix_platform.peer (peer_id) ON DELETE CASCADE,
    CONSTRAINT chk_status CHECK (status IN ('ACTIVE', 'PENDING', 'DISABLED'))
);

CREATE INDEX idx_peering_session_asn
    ON ix_platform.peering_session USING btree (peer_id)
    WHERE status = 'ACTIVE';

CREATE TABLE ix_platform.traffic_sample (
    sample_id   BIGSERIAL PRIMARY KEY,
    session_id  BIGINT NOT NULL REFERENCES ix_platform.peering_session (session_id),
    bytes_in    BIGINT,
    bytes_out   BIGINT,
    sampled_at  TIMESTAMP NOT NULL
);

CREATE VIEW ix_platform.v_active_sessions AS
    SELECT s.session_id, s.peer_id, p.peer_name
    FROM ix_platform.peering_session AS s
    JOIN ix_platform.peer AS p ON p.peer_id = s.peer_id
    WHERE s.status = 'ACTIVE';

CREATE FUNCTION ix_platform.fn_calculate_billing(p_session_id BIGINT)
    RETURNS NUMERIC AS $BODY$
DECLARE
    total NUMERIC;
BEGIN
    SELECT SUM(bytes_out) * 0.0001 INTO total
    FROM ix_platform.traffic_sample WHERE session_id = p_session_id;
    RETURN total;
END;
$BODY$ LANGUAGE plpgsql;

COMMENT ON TABLE ix_platform.peering_session IS 'Stores active BGP peering sessions for billing';

GRANT SELECT ON ix_platform.peering_session TO app_readwrite;
"""


def generate_demo():
    print("=" * 72)
    print("ORIGINAL DDL")
    print("=" * 72)
    print(DEMO_SQL)
    mapping = Mapping()
    dialect = detect_dialect(DEMO_SQL)
    print(f"[detected dialect: {dialect}]\n")
    output = sanitize_text(DEMO_SQL, dialect, mapping)
    print("=" * 72)
    print("SANITIZED DDL")
    print("=" * 72)
    print(output)
    print("=" * 72)
    print("MAPPING")
    print("=" * 72)
    print(json.dumps(mapping.to_json(), indent=2, ensure_ascii=False))
    print("=" * 72)
    print("SCHEMA SUMMARY (--summary)")
    print("=" * 72)
    print(build_summary([(output, dialect)], mapping))
    print("=" * 72)
    print_summary(mapping)
    warnings, leaks = verify_pass(output, mapping, dialect)
    if warnings:
        for w in warnings:
            print(f'[WARN] Possible unsanitized token: "{w}"', file=sys.stderr)
    if leaks:
        for l in leaks:
            print(f'[LEAK] Original token survived in output: "{l}"', file=sys.stderr)
        print("\nDEMO SELF-TEST FAILED: leaks detected.", file=sys.stderr)
        return 1
    # round-trip parseability
    try:
        sqlglot.parse(output, read=dialect)
        print("\nDEMO SELF-TEST PASSED: no leaks, output re-parses cleanly.", file=sys.stderr)
    except Exception as e:
        print(f"\nDEMO SELF-TEST WARNING: output did not re-parse: {e}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Strip company IP from PostgreSQL / Oracle DDL while keeping structure.")
    ap.add_argument("input", nargs="?",
                    help="input .sql file, directory (batch), or '-' for stdin")
    ap.add_argument("-o", "--output", help="output file, directory (batch), or '-' for stdout")
    ap.add_argument("-m", "--mapping", help="path to write the mapping JSON")
    ap.add_argument("--summary", metavar="PATH",
                    help="also write a dense schema-topology markdown (one combined file in "
                         "batch mode) for upload to a Claude Project knowledge base")
    ap.add_argument("--dialect", choices=("postgres", "oracle", "auto"), default="auto")
    ap.add_argument("--use-mapping", help="seed from an existing mapping for cross-run consistency")
    ap.add_argument("--strict-quoting", action="store_true",
                    help="never merge quoted and unquoted identifiers")
    ap.add_argument("--verify-strict", action="store_true",
                    help="exit non-zero on any [WARN], not just confirmed [LEAK]")
    ap.add_argument("--demo", action="store_true",
                    help="run the built-in self-test on fictional sample DDL")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.demo:
        return generate_demo()
    if not args.input:
        sys.stderr.write("ERROR: input is required (file, directory, or '-').\n")
        return 2

    if args.use_mapping:
        try:
            mapping = Mapping.load(args.use_mapping)
        except MappingError as exc:
            sys.stderr.write(f"ERROR: {exc}\n")
            return 2
        mapping.strict_quoting = args.strict_quoting or mapping.strict_quoting
    else:
        mapping = Mapping(strict_quoting=args.strict_quoting)

    is_batch = Path(args.input).is_dir() if args.input != "-" else False
    all_output = []
    any_leak = any_warn = False

    for name, text in iter_inputs(args.input):
        dialect = detect_dialect(text) if args.dialect == "auto" else args.dialect
        output = sanitize_text(text, dialect, mapping)
        all_output.append((name, output, dialect))
        target = write_output(args.output, name, output, is_batch)
        warnings, leaks = verify_pass(output, mapping, dialect)
        for w in warnings:
            sys.stderr.write(f'[WARN] Possible unsanitized token: "{w}" (in {name})\n')
            any_warn = True
        for l in leaks:
            sys.stderr.write(f'[LEAK] Original token survived: "{l}" (in {name})\n')
            any_leak = True
        if target and args.output not in (None, "-"):
            sys.stderr.write(f"Output written to: {target}\n")

    if args.mapping:
        mapping.dump(args.mapping)
        sys.stderr.write(f"Mapping written to: {args.mapping}\n")

    if args.summary:
        summary_md = build_summary(((o, d) for _n, o, d in all_output), mapping)
        Path(args.summary).write_text(summary_md, encoding="utf-8")
        sys.stderr.write(f"Summary written to: {args.summary}\n")

    print_summary(mapping)

    if any_leak:
        return 1
    if any_warn and args.verify_strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
