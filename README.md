# sanitize_ddl.py

A local, single-file Python CLI that strips company intellectual property from **PostgreSQL**
and **Oracle** DDL while preserving the structural skeleton — so you can safely share a schema
with external AI tools, colleagues, or forums without leaking proprietary database design.

Every business-meaningful identifier (schema, table, column, index, constraint, sequence, view,
materialized view, function/procedure, trigger, type/enum, domain, partition, tablespace, role)
is replaced with a deterministic generic placeholder (`table_001`, `col_001`, …). Comments,
string-literal data, enum values and function bodies are stripped, while data types, keys,
foreign-key relationships, index methods and partitioning are kept intact. A reverse-lookup
`mapping.json` records every replacement.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt      # just sqlglot
```

## Usage

```bash
# single file
python sanitize_ddl.py input.sql -o sanitized.sql -m mapping.json

# batch a directory of .sql files into an output directory (shared mapping)
python sanitize_ddl.py ./ddl_folder/ -o ./sanitized_output/ -m mapping.json

# stdin -> stdout
cat schema.sql | python sanitize_ddl.py - -o - -m mapping.json

# force a dialect (default is auto-detect)
python sanitize_ddl.py input.sql --dialect oracle -o sanitized.sql -m mapping.json

# reuse a previous mapping so shared identifiers keep the same placeholder across runs
python sanitize_ddl.py new_migration.sql --use-mapping mapping.json \
    -o sanitized_migration.sql -m mapping_updated.json

# also emit a dense schema-topology markdown (for a Claude Project knowledge base)
python sanitize_ddl.py input.sql -o sanitized.sql -m mapping.json --summary summary.md
# batch mode writes ONE combined summary across all files
python sanitize_ddl.py ./ddl_folder/ -o ./sanitized_output/ -m mapping.json --summary summary.md

# self-test on built-in fictional sample DDL (prints input, output and mapping)
python sanitize_ddl.py --demo
```

### Flags

| Flag | Meaning |
|------|---------|
| `input` | `.sql` file, directory (batch mode), or `-` for stdin |
| `-o, --output` | output file, directory (batch), or `-` for stdout |
| `-m, --mapping` | path to write the reverse-lookup mapping JSON |
| `--summary PATH` | also write a dense schema-topology markdown (one combined file in batch mode) |
| `--dialect` | `postgres`, `oracle`, or `auto` (default) |
| `--use-mapping PATH` | seed from an existing mapping for cross-run consistency |
| `--strict-quoting` | never merge quoted and unquoted identifiers (engine-exact) |
| `--verify-strict` | exit non-zero on any `[WARN]`, not only confirmed `[LEAK]` |
| `--demo` | run the built-in self-test |

## What gets sanitized vs preserved

**Sanitized** — every identifier and piece of business content: schema/table/column/index/
constraint/sequence/view/mview/function/trigger/type/domain/partition/tablespace/role names,
enum values, string-literal defaults and comparison values, comments (`--`, `/* */`,
`COMMENT ON`), and function/procedure bodies (replaced with `/* sanitized — logic removed */`).

**Preserved** — the structural skeleton: data types exactly (`VARCHAR(255)`, `NUMERIC(10,2)`,
`JSONB`, `NUMBER(10)`, `CLOB`, …), `NULL`/`NOT NULL`, PRIMARY/FOREIGN/UNIQUE/CHECK constraint
*types* (names are replaced, semantics kept), FK relationships (the sanitized link is preserved),
`ON DELETE/UPDATE` actions, identity/serial, index methods (`USING gin`/`btree`/…), partial-index
`WHERE` structure, column ordering, `PARTITION BY`, Oracle `TABLESPACE`/`STORAGE`, and numeric/
boolean/timestamp defaults (`DEFAULT 0`, `DEFAULT true`, `DEFAULT CURRENT_TIMESTAMP`).

## Output

1. **Sanitized SQL** — valid in the same dialect, re-executable to create the skeleton.
2. **`mapping.json`** — grouped by category for reverse lookup, e.g.

   ```json
   {
     "schemas":  { "schema_001": "ix_platform" },
     "tables":   { "table_001": "peering_session" },
     "columns":  { "col_001": "asn_number" },
     "enum_values": { "val_001": "ACTIVE" }
   }
   ```

   (A hidden `_keys`/`_meta` block records the canonical lookup keys so `--use-mapping` stays
   exact for quoted/mixed-case identifiers.)
3. **stdout summary** — `Sanitized: 12 tables, 87 columns, 15 indexes, …`.
4. **`--summary` markdown** (optional) — a dense, self-contained schema topology using only
   sanitized names, designed to upload to a Claude Project as a fast-to-parse structural
   overview. Built by re-parsing the sanitized output, so it never sees an original name.
   Sections: **Overview** (counts), a per-table catalog (`## table_001 (N columns)` with PK,
   columns, FKs out/in, indexes, unique), **Relationships** (FK adjacency list), **Views**
   (which tables each view reads + join columns), and **Custom Types** (enum value registry).
   In batch mode one combined topology is emitted across every file.

## How it works

Parsing is done with [sqlglot](https://github.com/tobymao/sqlglot). Each statement is sanitized on
its AST (identifiers classified by their node position, not by name, so a name used as both a
table and a column gets independent placeholders). A segment-aware regex/tokenizer **fallback**
handles statements sqlglot can only parse as an opaque `Command` — Oracle `TABLESPACE`/`STORAGE`/
partition-def tables and indexes, PG `DOMAIN`, and PL/SQL blocks — guaranteeing no non-reserved
original token survives there either. A final **leak-verification pass** re-parses the output and
runs a raw-substring backstop over every stored original; surviving business tokens are reported
as `[LEAK]` (a hard failure), suspicious-but-unconfirmed ones as `[WARN]`.

## Quality / verification

```bash
.venv/bin/python sanitize_ddl.py --demo     # self-test: no leaks + output re-parses
.venv/bin/python -m pytest -q               # ~25 tests
```

## Verification

A leak-verification pass runs after every file. `[LEAK]` (a confirmed original token surviving in
the output) is a hard failure and sets a non-zero exit code; `[WARN]` flags a suspicious-but-
unconfirmed token (use `--verify-strict` to fail on those too). The AST path is the primary path
and is leak-clean; the regex fallback (below) is covered by a raw-substring backstop.

## Known limitations

- **Output is normalized**, not byte-for-byte preserved: sqlglot regenerates AST-parsed statements,
  so whitespace is reformatted and some type spellings are canonicalized to equivalents
  (`INTEGER`→`INT`, `NUMERIC`→`DECIMAL`, `BIGSERIAL`→`GENERATED … AS IDENTITY`). Statements that go
  through the fallback path keep their original layout.
- **Oracle PL/SQL** (procedures, functions, packages, triggers) is reduced to a *signature +
  body-removed comment* skeleton; sqlglot cannot fully parse PL/SQL, so the gutted Oracle block is
  not guaranteed to re-execute (PostgreSQL function skeletons remain valid `$$ … $$` bodies).
  PL/SQL terminated only by `;` (no `/`) is best-effort; use the standard `/` terminator.
- **Regex fallback edge case:** statements sqlglot can only parse as an opaque `Command` (Oracle
  `TABLESPACE`/`STORAGE`/partition-def tables & indexes, PG `DOMAIN`, PL/SQL) are sanitized by a
  position-aware tokenizer. It scrubs identifiers in column definitions, key/index/`CHECK` lists,
  qualified names and after object keywords. A business identifier that *exactly spells a SQL
  keyword/type* (e.g. a column literally named `date`) **and** sits in an unusual fallback position
  (e.g. a partial-index `WHERE` on a tablespace table) may be kept — the AST path always renames
  these, and the backstop will report it as `[WARN]`/`[LEAK]`. Fallback `CHECK`/`IN` string values
  are recorded under `string_defaults` rather than `enum_values`.
- **Liquibase XML** input is not supported in this version (planned follow-up).
