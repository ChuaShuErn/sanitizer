"""Tests for sanitize_ddl.py.

Run with:  ../.venv/bin/python -m pytest -q   (from the tests/ dir)
       or:  .venv/bin/python -m pytest -q     (from the project root)
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sanitize_ddl as S  # noqa: E402


# --------------------------------------------------------------------------- helpers
def sanitize(sql, dialect="postgres", mapping=None):
    m = mapping or S.Mapping()
    out = S.sanitize_text(sql, dialect, m)
    return out, m


def all_originals(m):
    vals = set()
    for c in S.CATEGORIES:
        vals.update(m.rev[c].values())
    return vals


# --------------------------------------------------------------------------- tests
def test_basic_table_sanitized_and_no_leak():
    sql = "CREATE TABLE peering_session (asn_number BIGINT NOT NULL, status VARCHAR(20));"
    out, m = sanitize(sql)
    assert "peering_session" not in out and "asn_number" not in out and "status" not in out
    assert m.rev["tables"] == {"table_001": "peering_session"}
    _, leaks = S.verify_pass(out, m, "postgres")
    assert leaks == []


def test_data_types_preserved():
    sql = ("CREATE TABLE t (a VARCHAR(255), b NUMERIC(10,2), c JSONB, d BYTEA, "
           "e TIMESTAMP, f BIGINT);")
    out, _ = sanitize(sql)
    for typ in ("VARCHAR(255)", "JSONB", "BYTEA", "TIMESTAMP", "BIGINT"):
        assert typ in out
    assert "DECIMAL(10, 2)" in out or "NUMERIC(10, 2)" in out  # NUMERIC≡DECIMAL


def test_oracle_types_preserved():
    sql = "CREATE TABLE t (a NUMBER(10), b VARCHAR2(20), c CLOB, d NUMBER(14,2));"
    out, _ = sanitize(sql, dialect="oracle")
    for typ in ("NUMBER(10)", "VARCHAR2(20)", "CLOB", "NUMBER(14, 2)"):
        assert typ in out


def test_fk_relationship_preserved_and_consistent():
    sql = (
        "CREATE TABLE customers (id INT PRIMARY KEY);\n"
        "CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT "
        "REFERENCES customers(id) ON DELETE CASCADE);"
    )
    out, m = sanitize(sql)
    customers_ph = [k for k, v in m.rev["tables"].items() if v == "customers"][0]
    # the FK target in orders must use the SAME placeholder as the customers table def
    assert f"REFERENCES {customers_ph}" in out
    assert "ON DELETE CASCADE" in out


def test_deterministic_mapping_same_name_same_placeholder():
    sql = (
        "CREATE TABLE a (customer_id INT);\n"
        "CREATE TABLE b (customer_id INT, note TEXT);"
    )
    out, m = sanitize(sql)
    # customer_id appears in both tables -> one placeholder
    cust_phs = [k for k, v in m.rev["columns"].items() if v == "customer_id"]
    assert len(cust_phs) == 1
    assert out.count(cust_phs[0]) == 2


def test_determinism_across_runs():
    sql = "CREATE TABLE t (a INT, b INT, CONSTRAINT c UNIQUE (a, b));"
    out1, m1 = sanitize(sql)
    out2, m2 = sanitize(sql)
    assert out1 == out2
    assert m1.to_json() == m2.to_json()


def test_pg_case_folding_unquoted():
    sql = 'CREATE TABLE MyTable (Col INT);\nCREATE INDEX i ON mytable (col);'
    out, m = sanitize(sql, dialect="postgres")
    # MyTable and mytable fold to the same identifier
    assert len(m.rev["tables"]) == 1
    assert len(m.rev["columns"]) == 1


def test_oracle_case_folding_uppercase():
    sql = 'CREATE TABLE MyTable (Col INT);\nCREATE INDEX i ON MYTABLE (COL);'
    out, m = sanitize(sql, dialect="oracle")
    assert len(m.rev["tables"]) == 1
    assert len(m.rev["columns"]) == 1


def test_quoted_identifier_preserved_and_sanitized():
    sql = 'CREATE TABLE "Weird Name" ("Col With Space" INT);'
    out, m = sanitize(sql)
    assert "Weird Name" not in out and "Col With Space" not in out
    assert '"table_001"' in out  # quoting style preserved


def test_table_vs_column_namespacing():
    sql = "CREATE TABLE status (status INT);"
    out, m = sanitize(sql)
    assert "status" not in out
    assert m.rev["tables"] == {"table_001": "status"}
    assert m.rev["columns"] == {"col_001": "status"}


def test_string_literal_policy():
    sql = ("CREATE TABLE t (status VARCHAR(20) DEFAULT 'PENDING_REVIEW', "
           "n INT DEFAULT 0, b BOOLEAN DEFAULT true, "
           "CONSTRAINT c CHECK (status IN ('ACTIVE','DISABLED')));")
    out, m = sanitize(sql)
    assert "PENDING_REVIEW" not in out and "ACTIVE" not in out and "DISABLED" not in out
    assert "DEFAULT 0" in out            # numeric default kept
    assert "DEFAULT TRUE" in out.upper() # boolean default kept
    assert "PENDING_REVIEW" in m.rev["string_defaults"].values()
    assert {"ACTIVE", "DISABLED"} <= set(m.rev["enum_values"].values())


def test_enum_value_consistency_across_objects():
    sql = (
        "CREATE TYPE st AS ENUM ('ACTIVE','PENDING');\n"
        "CREATE TABLE t (s VARCHAR(10), CHECK (s IN ('ACTIVE','PENDING')));"
    )
    out, m = sanitize(sql)
    active_ph = [k for k, v in m.rev["enum_values"].items() if v == "ACTIVE"]
    assert len(active_ph) == 1
    assert out.count(active_ph[0]) == 2  # used in the type AND the check


def test_comments_stripped():
    sql = (
        "-- a leading comment about billing\n"
        "CREATE TABLE t (a INT /* inline secret */);\n"
        "COMMENT ON TABLE t IS 'business description here';"
    )
    out, m = sanitize(sql)
    for leak in ("billing", "secret", "business description"):
        assert leak not in out


def test_function_body_removed_signature_kept():
    sql = (
        "CREATE FUNCTION fn_calc(p_id BIGINT) RETURNS NUMERIC AS $$\n"
        "  SELECT secret_value FROM secret_table WHERE id = p_id;\n"
        "$$ LANGUAGE plpgsql;"
    )
    out, m = sanitize(sql)
    assert "secret_value" not in out and "secret_table" not in out
    assert "sanitized" in out                      # body-removed marker present
    assert "RETURNS" in out.upper()                # signature kept
    assert m.rev["functions"] == {"func_001": "fn_calc"}


def test_schema_qualified_names():
    sql = "CREATE TABLE myschema.mytable (mycol INT);"
    out, m = sanitize(sql)
    assert m.rev["schemas"] == {"schema_001": "myschema"}
    assert m.rev["tables"] == {"table_001": "mytable"}
    assert "schema_001.table_001" in out


def test_use_mapping_continuity():
    sql1 = "CREATE TABLE customers (id INT, customer_name VARCHAR(50));"
    sql2 = "CREATE TABLE orders (id INT, customer_id INT REFERENCES customers(id));"
    out1, m1 = sanitize(sql1)
    cust_ph = [k for k, v in m1.rev["tables"].items() if v == "customers"][0]
    out2, m2 = sanitize(sql2, mapping=m1)  # reuse same mapping object == --use-mapping
    assert f"REFERENCES {cust_ph}" in out2
    assert m2.rev["tables"][cust_ph] == "customers"  # unchanged


def test_use_mapping_roundtrip_via_json(tmp_path):
    m = S.Mapping()
    S.sanitize_text('CREATE TABLE "MixedCase" (id INT);', "postgres", m)
    p = tmp_path / "m.json"
    m.dump(p)
    m2 = S.Mapping.load(p)
    # quoted MixedCase must keep its placeholder + key on reload
    out, _ = sanitize('CREATE INDEX i ON "MixedCase" (id);', mapping=m2)
    assert m2.rev["tables"] == m.rev["tables"]


def test_oracle_tablespace_table_fallback():
    sql = ("CREATE TABLE billing.acct (id NUMBER(12), amt NUMBER(14,2) DEFAULT 0) "
           "TABLESPACE ts_data STORAGE (INITIAL 64K NEXT 1M);")
    out, m = sanitize(sql, dialect="oracle")
    assert "billing" not in out and "acct" not in out and "ts_data" not in out
    assert "64K" in out and "1M" in out        # storage units intact
    assert "NUMBER(12)" in out
    assert m.rev["tablespaces"] == {"tspace_001": "ts_data"}
    _, leaks = S.verify_pass(out, m, "oracle")
    assert leaks == []


def test_oracle_plsql_body_gutted():
    sql = (
        "CREATE OR REPLACE PROCEDURE apply_fee(p_id NUMBER) IS\n"
        "  v NUMBER := 25;\n"
        "BEGIN\n"
        "  UPDATE secret_audit SET x = secret_logic WHERE id = p_id;\n"
        "END;\n/\n"
    )
    out, m = sanitize(sql, dialect="oracle")
    assert "secret_audit" not in out and "secret_logic" not in out
    assert "sanitized" in out
    assert m.rev["functions"] == {"func_001": "apply_fee"}


def test_grant_role_sanitized():
    sql = "GRANT SELECT, UPDATE ON peering_session TO app_readwrite;"
    out, m = sanitize(sql)
    assert "app_readwrite" not in out
    assert "SELECT" in out.upper()  # privilege kept
    assert "app_readwrite" in m.rev["roles"].values()


def test_view_aliases_kept_columns_sanitized():
    sql = ("CREATE VIEW v AS SELECT t.peer_name FROM peering_session AS t "
           "WHERE t.status = 'ACTIVE';")
    out, m = sanitize(sql)
    assert "peer_name" not in out and "peering_session" not in out
    assert " AS t" in out and "t." in out  # alias preserved
    assert "peer_name" in m.rev["columns"].values()


def test_mapping_completeness_every_placeholder_in_mapping():
    sql = S.DEMO_SQL
    out, m = sanitize(sql)
    placeholders_in_output = set(S.re.findall(r"\b[a-z_]+_\d{3,}\b", out))
    known = set()
    for c in S.CATEGORIES:
        known.update(m.rev[c].keys())
    missing = placeholders_in_output - known
    assert missing == set(), f"placeholders not in mapping: {missing}"


def test_partial_index_where_sanitized():
    sql = ("CREATE INDEX idx_active ON sessions USING btree (peer_id) "
           "WHERE status = 'ACTIVE';")
    out, m = sanitize(sql)
    assert "ACTIVE" not in out and "sessions" not in out and "peer_id" not in out
    assert "USING btree" in out  # index method preserved


def test_no_leak_on_full_demo():
    out, m = sanitize(S.DEMO_SQL)
    _, leaks = S.verify_pass(out, m, "postgres")
    assert leaks == []


def test_dialect_autodetect():
    assert S.detect_dialect("CREATE TABLE t (a VARCHAR2(20), b NUMBER(10));") == "oracle"
    assert S.detect_dialect("CREATE TABLE t (a JSONB, b SERIAL);") == "postgres"


# --------------------------------------------------------------------------- audit regressions
def test_audit_L1_q_quote_default_not_leaked():
    sql = "CREATE TABLE t (a VARCHAR2(50) DEFAULT q'[ACME Corp Internal]') TABLESPACE ts1;"
    out, m = sanitize(sql, dialect="oracle")
    assert "ACME" not in out and "q'[" not in out
    _, leaks = S.verify_pass(out, m, "oracle")
    assert leaks == []


def test_audit_L2_keyword_colliding_columns_sanitized_in_fallback():
    # function/keyword-named columns in a TABLESPACE (fallback) table must still be scrubbed
    sql = ("CREATE TABLE server_inventory (host VARCHAR2(255), rank NUMBER, "
           "name VARCHAR2(10), value NUMBER) TABLESPACE infra_ts;")
    out, m = sanitize(sql, dialect="oracle")
    for leak in ("host", "rank", "server_inventory"):
        assert not S.re.search(rf"(?<![\w]){leak}(?![\w])", out, S.re.IGNORECASE), f"{leak} leaked"
    assert out.count("VARCHAR2(255)") == 1  # the type is preserved


def test_audit_L3_non_ascii_identifiers_whole_and_storage_kept():
    sql = ("CREATE TABLE müller_data (id NUMBER, café_name VARCHAR2(100)) "
           "TABLESPACE users_ts STORAGE (INITIAL 64K NEXT 1M MAXEXTENTS 121 FREELISTS 4);")
    out, m = sanitize(sql, dialect="oracle")
    assert "müller" not in out and "café" not in out
    assert "INITIAL 64K NEXT 1M MAXEXTENTS 121 FREELISTS 4" in out  # storage clause intact


def test_audit_L4_unterminated_string_no_leak():
    out, m = sanitize("CREATE TABLE accounts (note text DEFAULT 'Confidential ACME data);")
    assert "Confidential" not in out and "ACME" not in out


def test_audit_S1_lone_slash_after_semicolon_keeps_next_statement():
    sql = ("CREATE TYPE finance.money_obj AS OBJECT (amount NUMBER);\n/\n"
           "CREATE TABLE finance.secret_ledger (id NUMBER) TABLESPACE ledger_ts;")
    out, m = sanitize(sql, dialect="oracle")
    assert "secret_ledger" not in out
    assert out.count("CREATE TABLE") == 1   # the table wasn't swallowed
    assert "secret_ledger" in m.rev["tables"].values()


def test_audit_X1_partition_key_consistent_with_column():
    sql = ("CREATE TABLE sales (id NUMBER, region VARCHAR2(20)) "
           "PARTITION BY LIST (region) (PARTITION p_west VALUES ('X')) TABLESPACE ts1;")
    out, m = sanitize(sql, dialect="oracle")
    region_ph = [k for k, v in m.rev["columns"].items() if v == "region"][0]
    assert f"PARTITION BY LIST ({region_ph})" in out      # key uses the column placeholder
    assert "p_west" in m.rev["partitions"].values()        # the partition NAME is a partition


def test_audit_X2_domain_reused_as_column_type():
    sql = ("CREATE DOMAIN us_zip AS TEXT;\n"
           "CREATE TABLE addr (id INT, zip us_zip);")
    out, m = sanitize(sql, dialect="postgres")
    zip_ph = [k for k, v in m.rev["domains"].items() if v == "us_zip"][0]
    assert f"zip" not in out
    assert out.count(zip_ph) == 2  # declaration + the column type reference agree


def test_audit_X3_function_call_placeholder_matches_mapping_case():
    sql = "CREATE VIEW r AS SELECT compute_score(amount) AS s FROM txns;"
    out, m = sanitize(sql)
    func_ph = list(m.rev["functions"].keys())[0]
    assert func_ph in out                    # lowercase placeholder, exactly as in mapping
    assert func_ph.upper() not in out        # not the uppercased FUNC_001 form


def test_audit_S4_returns_trigger_function_body_gutted():
    sql = ("CREATE OR REPLACE FUNCTION upd_ts() RETURNS trigger AS $$ "
           "BEGIN UPDATE secret_t SET x=secret_c; RETURN NEW; END; $$ LANGUAGE plpgsql;")
    out, m = sanitize(sql, dialect="postgres")
    assert "secret_t" not in out and "secret_c" not in out
    assert "sanitized" in out and "plpgsql" in out   # body gone, language kept
    assert "SQLSANBODY" not in out                    # sentinel fully restored


def test_audit_C2_bad_use_mapping_clean_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not valid json {{{")
    assert S.main(["-", "--use-mapping", str(bad), "-o", "-"]) == 2  # clean exit, no traceback
    with pytest.raises(S.MappingError):
        S.Mapping.load(tmp_path / "missing.json")


def test_audit_qualified_function_call_schema_consistent():
    sql = ("CREATE SCHEMA audit;\n"
           "CREATE TRIGGER trg AFTER UPDATE ON app.res FOR EACH ROW "
           "EXECUTE FUNCTION audit.log_change();")
    out, m = sanitize(sql)
    audit_ph = [k for k, v in m.rev["schemas"].items() if v == "audit"][0]
    assert f"{audit_ph}.func_" in out or f"{audit_ph}." in out  # qualifier == schema decl
    assert "audit" not in m.rev["columns"].values()             # not mis-mapped as a column


def test_structural_json_default_preserved():
    out, m = sanitize("CREATE TABLE t (a JSONB DEFAULT '{}', b INT[] DEFAULT '{}');")
    assert "DEFAULT '{}'" in out
    assert "{}" not in m.rev["string_defaults"].values()


def test_non_utf8_file_decodes(tmp_path):
    p = tmp_path / "latin1.sql"
    p.write_bytes("CREATE TABLE café (id int);".encode("latin-1"))
    text = S._read_text(p)
    out, m = sanitize(text)
    assert "café" not in out and m.rev["tables"] == {"table_001": "café"}


# --------------------------------------------------------------------------- re-audit regressions
def test_reaudit_keyword_columns_in_fallback_keylist_sanitized():
    # the LEAK class: keyword-spelled columns in an index / key column list (fallback path)
    sql = ("CREATE TABLE metrics (metric_id NUMBER, value NUMBER, cache VARCHAR2(10), "
           "comment VARCHAR2(50)) TABLESPACE app_ts;\n"
           "CREATE INDEX ix ON metrics (value, cache, comment) TABLESPACE app_ts;")
    out, m = sanitize(sql, dialect="oracle")
    for kw in ("value", "cache", "comment", "metrics"):
        assert not S.re.search(rf"(?<![\w]){kw}(?![\w])", out, S.re.IGNORECASE), f"{kw} leaked"
    # the same column keeps one placeholder across the table def and the index
    value_ph = [k for k, v in m.rev["columns"].items() if v == "value"][0]
    assert out.count(value_ph) == 2


def test_reaudit_fk_action_keywords_preserved_in_fallback():
    sql = ("CREATE TABLE c (id NUMBER, p NUMBER, FOREIGN KEY (p) REFERENCES par(x) "
           "ON DELETE CASCADE ON UPDATE SET NULL) TABLESPACE ts1;")
    out, m = sanitize(sql, dialect="oracle")
    assert "ON DELETE CASCADE" in out and "ON UPDATE SET NULL" in out
    assert "DELETE" not in m.rev["tables"].values()  # not mangled into a table placeholder


def test_reaudit_storage_keywords_preserved():
    sql = ("CREATE TABLE t (id NUMBER) TABLESPACE ts1 "
           "STORAGE (INITIAL 64K NEXT 1M BUFFER_POOL KEEP) ENABLE ROW MOVEMENT;")
    out, m = sanitize(sql, dialect="oracle")
    assert "ENABLE ROW MOVEMENT" in out
    assert "BUFFER_POOL KEEP" in out


def test_reaudit_nested_check_function_args_sanitized():
    # a column referenced inside a function call inside a CHECK (fallback path) must be
    # sanitized and consistent with its declaration; the function name is kept.
    sql = ("CREATE TABLE t (name VARCHAR2(20), "
           "CONSTRAINT ck CHECK (LENGTH(name) > 5 AND value > 0)) TABLESPACE ts1;")
    out, m = sanitize(sql, dialect="oracle")
    name_ph = [k for k, v in m.rev["columns"].items() if v == "name"][0]
    assert f"LENGTH({name_ph})" in out          # function kept, column sanitized
    assert not S.re.search(r"(?<![\w])name(?![\w])", out)  # 'name' gone everywhere


def test_summary_sections_and_topology():
    sql = (
        "CREATE TYPE status_t AS ENUM ('ACTIVE','CLOSED');\n"
        "CREATE TABLE app.peer (peer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "
        "peer_name VARCHAR(100) NOT NULL, st status_t);\n"
        "CREATE TABLE app.session (sid BIGINT PRIMARY KEY, "
        "peer_id BIGINT REFERENCES app.peer(peer_id) ON DELETE CASCADE);\n"
        "CREATE INDEX idx_pn ON app.peer USING btree (peer_name);\n"
        "CREATE VIEW v_active AS SELECT s.sid, p.peer_name FROM app.session s "
        "JOIN app.peer p ON p.peer_id = s.peer_id WHERE p.st = 'ACTIVE';"
    )
    m = S.Mapping()
    out = S.sanitize_text(sql, "postgres", m)
    summary = S.build_summary([(out, "postgres")], m)

    # only sanitized names — no originals anywhere
    for orig in ("peer", "session", "status_t", "peer_name", "v_active", "ACTIVE", "app"):
        assert not S.re.search(rf"(?<![\w]){orig}(?![\w])", summary), f"{orig} leaked into summary"

    # required sections
    for section in ("# Schema Summary", "## Overview", "## Relationships",
                    "## Views", "## Custom Types"):
        assert section in summary

    # overview stats
    assert "- Tables: 2" in summary
    assert "- Foreign keys: 1" in summary
    assert "- Indexes: 1" in summary

    # table block + FK topology (resolve placeholders from the mapping)
    peer = [k for k, v in m.rev["tables"].items() if v == "peer"][0]
    session = [k for k, v in m.rev["tables"].items() if v == "session"][0]
    assert f"## {peer} (" in summary
    assert f"PK: " in summary and "GENERATED ALWAYS AS IDENTITY" in summary
    assert f"{session} → {peer}" in summary                 # relationship edge
    assert S.re.search(rf"FKs out:.*→ {peer}\.", summary)   # FK out with target
    assert S.re.search(rf"FKs in:.*{session}\.", summary)   # reverse edge on peer
    assert "BTREE(" in summary                              # index method
    # views + enum registry use placeholders
    assert S.re.search(r"view_\d+: reads ", summary)
    assert S.re.search(r"type_\d+: val_\d+, val_\d+", summary)


def test_summary_oracle_tablespace_table_via_reduction():
    # an Oracle TABLESPACE table parses as Command; the summary must still recover its
    # columns/PK via structural reduction.
    sql = ("CREATE TABLE fin.acct (acct_id NUMBER(12) PRIMARY KEY, bal NUMBER(14,2)) "
           "TABLESPACE ts1 STORAGE (INITIAL 64K);")
    m = S.Mapping()
    out = S.sanitize_text(sql, "oracle", m)
    summary = S.build_summary([(out, "oracle")], m)
    assert "- Tables: 1" in summary
    assert "(2 columns)" in summary
    assert "NUMBER(12)" in summary or "NUMBER(14, 2)" in summary
    assert "acct" not in summary and "fin" not in summary


def test_summary_use_mapping_consistency(tmp_path):
    # --summary must use the same placeholders as the mapping (incl. seeded --use-mapping)
    m = S.Mapping()
    S.sanitize_text("CREATE TABLE customers (id INT PRIMARY KEY);", "postgres", m)
    cust = [k for k, v in m.rev["tables"].items() if v == "customers"][0]
    out = S.sanitize_text(
        "CREATE TABLE orders (id INT, cid INT REFERENCES customers(id));", "postgres", m)
    summary = S.build_summary([(out, "postgres")], m)
    assert f"→ {cust}" in summary  # FK target uses the seeded customers placeholder


def test_reaudit_oracle_procedure_skeleton_clean():
    sql = ("CREATE OR REPLACE PROCEDURE secret_proc(p_in NUMBER) IS\n"
           "BEGIN\n  secret_logic();\nEND;\n/")
    out, m = sanitize(sql, dialect="oracle")
    assert "secret_proc" not in out and "secret_logic" not in out and "p_in" not in out
    assert "$$" not in out                       # no PostgreSQL body syntax in Oracle output
    assert "IS" not in m.rev["columns"].values()  # no bogus IS column
    assert "sanitized" in out and out.rstrip().endswith("/")
