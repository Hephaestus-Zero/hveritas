"""Independent SQLite database state and delta probe (Invariant I3)."""

from __future__ import annotations

import base64
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hveritas.ledger.canonical import canonical_json, sha256_hex


@dataclass(frozen=True)
class TableSnapshot:
    row_count: int
    table_hash: str
    rows_by_key: dict[str, str]


def _encode_sql_val(val: Any) -> Any:
    if isinstance(val, bytes):
        return {"__b64__": base64.b64encode(val).decode("ascii")}
    return val


class SqliteDbProbe:
    """Inspects workspace `.sqlite` / `.db` files directly via read-only SQLite connections."""

    DB_SUFFIXES = (".sqlite", ".sqlite3", ".db")

    def snapshot_workspace_dbs(self, workspace: Path) -> dict[str, dict[str, TableSnapshot]]:
        root = workspace.resolve()
        result: dict[str, dict[str, TableSnapshot]] = {}
        if not root.exists():
            return result

        db_files = sorted(
            p
            for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in self.DB_SUFFIXES and ".git" not in p.parts
        )
        for db_path in db_files:
            rel = db_path.relative_to(root).as_posix()
            snaps = self._snapshot_single_db(db_path)
            if snaps is not None:
                result[rel] = snaps
        return result

    def _snapshot_single_db(self, db_path: Path) -> dict[str, TableSnapshot] | None:
        try:
            uri = f"file:{db_path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
        except sqlite3.Error:
            return None

        try:
            tables_rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC"
            ).fetchall()
            out: dict[str, TableSnapshot] = {}
            for (tbl_name,) in tables_rows:
                quoted = '"' + str(tbl_name).replace('"', '""') + '"'
                col_info = conn.execute(f"PRAGMA table_info({quoted})").fetchall()
                col_names = [str(c[1]) for c in col_info]
                rows = conn.execute(f"SELECT rowid, * FROM {quoted} ORDER BY rowid ASC").fetchall()
                rows_by_key: dict[str, str] = {}
                serial_rows: list[dict[str, Any]] = []
                for r in rows:
                    rowid = str(r[0])
                    row_dict = {
                        col_names[i]: _encode_sql_val(r[i + 1]) for i in range(len(col_names))
                    }
                    row_json = canonical_json(row_dict)
                    rows_by_key[rowid] = sha256_hex(row_json)
                    serial_rows.append({"rowid": rowid, "cols": row_dict})
                out[str(tbl_name)] = TableSnapshot(
                    row_count=len(rows),
                    table_hash=sha256_hex(canonical_json(serial_rows)),
                    rows_by_key=rows_by_key,
                )
            return out
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def diff(
        self,
        pre: dict[str, dict[str, TableSnapshot]],
        post: dict[str, dict[str, TableSnapshot]],
    ) -> dict[str, Any]:
        all_dbs = sorted(set(pre.keys()) | set(post.keys()))
        delta: dict[str, Any] = {}
        for db_rel in all_dbs:
            t_pre = pre.get(db_rel, {})
            t_post = post.get(db_rel, {})
            pre_names = set(t_pre.keys())
            post_names = set(t_post.keys())
            tables_added = sorted(post_names - pre_names)
            tables_deleted = sorted(pre_names - post_names)
            tables_changed: dict[str, Any] = {}

            for tbl in sorted(post_names):
                s_before = t_pre.get(tbl)
                s_after = t_post[tbl]
                if s_before is None:
                    tables_changed[tbl] = {
                        "rows_before": 0,
                        "rows_after": s_after.row_count,
                        "inserted_rowids": sorted(s_after.rows_by_key.keys()),
                        "deleted_rowids": [],
                        "updated_rowids": [],
                    }
                elif s_before.table_hash != s_after.table_hash:
                    k_pre = set(s_before.rows_by_key.keys())
                    k_post = set(s_after.rows_by_key.keys())
                    inserted = sorted(k_post - k_pre)
                    deleted = sorted(k_pre - k_post)
                    updated = sorted(
                        k
                        for k in (k_pre & k_post)
                        if s_before.rows_by_key[k] != s_after.rows_by_key[k]
                    )
                    tables_changed[tbl] = {
                        "rows_before": s_before.row_count,
                        "rows_after": s_after.row_count,
                        "inserted_rowids": inserted,
                        "deleted_rowids": deleted,
                        "updated_rowids": updated,
                    }

            if tables_added or tables_deleted or tables_changed:
                delta[db_rel] = {
                    "tables_added": tables_added,
                    "tables_deleted": tables_deleted,
                    "tables_changed": tables_changed,
                }
        return delta
