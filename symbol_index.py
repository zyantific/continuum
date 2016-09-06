# -*- coding: utf-8 -*-
"""
    This file is part of the continuum IDA PRO plugin (see zyantific.com).

    The MIT License (MIT)

    Copyright (c) 2016 Joel Hoener <athre0z@zyantific.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

from __future__ import absolute_import, print_function, division

import sqlite3
import idaapi
from idc import *


class SymbolIndex(object):
    INDEX_DB_NAME = 'index.db'

    def __init__(self, project):
        self.db = sqlite3.connect(os.path.join(project.meta_dir, self.INDEX_DB_NAME))
        self.db.row_factory = sqlite3.Row
        self.create_schema()

    def create_schema(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='binary'")

        # Schema already good? Skip.
        if cursor.fetchone():
            return

        # Nope, create schema now.
        cursor.executescript("""
            CREATE TABLE binary (
                id          INTEGER PRIMARY KEY,
                idb_path    TEXT NOT NULL UNIQUE,
                input_file  TEXT NOT NULL
            );

            CREATE TABLE export (
                id          INTEGER PRIMARY KEY,
                binary_id   INTEGER NOT NULL,
                name        TEXT NOT NULL,
                FOREIGN KEY(binary_id) REFERENCES binary(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE
            );

            CREATE INDEX idx_export_name ON export(name);

            /*CREATE TABLE xrefs (
                id          INTEGER PRIMARY KEY,
                export_id   INTEGER NOT NULL,
                binary_id   INTEGER NOT NULL,
                FOREIGN KEY(export_id) REFERENCES export(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE,
                FOREIGN KEY(binary_id) REFERENCES binary(id)
                    ON UPDATE CASCADE
                    ON DELETE CASCADE
            );*/

            CREATE TABLE types (
              id            INTEGER PRIMARY KEY,
              name          TEXT NOT NULL UNIQUE,
              is_fwd_decl   INTEGER NOT NULL,
              c_type        TEXT NOT NULL
            );
        """)
        self.db.commit()

    def is_idb_indexed(self, idb_path):
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM binary WHERE idb_path=?", [idb_path])
        return cursor.fetchone() is not None

    def index_symbols_for_this_idb(self):
        idb_path = GetIdbPath()
        if self.is_idb_indexed(idb_path):
            raise Exception("Cache for this IDB is already built.")

        # Create binary record.
        cursor = self.db.cursor()
        cursor.execute(
            "INSERT INTO binary (idb_path, input_file) VALUES (?, ?)",
            [idb_path, GetInputFile()],
        )
        binary_id = cursor.lastrowid

        # Populate index.
        for i in xrange(GetEntryPointQty()):
            ordinal = GetEntryOrdinal(i)
            name = GetEntryName(ordinal)

            # For of now, we only support names exported by-name.
            if name is None:
                continue

            cursor.execute(
                "INSERT INTO export (binary_id, name) VALUES (?, ?)",
                [binary_id, name],
            )

        # All good, flush.
        self.db.commit()

    def index_types_for_this_idb(self):
        cursor = self.db.cursor()
        cur_named_type = idaapi.first_named_type(
            idaapi.cvar.idati,
            idaapi.NTF_TYPE | idaapi.NTF_SYMM
        )

        while cur_named_type:
            code, type_str, fields_str, cmt, field_cmts, sclass, value = idaapi.get_named_type64(
                idaapi.cvar.idati,
                cur_named_type,
                idaapi.NTF_TYPE | idaapi.NTF_SYMM,
            )

            ti = idaapi.tinfo_t()
            ti.deserialize(idaapi.cvar.idati, type_str, fields_str)
            c_type = ti._print(
                cur_named_type,
                idaapi.PRTYPE_1LINE | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                0, 0, None, cmt,
            )

            # TODO: prefer more concrete type rather than stupidly replacing.
            cursor.execute(
                "INSERT OR REPLACE INTO types (name, is_fwd_decl, c_type) VALUES (?, ?, ?)",
                [cur_named_type, ti.is_forward_decl(), c_type],
            )

            cur_named_type = idaapi.next_named_type(
                idaapi.cvar.idati,
                cur_named_type,
                idaapi.NTF_TYPE | idaapi.NTF_SYMM,
            )

        self.db.commit()

    def load_types_into_idb(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM types")
        for cur_row in cursor.fetchall():
            idaapi.parse_decls(idaapi.cvar.idati, str(cur_row['c_type']), None, 0)

    def find_export(self, symbol):
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT e.id, b.idb_path FROM export e
            JOIN binary b ON e.binary_id = b.id
            WHERE e.name = ?
        """, [symbol])
        row = cursor.fetchone()
        return None if row is None else dict(row)
