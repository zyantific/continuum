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

import os
import sqlite3
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
        """)
        self.db.commit()

    def is_idb_indexed(self, idb_path):
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM binary WHERE idb_path=?", [idb_path])
        return cursor.fetchone() is not None

    def build_for_this_idb(self):
        idb_path = GetIdbPath()
        if self.is_idb_indexed(idb_path):
            raise Exception("Cache for this IDB is already built.")

        # Create binary record.
        cursor = self.db.cursor()
        cursor.execute("INSERT INTO binary (idb_path, input_file) VALUES (?, ?)", [
            idb_path, 
            GetInputFile(),
        ])
        binary_id = cursor.lastrowid

        # Populate index.
        for i in xrange(GetEntryPointQty()):
            ordinal = GetEntryOrdinal(i)
            name = GetEntryName(ordinal)

            # For of now, we only support names exported by-name.
            if name is None:
                continue

            cursor.execute("INSERT INTO export (binary_id, name) VALUES (?, ?)", [
                binary_id,
                name,
            ])

        # All good, flush.
        self.db.commit()

    def find_export(self, symbol):
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT e.id, b.idb_path FROM export e
            JOIN binary b ON e.binary_id = b.id
            WHERE e.name = ?
        """, [symbol])
        row = cursor.fetchone()
        return None if row is None else dict(row)
