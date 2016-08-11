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

import sys
import os
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import random
import socket
import asyncore
import idaapi
import subprocess
import fnmatch
import itertools
import sqlite3
from idautils import *
from idc import *
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import QDialog

from .server import Server
from .client import Client
from .symbol_index import SymbolIndex


def find_cont_directory(start_path):
    tail = object()
    head = start_path
    while tail:
        head, tail = os.path.split(head)
        cur_meta_path = os.path.join(head, tail, '.continuum')
        if os.path.exists(cur_meta_path):
            return cur_meta_path


def find_project_files(path, pattern):
    patterns = [x.strip() for x in pattern.split(';')]
    for dirpath, _, filenames in os.walk(path):
        relevant_files = itertools.chain.from_iterable(
            fnmatch.filter(filenames, x) for x in patterns
        )

        # Py2 Y U NO SUPPORT "yield from"? :(
        for cur_file in relevant_files:
            yield os.path.join(dirpath, cur_file)


def analyze_project_files(files):
    return [subprocess.Popen([
        # TODO: don't hardcode path
        sys.executable, '-A', r'-S"C:\Development\continuum\analyze.py"', 
        '-L{}.log'.format(x), x
    ]) for x in files]


def launch_ida_gui_instance(idb_path):
    return subprocess.Popen([sys.executable, idb_path])


class Continuum(object):
    def __init__(self):
        self.client = None
        self.server = None
        self.timer = None
        self.continuum_dir = None
        self.symbol_index = None

    def create_server_if_none(self):
        # Server alive?
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_port = self.read_or_generate_server_port()
        try:
            sock.connect(('127.0.0.1', server_port))
        except socket.error as exc:
            # Nope, create one.
            print("[continuum] Creating server.")
            self.server = Server(server_port, self)
        finally:
            sock.close()

    def create_client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_port = self.read_or_generate_server_port()
        try:
            sock.connect(('127.0.0.1', server_port))
            self.client = Client(sock, self)
        except socket.error as exc:
            sock.close()
            raise Exception("No server found")

    def register_hotkeys(self):
        def follow_extrn():
            ea = ScreenEA()
            if GetSegmentAttr(ea, SEGATTR_TYPE) != SEG_XTRN:
                return
            self.client.send_focus_symbol(Name(ea))

        idaapi.add_hotkey('Shift+F', follow_extrn)

    def unregister_hotkeys(self):
        pass  # TODO

    def enable_asyncore_loop(self):
        def beat():
            asyncore.loop(count=1, timeout=0)

        # Yep, this isn't especially "true async", but it's fine for what we do.
        timer = QTimer()
        timer.timeout.connect(beat)
        timer.setSingleShot(False)
        timer.setInterval(1)
        timer.start()

        self.timer = timer

    def disable_asyncore_loop(self):
        self.timer = None

    def open_project(self, cont_dir):
        print("[continuum] Opening project.")

        self.continuum_dir = cont_dir
        self.symbol_index = SymbolIndex(self)
        self.create_server_if_none()
        self.create_client()
        self.enable_asyncore_loop()
        self.register_hotkeys()

    def close_project(self):
        print("[continuum] Closing project.")

        self.unregister_hotkeys()
        self.disable_asyncore_loop()
        
        # Are we server? Initiate host migration.
        if self.server:
            self.server.migrate_host_and_shutdown()
            self.server = None

        self.client.close()
        self.client = None

    def create_project(self, root, file_patterns):
        # Create meta directory.
        cont_dir = os.path.join(root, '.continuum')
        if os.path.exists(cont_dir):
            raise Exception("Directory is already a continuum project")
        os.mkdir(cont_dir)

        # Create index.
        files = find_project_files(root, file_patterns)
        analyze_project_files(files)

        # TODO: store file patterns somewhere for future use
        self.open_project(cont_dir)

    def _handle_open_idb(self, _, is_old_database):
        # Is IDB part of a continuum project?
        cont_dir = find_cont_directory(GetIdbDir())
        if cont_dir:
            self.open_project(cont_dir)

    def _handle_close_idb(self, _):
        if self.client:
            self.close_project()

    def read_or_generate_server_port(self, force_fresh=False):
        server_port_file = os.path.join(self.continuum_dir, 'server_port')
        if not force_fresh and os.path.exists(server_port_file):
            with open(server_port_file) as f:
                return int(f.read())
        else:
            server_port = int(random.uniform(10000, 65535))
            with open(server_port_file, 'w') as f:
                f.write(str(server_port))
            return server_port

    def open_proj_creation_dialog(self):
        if self.client:
            print("[continuum] A project is already opened.")
            return

        if not GetIdbPath():
            print("[continuum] Please load an IDB related to the project first.")
            return

        from .ui import ProjectCreationDialog
        dialog = ProjectCreationDialog(GetIdbDir())
        chosen_action = dialog.exec_()

        if chosen_action == QDialog.Accepted:
            self.create_project(dialog.project_path, dialog.file_patterns)

    def ui_init(self):
        # Register menu entry. 
        # @HR: I really preferred the pre-6.5 mechanic.
        zelf = self
        class MenuEntry(idaapi.action_handler_t):
            def activate(self, ctx):
                zelf.open_proj_creation_dialog()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        action = idaapi.action_desc_t(
            'continuum_new_project',
            "New continuum project...",
            MenuEntry(),
        )
        idaapi.register_action(action)
        idaapi.attach_action_to_menu("File/Open...", 'continuum_new_project', 0)

        # Sign up for events.
        idaapi.notify_when(idaapi.NW_OPENIDB, self._handle_open_idb)
        idaapi.notify_when(idaapi.NW_CLOSEIDB, self._handle_close_idb)

        # Alright, is an IDB loaded? Pretend IDB open event as we miss the callback
        # when it was loaded before our plugin was staged.
        if GetIdbPath():
            self._handle_open_idb(None, None)


def PLUGIN_ENTRY():
    from .plugin import Plugin
    return Plugin()
