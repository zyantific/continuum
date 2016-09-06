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
import random
import socket
import asyncore
import idaapi
import subprocess
from idautils import *
from idc import *
from PyQt5.QtCore import QTimer, QObject, pyqtSignal

from .server import Server
from .client import Client
from .project import Project


def launch_ida_gui_instance(idb_path):
    return subprocess.Popen([sys.executable, idb_path])


class Continuum(QObject):
    project_opened = pyqtSignal([Project])
    project_closing = pyqtSignal()
    client_created = pyqtSignal([Client])

    def __init__(self):
        super(Continuum, self).__init__()

        self.project = None
        self.client = None
        self.server = None
        self.loop_entered = False
        self._timer = None

        # Sign up for events.
        idaapi.notify_when(idaapi.NW_OPENIDB, self.handle_open_idb)
        idaapi.notify_when(idaapi.NW_CLOSEIDB, self.handle_close_idb)

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
            self.client_created.emit(self.client)
        except socket.error:
            sock.close()
            raise Exception("No server found")

    def enable_asyncore_loop(self):
        def beat():
            self.loop_entered = True
            try:
                asyncore.loop(count=1, timeout=0)
            finally:
                self.loop_entered = False

        # Yep, this isn't especially real-time IO, but it's fine for what we do.
        timer = QTimer()
        timer.timeout.connect(beat)
        timer.setSingleShot(False)
        timer.setInterval(15)
        timer.start()

        self._timer = timer

    def disable_asyncore_loop(self):
        self._timer = None

    def open_project(self, project):
        print("[continuum] Opening project.")

        self.project = project
        self.create_server_if_none()
        self.create_client()
        self.enable_asyncore_loop()

        self.project_opened.emit(project)

    def close_project(self):
        print("[continuum] Closing project.")

        self.project_closing.emit()
        self.disable_asyncore_loop()
        
        # Are we server? Initiate host migration.
        if self.server:
            self.server.migrate_host_and_shutdown()
            self.server = None

        self.client.close()
        self.client = None
        self.project = None

    def handle_open_idb(self, _, is_old_database):
        # Is IDB part of a continuum project? Open it.
        proj_dir = Project.find_project_dir(GetIdbDir())
        if proj_dir:
            project = Project()
            project.open(proj_dir)
            self.open_project(project)

    def handle_close_idb(self, _):
        if self.client:
            self.close_project()

    def read_or_generate_server_port(self, force_fresh=False):
        server_port_file = os.path.join(self.project.meta_dir, 'server_port')
        if not force_fresh and os.path.exists(server_port_file):
            with open(server_port_file) as f:
                return int(f.read())
        else:
            server_port = int(random.uniform(10000, 65535))
            with open(server_port_file, 'w') as f:
                f.write(str(server_port))
            return server_port

    def follow_extern(self):
        ea = ScreenEA()
        if GetSegmentAttr(ea, SEGATTR_TYPE) != SEG_XTRN:
            return

        name = Name(ea)
        if name.startswith('__imp_'):
            name = name[6:]

        self.client.send_focus_symbol(name)


def PLUGIN_ENTRY():
    from .plugin import Plugin
    return Plugin()
