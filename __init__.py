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

from .server import Server
from .client import Client
from .symbol_index import SymbolIndex


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


def launch_ida_gui_instance(self, idb_path):
    return subprocess.Popen([sys.executable, idb_path])


class Continuum(object):
    def __init__(self):
        self.client = None
        self.server = None
        self.timer = None
        self.continuum_dir = None
        self.server_port = None
        self.symbol_index = None

    def create_server_if_none(self):
        # Server alive?
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', self.server_port))
        except socket.error as exc:
            # Nope, create one.
            print('No existing server found, creating new one.')
            self.server = Server(self.server_port, self)
        finally:
            sock.close()

    def create_client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', self.server_port))
            self.client = Client(sock)
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

    def basic_init(self):
        # Determine continuum data directory.
        idb_dir = GetIdbDir()
        self.continuum_dir = os.path.join(idb_dir, '.continuum')
        if not os.path.exists(self.continuum_dir):
            if os.path.exists(self.continuum_dir):
                raise Exception("Directory is already an continuum project (wat?)")
            os.mkdir(self.continuum_dir)

        # Read or define server port.
        server_port_file = os.path.join(self.continuum_dir, 'server_port')
        if os.path.exists(server_port_file):
            with open(server_port_file) as f:
                self.server_port = int(f.read())
        else:
            self.server_port = int(random.uniform(10000, 65535))
            with open(server_port_file, 'w') as f:
                f.write(str(self.server_port))

        # Initialize symbol index.
        self.symbol_index = SymbolIndex(self)

    def full_init(self):
        self.basic_init()
        self.create_server_if_none()
        self.create_client()
        self.register_hotkeys()
        self.enable_asyncore_loop()

        from .ui import ProjectCreationDialog
        self.xxx = ProjectCreationDialog()
        self.xxx.show()


def PLUGIN_ENTRY():
    from .plugin import Plugin
    return Plugin()
