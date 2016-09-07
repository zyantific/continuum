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
import asyncore
from idc import *
from idautils import *
from .proto import ProtoMixin
from PyQt5.QtCore import QObject, pyqtSignal


class Client(QObject, ProtoMixin, asyncore.dispatcher_with_send):
    client_analysis_state_updated = pyqtSignal([str, str])  # idb_path, state
    refresh_project = pyqtSignal()
    sync_types = pyqtSignal([bool])  # purge_non_indexed

    def __init__(self, sock, core):
        asyncore.dispatcher_with_send.__init__(self, sock=sock)
        ProtoMixin.__init__(self)
        QObject.__init__(self)
        self.core = core
        self.idb_path = GetIdbPath()

        self.send_packet({
            'kind': 'new_client',
            'input_file': GetInputFile(),
            'idb_path': GetIdbPath(),
            'pid': os.getpid(),
        })

        print("[continuum] Connected.")

    def handle_close(self):
        asyncore.dispatcher_with_send.handle_close(self)
        print("[continuum] Connection lost, reconnecting.")
        self.core.create_client()

    def handle_msg_focus_symbol(self, symbol, **_):
        for i in xrange(GetEntryPointQty()):
            ordinal = GetEntryOrdinal(i)
            if GetEntryName(ordinal) == symbol:
                # `Jump` also focuses the instance.
                Jump(GetEntryPoint(ordinal))
                break

    def handle_msg_focus_instance(self, **_):
        Jump(ScreenEA())

    def handle_msg_become_host(self, **_):
        print("[continuum] We were elected as host.")
        self.core.create_server_if_none()

    def handle_msg_refresh_project(self, **_):
        self.refresh_project.emit()

    def handle_msg_analysis_state_updated(self, client, state, **_):
        self.client_analysis_state_updated.emit(client, state)

    def handle_msg_sync_types(self, purge_non_indexed, **_):
        self.sync_types.emit(purge_non_indexed)

    @staticmethod
    def _allow_others_focusing():
        if sys.platform == 'win32':
            # On Windows, there's a security mechanism preventing other applications
            # from putting themselves into the foreground unless explicitly permitted.
            import ctypes
            ctypes.windll.user32.AllowSetForegroundWindow(-1)
    
    def send_focus_symbol(self, symbol):
        self._allow_others_focusing()
        self.send_packet({
            'kind': 'focus_symbol',
            'symbol': symbol,
        })

    def send_focus_instance(self, idb_path):
        self._allow_others_focusing()
        self.send_packet({
            'kind': 'focus_instance',
            'idb_path': idb_path,
        })

    def send_refresh_project(self):
        self.send_packet({'kind': 'refresh_project'})

    def send_analysis_state(self, state):
        self.send_packet({
            'kind': 'update_analysis_state',
            'state': state,
        })

    def send_sync_types(self, purge_non_indexed):
        self.send_packet({
            'kind': 'sync_types',
            'purge_non_indexed': purge_non_indexed,
        })
