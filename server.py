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

import asyncore
import socket
from idc import *
from idautils import *
from collections import defaultdict
from .proto import ProtoMixin
from PyQt5.QtCore import QObject, pyqtSignal


class ClientConnection(ProtoMixin, asyncore.dispatcher_with_send):
    def __init__(self, sock, server):
        # We need to use old-style init calls here because asyncore 
        # consists of old-style classes :(
        asyncore.dispatcher_with_send.__init__(self, sock=sock)
        ProtoMixin.__init__(self)

        self.input_file = None
        self.idb_path = None
        self.server = server
        self.project = server.core.project
        self.server.clients.add(self)

    def handle_close(self):
        self.server.clients.remove(self)
        self.server.update_idb_client_map()
        print("[continuum] A client disconnected.")
        asyncore.dispatcher_with_send.handle_close(self)

    def send_or_delay_packet(self, receiver_idb_path, packet):
        # Is a client for this IDB alive? Just send message.
        client = self.server.idb_client_map.get(receiver_idb_path)
        if client:
            client.send_packet(packet)
        # Nope, put message into backlog and launch a fresh idaq.
        else:
            self.server.queue_delayed_packet(receiver_idb_path, packet)
            from . import launch_ida_gui_instance
            launch_ida_gui_instance(receiver_idb_path)

    def handle_msg_new_client(self, input_file, idb_path, **_):
        self.input_file = input_file
        self.idb_path = idb_path
        self.server.update_idb_client_map()

        # Client start-up sequence is completed, deliver delayed messages.
        self.server.process_delayed_packets(self)

    def handle_msg_focus_symbol(self, symbol, **_):
        export = self.project.symbol_index.find_export(symbol)
        if export is None:
            print("[continuum] Symbol '{}' not found.".format(symbol))
            return

        self.send_or_delay_packet(export['idb_path'], {
            'kind': 'focus_symbol',
            'symbol': symbol,
        })

    def handle_msg_focus_instance(self, idb_path, **_):
        self.send_or_delay_packet(idb_path, {'kind': 'focus_instance'})

    def handle_msg_refresh_project(self, **_):
        for cur_client in self.server.clients:
            if cur_client == self:
                continue
            cur_client.send_packet({'kind': 'refresh_project'})


class Server(asyncore.dispatcher):
    def __init__(self, port, core):
        asyncore.dispatcher.__init__(self)

        self.core = core
        self.clients = set()
        self.idb_client_map = dict()
        self._delayed_packets = defaultdict(list)

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(('127.0.0.1', port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print("[continuum] Connection from {!r}".format(addr))
            ClientConnection(sock, self)

    def update_idb_client_map(self):
        self.idb_client_map = {
            x.idb_path: x for x in self.clients if x.idb_path is not None
        }

    def queue_delayed_packet(self, idb_path, packet):
        self._delayed_packets[idb_path].append(packet)

    def process_delayed_packets(self, client):
        assert client.idb_path
        for cur_packet in self._delayed_packets[client.idb_path]:
            client.send_packet(cur_packet)

    def migrate_host_and_shutdown(self):
        # Any other client online? Migrate host.
        host_candidates = [x for x in self.clients if x.idb_path != self.core.client.idb_path]
        if host_candidates:
            self.core.read_or_generate_server_port(force_fresh=True)
            elected_client = next(iter(host_candidates))
            elected_client.send_packet({'kind': 'become_host'})

        # Close server socket.
        self.close()

        # Disconnect clients.
        for cur_client in self.clients:
            cur_client.close()
