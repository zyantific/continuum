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
import random
import socket
import uuid
import asyncore
import struct
import json
sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import idaapi
from idautils import *
from idc import *
from PyQt5.QtCore import QTimer


class ProtoMixin(object):
    NET_HDR_FORMAT = '>I'
    NET_HDR_LEN = struct.calcsize(NET_HDR_FORMAT)

    def handle_packet(self, packet):
        pass

    def handle_read(self):
        self.recv_buf += self.recv(1500)
        if len(self.recv_buf) < self.NET_HDR_LEN:
            return

        packet_len, = struct.unpack(
            self.NET_HDR_FORMAT, 
            self.recv_buf[:self.NET_HDR_LEN],
        )
        if len(self.recv_buf) < packet_len:
            return

        packet = self.recv_buf[self.NET_HDR_LEN:packet_len + self.NET_HDR_LEN]
        packet = packet.decode('utf8')
        packet = json.loads(packet)
        self.handle_packet(packet)
        self.recv_buf = self.recv_buf[packet_len:]

    def send_packet(self, packet):
        packet = json.dumps(packet).encode('utf8')
        self.send(struct.pack(self.NET_HDR_FORMAT, len(packet)))
        self.send(packet)


class Server(ProtoMixin, asyncore.dispatcher_with_send):
    def __init__(self, sock, factory):
        asyncore.dispatcher_with_send.__init__(self, sock=sock)
        self.factory = factory
        self.recv_buf = bytearray()
        self.guid = None
        self.input_file = None
        self.factory.clients.add(self)

    def handle_close(self):
        self.factory.clients.remove(self)
        asyncore.dispatcher_with_send.handle_close(self)

    def handle_packet(self, packet):
        kind = packet['kind']
        if kind == 'new_client':
            self.guid = packet['guid']
            self.input_file = packet['input_file']
            print("[{}] claimed file '{}'".format(self.guid, self.input_file))
        elif kind == 'broadcast':
            packet['src'] = self.guid
            for cur_client in self.factory.clients:
                if cur_client == self:
                    continue
                cur_client.send_packet(packet)
        elif kind == 'directed_msg':
            packet['src'] = self.guid
            for cur_client in self.factory.clients:
                if cur_client.guid == packet['dst']:
                    cur_client.send_packet(packet)
                    break
        else:
            print("Received packet of unknown kind '{}'.".format(kind))
            return


class ServerFactory(asyncore.dispatcher):
    def __init__(self, port):
        asyncore.dispatcher.__init__(self)
        self.clients = set()
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(('127.0.0.1', port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print("Connection from {!r}".format(addr))
            Server(sock, self)


class Client(ProtoMixin, asyncore.dispatcher):
    def __init__(self, sock):
        asyncore.dispatcher.__init__(self, sock=sock)
        self.guid = uuid.uuid4()
        self.recv_buf = bytearray()

        self.send_packet({
            'kind': 'broadcast',
            'msg': {
                'kind': 'new_client',
                'guid': str(self.guid),
                'input_file': GetInputFile(),
            }
        })

    def handle_packet(self, packet):
        print('RECVED PACKET:')
        print(repr(packet))


class Continuum(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Hurr"
    help = "This is help"
    wanted_name = "continuum"
    wanted_hotkey = 'Alt-F9'

    def create_or_join_network(self):
        server_port_file = os.path.join(self.continuum_dir, 'server_port')

        # Read or define server port.
        if os.path.exists(server_port_file):
            with open(server_port_file) as f:
                server_port = int(f.read())
        else:
            server_port = int(random.uniform(10000, 65535))
            with open(server_port_file, 'w') as f:
                f.write(str(server_port))

        # Server alive?
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', server_port))
            self.client = Client(sock)
        except socket.error as exc:
            # Nope, create one.
            sock.close()
            print('No existing server found, creating new one.')
            self.server = ServerFactory(server_port)

            # Yeah, it's not especially clean to connect to our local server,
            # but it makes the whole software design and especially server
            # migration a lot easier.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('127.0.0.1', server_port))
            self.client = Client(sock)

    def init(self):
        print('[continuum] v0.0.0 by athre0z (zyantific.com) loaded!')

        idb_dir = GetIdbDir()
        self.continuum_dir = os.path.join(idb_dir, '.continuum')

        if not os.path.exists(self.continuum_dir):
            if os.path.exists(self.continuum_dir):
                raise Exception("Directory is already an continuum project (wat?)")
            os.mkdir(self.continuum_dir)

        self.create_or_join_network()

        def beat():
            asyncore.loop(count=1, timeout=0)

        # Yep, this isn't especially "true async", but it's fine for what we do.
        timer = QTimer()
        timer.timeout.connect(beat)
        timer.setSingleShot(False)
        timer.setInterval(1)
        timer.start()

        # We hack our timer into the idaapi module to prevent it from being GCed.
        idaapi._dirty_hack_continuum_timer = timer

        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)

    def term(self):
        idaapi.msg("term() called!\n")


def PLUGIN_ENTRY():
    return Continuum()
