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
from .proto import ProtoMixin


class Server(ProtoMixin, asyncore.dispatcher_with_send):
    def __init__(self, sock, factory):
        asyncore.dispatcher_with_send.__init__(self, sock=sock)
        ProtoMixin.__init__(self)
        self.factory = factory
        self.guid = None
        self.input_file = None
        self.factory.clients.add(self)

    def handle_close(self):
        self.factory.clients.remove(self)
        asyncore.dispatcher_with_send.handle_close(self)

    def handle_packet(self, packet):
        trans_kind = packet['kind']
        if trans_kind == 'new_client':
            self.guid = packet['guid']
            self.input_file = packet['input_file']
            print("[{}] claimed file '{}'".format(self.guid, self.input_file))
        elif trans_kind == 'broadcast':
            packet['src'] = self.guid
            for cur_client in self.factory.clients:
                if cur_client == self:
                    continue
                cur_client.send_packet(packet)
        elif trans_kind == 'directed_msg':
            packet['src'] = self.guid
            for cur_client in self.factory.clients:
                if cur_client.guid == packet['dst']:
                    cur_client.send_packet(packet)
                    break
        else:
            print("Received packet of unknown transport kind '{}'.".format(trans_kind))
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
            server = Server(sock, self)
