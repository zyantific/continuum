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

import struct
import json


class ProtoMixin(object):
    """Mixin implementing a simple length-prefixed packet JSON protocol."""

    NET_HDR_FORMAT = '>I'
    NET_HDR_LEN = struct.calcsize(NET_HDR_FORMAT)

    def __init__(self):
        self.recv_buf = bytearray()

    def handle_packet(self, packet):
        handler = getattr(self, 'handle_msg_' + packet['kind'], None)
        if handler is None:
            print("Received packet of unknown kind '{}'".format(packet['kind']))
            return

        print("[continuum] {} RECVED: {!r}".format(self.__class__.__name__, packet))
        if type(packet) != dict or any(type(x) != unicode for x in packet.keys()):
            print("Received malformed packet.")
            return

        try:
            handler(**packet)
        except TypeError as exc:
            print("Received invalid arguments for packet: " + str(exc))
            return

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
        packet = json.loads(packet.decode('utf8'))
        self.handle_packet(packet)
        self.recv_buf = self.recv_buf[packet_len + self.NET_HDR_LEN:]

    def send_packet(self, packet):
        packet = json.dumps(packet).encode('utf8')
        self.send(struct.pack(self.NET_HDR_FORMAT, len(packet)))
        self.send(packet)
