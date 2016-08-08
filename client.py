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
import uuid
from idc import *
from idautils import *
from .proto import ProtoMixin


class Client(ProtoMixin, asyncore.dispatcher):
    def __init__(self, sock):
        asyncore.dispatcher.__init__(self, sock=sock)
        ProtoMixin.__init__(self)
        self.guid = uuid.uuid4()

        self.send_packet({
            'kind': 'broadcast',
            'msg': {
                'kind': 'new_client',
                'guid': str(self.guid),
                'input_file': GetInputFile(),
            },
        }) 


    def handle_packet(self, packet):
        trans_kind = packet['kind']
        if trans_kind in ('broadcast', 'directed_msg'):
            msg = packet['msg']
            handler = getattr(self, 'handle_msg_' + msg['kind'], None)
            if handler is None:
                print("Received packet of unknown kind '{}'".format(msg['kind']))
                return

            try:
                print('CLIENT RECVED: {!r}'.format(msg))
                handler(**msg)
            except TypeError as exc:
                print("Received invalid arguments for packet: " + str(exc))
        else:
            print("Received packet of unknown transport kind '{}'.".format(trans_kind))

    def handle_msg_focus_by_symbol(self, symbol, **_):
        for i in xrange(GetEntryPointQty()):
            ordinal = GetEntryOrdinal(i)
            if GetEntryName(ordinal) == symbol:
                Jump(GetEntryPoint(ordinal))
                break

    def handle_msg_new_client(self, **_):
        pass  # dont care
    
    def send_focus_by_symbol(self, symbol):
        self.send_packet({
            'kind': 'broadcast',
            'msg': {
                'kind': 'focus_by_symbol',
                'symbol': symbol,
            },
        })
