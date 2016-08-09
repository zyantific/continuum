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

import idaapi
from . import Continuum


class Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Plugin adding multi-binary project support"
    help = comment
    wanted_name = "continuum"
    wanted_hotkey = 'Alt-F9'
        
    def init(self):
        self.core = Continuum()
        self.core.full_init()
        
        # Hack ref to plugin core object into idaapi for easy debugging.
        idaapi.continuum = self.core

        print("[continuum] v0.0.0 by athre0z (zyantific.com) loaded!")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("[continuum] No fancy action hidden here, yet!")

    def term(self):
        self.core.disable_asyncore_loop()
        print("[continuum] plugin unloaded.")
