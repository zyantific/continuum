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

# NOTE: This is not a regular project file, this is invoked as batch script by IDA!

from __future__ import absolute_import, print_function, division

import sys
import socket
sys.path.append(r"C:\Development")  # TODO: don't hardcode this
from continuum.project import Project

# Turn on coagulation of data in the final pass of analysis
SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) | AF2_DODATA)
print("Analyzing input file ...")
Wait()

# Index symbols.
print("Indexing symbols ...")
proj = Project()
proj.open(Project.find_project_dir(GetIdbDir()))
proj.symbol_index.build_for_this_idb()

# Prevent UI from popping up.
print("All good, exiting.")
Exit(0)
