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
import os
from idc import *
from idautils import *

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..',
    )
)

from continuum import Continuum
from continuum.project import Project

# Connect to server instance.
proj = Project()
cont = Continuum()
proj.open(Project.find_project_dir(GetIdbDir()), skip_analysis=True)
cont.open_project(proj)

# Wait for auto-analysis to complete.
SetShortPrm(INF_AF2, GetShortPrm(INF_AF2) | AF2_DODATA)
print("Analyzing input file ...")
cont.client.send_analysis_state('auto-analysis')
Wait()

# Index types.
print("Indexing types ...")
cont.client.send_analysis_state('indexing-types')
proj.index.index_types_for_this_idb()

# Index symbols.
print("Indexing symbols ...")
cont.client.send_analysis_state('indexing-symbols')
proj.index.index_symbols_for_this_idb()
cont.client.send_sync_types(purge_non_indexed=False)

# Prevent UI from popping up.
cont.client.send_analysis_state('done')
print("All good, exiting.")
Exit(0)
