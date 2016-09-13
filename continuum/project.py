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
import subprocess
import itertools
import ConfigParser
import fnmatch
from PyQt5.QtCore import QObject, pyqtSignal
from idc import *

from .index import Index


class Project(QObject):
    META_DIR_NAME = '.continuum'
    CFG_FILE_NAME = 'project.conf'

    def __init__(self):
        super(Project, self).__init__()
        self.conf = None
        self.index = None
        self.proj_dir = None
        self.meta_dir = None
        self.ignore_changes = False
        self.files = []

    def open(self, root, skip_analysis=False):
        """Opens an existing project by its root path."""
        if self.proj_dir:
            raise Exception("A project is already opened")

        # Find meta directory and read config.
        meta_dir = os.path.join(root, self.META_DIR_NAME)
        conf = ConfigParser.SafeConfigParser()
        if not conf.read(os.path.join(meta_dir, self.CFG_FILE_NAME)):
            raise Exception("Project is lacking its config file")

        # Determine project files.
        file_patterns = conf.get('project', 'file_patterns')
        if file_patterns is None:
            raise Exception("Project configuration lacks `file_patterns` directive")
        files = list(self.find_project_files(root, file_patterns))

        # Everything fine, put info into `self`.
        self.conf = conf
        self.proj_dir = root
        self.meta_dir = meta_dir
        self.files = files
        self.index = Index(self)

        if not skip_analysis:
            # Is index for *this* IDB built? If not, do so.
            if not self.index.is_idb_indexed(GetIdbPath()):
                self.index.index_types_for_this_idb()
                self.index.index_symbols_for_this_idb()

            # Analyze other files, if required.
            self._analyze_project_files()

    def _analyze_project_files(self):
        plugin_root = os.path.dirname(os.path.realpath(__file__))
        procs = []

        for cur_file in self.files:
            # IDB already indexed? Skip.
            if self.index.is_idb_indexed(self.file_to_idb(cur_file)):
                continue

            procs.append(subprocess.Popen([
                sys.executable,
                '-A', 
                '-S"{}"'.format(os.path.join(plugin_root, 'analyze.py')), 
                '-L{}.log'.format(cur_file), 
                cur_file,
            ]))

        return procs

    @staticmethod
    def file_to_idb(file):
        return os.path.splitext(file)[0] + '.idb'

    @classmethod
    def find_project_dir(cls, start_path):
        """
        Traverses up the directory tree, searching for a project root.
        If one is found, returns the path, else `None`.
        """
        tail = object()
        head = start_path
        while tail:
            head, tail = os.path.split(head)
            cur_meta_path = os.path.join(head, tail, cls.META_DIR_NAME)
            if os.path.exists(cur_meta_path):
                return os.path.join(head, tail)

    @staticmethod
    def find_project_files(root, file_patterns):
        """Locates all binaries that are part of a project."""
        file_patterns = [x.strip() for x in file_patterns.split(';')]
        for dirpath, _, filenames in os.walk(root):
            relevant_files = itertools.chain.from_iterable(
                fnmatch.filter(filenames, x) for x in file_patterns
            )

            # Py2 Y U NO SUPPORT "yield from"? :(
            for cur_file in relevant_files:
                yield os.path.join(dirpath, cur_file)

    @classmethod
    def create(cls, root, file_patterns):
        """Creates a new project."""
        # Create meta directory.
        cont_dir = os.path.join(root, cls.META_DIR_NAME)
        if os.path.exists(cont_dir):
            raise Exception("Directory is already a continuum project")
        os.mkdir(cont_dir)

        # Create config file.
        config = ConfigParser.SafeConfigParser()
        config.add_section('project')
        config.set('project', 'file_patterns', file_patterns)
        with open(os.path.join(cont_dir, cls.CFG_FILE_NAME), 'w') as f:
            config.write(f)

        # Create initial index.
        project = Project()
        project.open(root)

        return project
