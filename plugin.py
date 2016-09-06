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
from idautils import *
from idc import *
from PyQt5.QtWidgets import QDialog

from .ui import ProjectExplorerWidget, ProjectCreationDialog
from .project import Project


class Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX

    comment = "Plugin adding multi-binary project support"
    help = comment
    wanted_name = "continuum"
    wanted_hotkey = 'Alt-F9'

    def __init__(self):
        super(Plugin, self).__init__()
        self.core = None
        self.project_explorer = None
        self.idb_hook = None
        self.ui_hook = None

    def init(self):
        self.core = Continuum()

        # Place UI hook so we know when to create our UI stuff.
        zelf = self
        class UiHooks(idaapi.UI_Hooks):
            def ready_to_run(self, *_):
                zelf.ui_init()
                zelf.ui_hook.unhook()

        self.ui_hook = UiHooks()
        self.ui_hook.hook()

        # Setup IDP hook for type changes.
        class IdbHooks(idaapi.IDB_Hooks):
            def local_types_changed(self, *args):
                if zelf.core.loop_entered:
                    return 0

                if zelf.core.client:
                    zelf.core.project.symbol_index.index_types_for_this_idb()
                    zelf.core.client.send_sync_types()

                return 0

        self.idb_hook = IdbHooks()
        self.idb_hook.hook()

        # Hack ref to plugin core object into idaapi for easy debugging.
        idaapi.continuum = self.core

        print("[continuum] v0.0.0 by athre0z (zyantific.com) loaded!")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        print("[continuum] No fancy action hidden here, yet!")

    def term(self):
        if self.core.client:
            self.core.close_project()

        self.idb_hook.unhook()
        self.core.disable_asyncore_loop()
        print("[continuum] Plugin unloaded.")

    def ui_init(self):
        # Register menu entry. 
        # @HR: I really preferred the pre-6.5 mechanic.
        zelf = self
        class MenuEntry(idaapi.action_handler_t):
            def activate(self, ctx):
                zelf.open_proj_creation_dialog()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

        action = idaapi.action_desc_t(
            'continuum_new_project',
            "New continuum project...",
            MenuEntry(),
        )
        idaapi.register_action(action)
        idaapi.attach_action_to_menu("File/Open...", 'continuum_new_project', 0)    

        # Alright, is an IDB loaded? Pretend IDB open event as we miss the callback
        # when it was loaded before our plugin was staged.
        if GetIdbPath():
            self.core.handle_open_idb(None, None)

        # Register hotkeys.
        idaapi.add_hotkey('Shift+F', self.core.follow_extern)

        # Sign up for events.
        self.core.project_opened.connect(self.create_proj_explorer)
        self.core.project_closing.connect(self.close_proj_explorer)
        self.core.client_created.connect(self.subscribe_client_events)

        # Project / client already open? Fake events.
        if self.core.project:
            self.create_proj_explorer(self.core.project)
        if self.core.client:
            self.subscribe_client_events(self.core.client)

    def create_proj_explorer(self, project):
        self.project_explorer = ProjectExplorerWidget(project)
        self.project_explorer.Show("continuum project")
        self.project_explorer.refresh_project_clicked.connect(self.refresh_project)
        self.project_explorer.focus_instance_clicked.connect(
            lambda idb_path: self.core.client.send_focus_instance(idb_path)
        )
        idaapi.set_dock_pos("continuum project", "Functions window", idaapi.DP_BOTTOM)

    def close_proj_explorer(self):
        self.project_explorer.Close(0)
        self.project_explorer = None

    def subscribe_client_events(self, client):
        client.sync_types.connect(self.core.project.symbol_index.load_types_into_idb)

    def open_proj_creation_dialog(self):
        if self.core.client:
            print("[continuum] A project is already opened.")
            return

        if not GetIdbPath():
            print("[continuum] Please load an IDB related to the project first.")
            return

        dialog = ProjectCreationDialog(GetIdbDir())
        chosen_action = dialog.exec_()

        if chosen_action == QDialog.Accepted:
            project = Project.create(dialog.project_path, dialog.file_patterns)
            self.core.open_project(project)

    def refresh_project(self, *_):
        if not self.project_explorer:
            return

        self.project_explorer.update()
        self.core.client.send_refresh_project()
