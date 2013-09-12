# -*- coding: utf-8 -*-
# tray_mixin.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Methods related to minimizing to tray and tray context menus.
"""
from PySide import QtCore
from PySide import QtGui

from leap.bitmask import __version__ as VERSION
from leap.bitmask.platform_init import IS_MAC


class TrayMixin(QtCore.QObject):
    """
    Several methods used to display systray and its contextual menu
    """

    def _show_systray(self):
        """
        Sets up the systray icon
        """
        if self._systray is not None:
            self._systray.setVisible(True)
            return

        # Placeholder action
        # It is temporary to display the tray as designed
        help_action = QtGui.QAction(self.tr("Help"), self)
        help_action.setEnabled(False)

        systrayMenu = QtGui.QMenu(self)
        systrayMenu.addAction(self._action_visible)
        systrayMenu.addSeparator()
        systrayMenu.addAction(self._action_eip_provider)
        systrayMenu.addAction(self._action_eip_status)
        systrayMenu.addAction(self._action_eip_startstop)
        systrayMenu.addAction(self._action_mail_status)
        systrayMenu.addSeparator()
        systrayMenu.addAction(self._action_preferences)
        systrayMenu.addAction(help_action)
        systrayMenu.addSeparator()
        systrayMenu.addAction(self.ui.action_log_out)
        systrayMenu.addAction(self.ui.action_quit)
        self._systray = QtGui.QSystemTrayIcon(self)
        self._systray.setContextMenu(systrayMenu)
        self._systray.setIcon(self._status_panel.ERROR_ICON_TRAY)
        self._systray.setVisible(True)
        self._systray.activated.connect(self._tray_activated)

        self._status_panel.set_systray(self._systray)

    def _tray_activated(self, reason=None):
        """
        SLOT
        TRIGGER: self._systray.activated

        Displays the context menu from the tray icon
        """
        self._update_hideshow_menu()

        context_menu = self._systray.contextMenu()
        if not IS_MAC:
            # for some reason, context_menu.show()
            # is failing in a way beyond my understanding.
            # (not working the first time it's clicked).
            # this works however.
            context_menu.exec_(self._systray.geometry().center())

    def _update_hideshow_menu(self):
        """
        Updates the Hide/Show main window menu text based on the
        visibility of the window.
        """
        get_action = lambda visible: (
            self.tr("Show Main Window"),
            self.tr("Hide Main Window"))[int(visible)]

        # set labels
        visible = self.isVisible() and self.isActiveWindow()
        self._action_visible.setText(get_action(visible))

    def _toggle_visible(self):
        """
        SLOT
        TRIGGER: self._action_visible.triggered

        Toggles the window visibility
        """
        visible = self.isVisible() and self.isActiveWindow()
        qApp = QtCore.QCoreApplication.instance()

        if not visible:
            qApp.setQuitOnLastWindowClosed(True)
            self.show()
            self.activateWindow()
            self.raise_()
        else:
            # We set this in order to avoid dialogs shutting down the
            # app on close, as they will be the only visible window.
            # e.g.: PreferencesWindow, LoggerWindow
            qApp.setQuitOnLastWindowClosed(False)
            self.hide()

        self._update_hideshow_menu()

    def _center_window(self):
        """
        Centers the mainwindow based on the desktop geometry
        """
        geometry = self._settings.get_geometry()
        state = self._settings.get_windowstate()

        if geometry is None:
            app = QtGui.QApplication.instance()
            width = app.desktop().width()
            height = app.desktop().height()
            window_width = self.size().width()
            window_height = self.size().height()
            x = (width / 2.0) - (window_width / 2.0)
            y = (height / 2.0) - (window_height / 2.0)
            self.move(x, y)
        else:
            self.restoreGeometry(geometry)

        if state is not None:
            self.restoreState(state)

    def _about(self):
        """
        SLOT
        TRIGGERS: self.ui.action_about_leap.triggered

        Display the About Bitmask dialog
        """
        QtGui.QMessageBox.about(
            self, self.tr("About Bitmask - %s") % (VERSION,),
            self.tr("Version: <b>%s</b><br>"
                    "<br>"
                    "Bitmask is the Desktop client application for "
                    "the LEAP platform, supporting encrypted internet "
                    "proxy, secure email, and secure chat (coming soon).<br>"
                    "<br>"
                    "LEAP is a non-profit dedicated to giving "
                    "all internet users access to secure "
                    "communication. Our focus is on adapting "
                    "encryption technology to make it easy to use "
                    "and widely available. <br>"
                    "<br>"
                    "<a href='https://leap.se'>More about LEAP"
                    "</a>") % (VERSION,))

