# -*- coding: utf-8 -*-
# logout_mixin.py
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
Methods related to log out, used from MainWindow
"""
from PySide import QtCore

from twisted.internet import threads


class LogoutMixin(QtCore.QObject):
    """
    Methods related to log out.
    """
    # XXX define here the signal maybe?

    def _logout(self):
        """
        SLOT
        TRIGGER: self.ui.action_log_out.triggered

        Starts the logout sequence
        """

        self._soledad_bootstrapper.cancel_bootstrap()

        # XXX: If other defers are doing authenticated stuff, this
        # might conflict with those. CHECK!
        threads.deferToThread(self._srp_auth.logout)
        self.logout.emit()

    def _done_logging_out(self, ok, message):
        """
        SLOT
        TRIGGER: self._srp_auth.logout_finished

        Switches the stackedWidget back to the login stage after
        logging out
        """
        self._logged_user = None
        self.ui.action_log_out.setEnabled(False)
        self.ui.stackedWidget.setCurrentIndex(self.LOGIN_INDEX)
        self._login_widget.set_password("")
        self._login_widget.set_enabled(True)
        self._login_widget.set_status("")
        self.ui.btnPreferences.setEnabled(False)
