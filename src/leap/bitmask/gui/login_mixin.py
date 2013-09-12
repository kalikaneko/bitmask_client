# -*- coding: utf-8 -*-
# login_mixin.py
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
Methods related to log in, used from MainWindow
"""
# TODO bring here the instantiation of the login_widget too
import logging
import keyring
from PySide import QtCore

from leap.bitmask.util.keyring_helpers import has_keyring
from leap.common.check import leap_assert

logger = logging.getLogger(__name__)


class LoginMixin(QtCore.QObject):
    """
    Methods related to the log in functionality.
    Inherited by the MainWindow widget.
    """

    # login/logout methods

    def _login(self):
        """
        SLOT
        TRIGGERS:
          self._login_widget.login

        Starts the login sequence. Which involves bootstrapping the
        selected provider if the selection is valid (not empty), then
        start the SRP authentication, and as the last step
        bootstrapping the EIP service
        """
        leap_assert(self._provider_config, "We need a provider config")

        username = self._login_widget.get_user()
        password = self._login_widget.get_password()
        provider = self._login_widget.get_selected_provider()

        self._enabled_services = self._settings.get_enabled_services(
            self._login_widget.get_selected_provider())

        if len(provider) == 0:
            self._login_widget.set_status(
                self.tr("Please select a valid provider"))
            return

        if len(username) == 0:
            self._login_widget.set_status(
                self.tr("Please provide a valid username"))
            return

        if len(password) == 0:
            self._login_widget.set_status(
                self.tr("Please provide a valid Password"))
            return

        self._login_widget.set_status(self.tr("Logging in..."), error=False)
        self._login_widget.set_enabled(False)

        if self._login_widget.get_remember() and has_keyring():
            # in the keyring and in the settings
            # we store the value 'usename@provider'
            username_domain = (username + '@' + provider).encode("utf8")
            try:
                keyring.set_password(self.KEYRING_KEY,
                                     username_domain,
                                     password.encode("utf8"))
                # Only save the username if it was saved correctly in
                # the keyring
                self._settings.set_user(username_domain)
            except Exception as e:
                logger.error("Problem saving data to keyring. %r"
                             % (e,))

        self._download_provider_config()

    def _cancel_login(self):
        """
        SLOT
        TRIGGERS:
          self._login_widget.cancel_login

        Stops the login sequence.
        """
        logger.debug("Cancelling log in.")

        if self._download_provider_defer:
            logger.debug("Cancelling download provider defer.")
            self._download_provider_defer.cancel()

        if self._login_defer:
            logger.debug("Cancelling login defer.")
            self._login_defer.cancel()

        self._login_widget.set_status(self.tr("Log in cancelled by the user."))

