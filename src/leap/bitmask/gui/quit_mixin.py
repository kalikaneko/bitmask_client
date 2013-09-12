# -*- coding: utf-8 -*-
# quit_mixin.py
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
Methods related to the shutdown of the client and quit.
"""
import logging

from PySide import QtCore

from leap.bitmask.platform_init import IS_WIN
if IS_WIN:
    from leap.bitmask.platform_init.locks import WindowsLock

logger = logging.getLogger(__name__)


class QuitMixin(QtCore.QObject):

    def quit(self):
        """
        Cleanup and tidely close the main window before quitting.
        """
        # TODO separate the shutting down of services from the
        # UI stuff.

        # Set this in case that the app is hidden
        qApp = QtCore.QCoreApplication.instance()
        qApp.setQuitOnLastWindowClosed(True)

        self._cleanup_and_quit()

        self._really_quit = True

        if self._wizard:
            self._wizard.close()

        if self._logger_window:
            self._logger_window.close()

        self.close()

        if self._quit_callback:
            self._quit_callback()

        logger.debug('Bye.')

    def _cleanup_pidfiles(self):
        """
        Removes lockfiles on a clean shutdown.

        Triggered after aboutToQuit signal.
        """
        if IS_WIN:
            WindowsLock.release_all_locks()

    def _cleanup_and_quit(self):
        """
        Call all the cleanup actions in a serialized way.
        Should be called from the quit function.
        """
        logger.debug('About to quit, doing cleanup...')

        if self._imap_service is not None:
            self._imap_service.stop()

        if self._srp_auth is not None:
            if self._srp_auth.get_session_id() is not None or \
               self._srp_auth.get_token() is not None:
                # XXX this can timeout after loong time: See #3368
                self._srp_auth.logout()

        if self._soledad:
            logger.debug("Closing soledad...")
            self._soledad.close()
        else:
            logger.error("No instance of soledad was found.")

        logger.debug('Terminating vpn')
        self._vpn.terminate(shutdown=True)

        if self._login_defer:
            logger.debug("Cancelling login defer.")
            self._login_defer.cancel()

        if self._download_provider_defer:
            logger.debug("Cancelling download provider defer.")
            self._download_provider_defer.cancel()

        # TODO missing any more cancels?

        logger.debug('Cleaning pidfiles')
        self._cleanup_pidfiles()
