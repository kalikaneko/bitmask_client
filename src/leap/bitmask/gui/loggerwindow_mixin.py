# -*- coding: utf-8 -*-
# loggerwindow_mixin.py
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
Methods related to the LoggerWindow
"""
import logging

from PySide import QtCore

from leap.bitmask.gui.loggerwindow import LoggerWindow
from leap.bitmask.util.leap_log_handler import LeapLogHandler

logger = logging.getLogger(__name__)


class LoggerWindowMixin(QtCore.QObject):

    def _uncheck_logger_button(self):
        """
        SLOT
        Sets the checked state of the loggerwindow button to false.
        """
        self.ui.btnShowLog.setChecked(False)

    def _get_leap_logging_handler(self):
        """
        Gets the leap handler from the top level logger

        :return: a logging handler or None
        :rtype: LeapLogHandler or None
        """
        leap_logger = logging.getLogger('leap')
        for h in leap_logger.handlers:
            if isinstance(h, LeapLogHandler):
                return h
        return None

    def _show_logger_window(self):
        """
        SLOT
        TRIGGERS:
          self.ui.action_show_logs.triggered
          self.ui.btnShowLog.clicked

        Displays the window with the history of messages logged until now
        and displays the new ones on arrival.
        """
        if self._logger_window is None:
            leap_log_handler = self._get_leap_logging_handler()
            if leap_log_handler is None:
                logger.error('Leap logger handler not found')
                return
            else:
                self._logger_window = LoggerWindow(handler=leap_log_handler)
                self._logger_window.setVisible(
                    not self._logger_window.isVisible())
                self.ui.btnShowLog.setChecked(self._logger_window.isVisible())
        else:
            self._logger_window.setVisible(not self._logger_window.isVisible())
            self.ui.btnShowLog.setChecked(self._logger_window.isVisible())

        self._logger_window.finished.connect(self._uncheck_logger_button)

    pass
