# -*- coding: utf-8 -*-
# wizard_mixin.py
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
Wizard related methods.
"""
from PySide import QtCore

from leap.bitmask.gui.wizard.wizard import Wizard
from leap.bitmask.platform_init import IS_MAC


class WizardMixin(QtCore.QObject):
    """
    Methods related with wizard, to be called from Main Window
    """

    def _init_wizard(self, standalone=False,
                     bypass_checks=False):
        self._wizard_firstrun = True
        self._wizard = Wizard(standalone=standalone,
                              bypass_checks=bypass_checks)
        # Give this window time to finish init and then show the wizard
        QtCore.QTimer.singleShot(1, self._launch_wizard)
        self._wizard.accepted.connect(self._finish_init)
        self._wizard.rejected.connect(self._rejected_wizard)

    def _rejected_wizard(self):
        """
        SLOT
        TRIGGERS: self._wizard.rejected

        Called if the wizard has been cancelled or closed before
        finishing.
        """
        if self._wizard_firstrun:
            self._settings.set_properprovider(False)
            self.quit()
        else:
            self._finish_init()

    def _launch_wizard(self):
        """
        SLOT
        TRIGGERS:
          self._login_widget.show_wizard
          self.ui.action_wizard.triggered

        Also called in first run.

        Launches the wizard, creating the object itself if not already
        there.
        """
        if self._wizard is None:
            self._wizard = Wizard(bypass_checks=self._bypass_checks)
            self._wizard.accepted.connect(self._finish_init)
            self._wizard.rejected.connect(self._wizard.close)

        self.setVisible(False)
        # Do NOT use exec_, it will use a child event loop!
        # Refer to http://www.themacaque.com/?p=1067 for funny details.
        self._wizard.show()
        if IS_MAC:
            self._wizard.raise_()
        self._wizard.finished.connect(self._wizard_finished)

    def _wizard_finished(self):
        """
        SLOT
        TRIGGERS
          self._wizard.finished

        Called when the wizard has finished.
        """
        self.setVisible(True)
