# -*- coding: utf-8 -*-
# eip_mixin.py
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
Methods dealing with EIP service.

TODO This module still needs heavy refactoring. We should decouple gui-related
     events and displays from internal EIP  logic as much as possible.
     Ideally, this should consist only of display reacting to events triggered
     by inner layers (we can bring back the idea of the EIP conductor, tightly
     coupled with the generic client state machine that we are working on)
"""
import logging
import os

from PySide import QtCore

from leap.bitmask.services.eip.vpnprocess import OpenVPNAlreadyRunning
from leap.bitmask.services.eip.vpnprocess import AlienOpenVPNAlreadyRunning

# XXX move exceptions to eip.__init__
from leap.bitmask.services.eip.vpnlaunchers import VPNLauncherException
from leap.bitmask.services.eip.vpnlaunchers import OpenVPNNotFoundException
from leap.bitmask.services.eip.vpnlaunchers import EIPNoPkexecAvailable
from leap.bitmask.services.eip.vpnlaunchers import \
    EIPNoPolkitAuthAgentAvailable
from leap.bitmask.services.eip.vpnlaunchers import EIPNoTunKextLoaded

from leap.bitmask.services.eip import get_eip_socket_host_and_port
from leap.bitmask.platform_init import IS_MAC

from leap.common.check import leap_assert

logger = logging.getLogger(__name__)


class EIPMixin(QtCore.QObject):
    # TODO move initialization bits here too

    def _try_autostart_eip(self):
        """
        Tries to autostart EIP
        """
        default_provider = self._settings.get_defaultprovider()

        if default_provider is None:
            logger.info("Cannot autostart Encrypted Internet because there is "
                        "no default provider configured")
            return

        self._action_eip_provider.setText(default_provider)

        self._enabled_services = self._settings.get_enabled_services(
            default_provider)

        if self._provisional_provider_config.load(
            os.path.join("leap",
                         "providers",
                         default_provider,
                         "provider.json")):
            self._download_eip_config()
        else:
            # XXX: Display a proper message to the user
            logger.error("Unable to load %s config, cannot autostart." %
                         (default_provider,))

    def _start_eip(self):
        """
        SLOT
        TRIGGERS:
          self._status_panel.start_eip
          self._action_eip_startstop.triggered
        or called from _finish_eip_bootstrap

        Starts EIP
        """
        self._status_panel.eip_pre_up()
        self.user_stopped_eip = False
        provider_config = self._get_best_provider_config()

        try:
            host, port = get_eip_socket_host_and_port()
            self._vpn.start(eipconfig=self._eip_config,
                            providerconfig=provider_config,
                            socket_host=host,
                            socket_port=port)

            self._settings.set_defaultprovider(
                provider_config.get_domain())

            provider = provider_config.get_domain()
            if self._logged_user is not None:
                provider = "%s@%s" % (self._logged_user, provider)

            self._status_panel.set_provider(provider)

            self._action_eip_provider.setText(provider_config.get_domain())

            self._status_panel.eip_started()

            # XXX refactor into status_panel method?
            self._action_eip_startstop.setText(self.tr("Turn OFF"))
            self._action_eip_startstop.disconnect(self)
            self._action_eip_startstop.triggered.connect(
                self._stop_eip)
        except EIPNoPolkitAuthAgentAvailable:
            self._status_panel.set_global_status(
                # XXX this should change to polkit-kde where
                # applicable.
                self.tr("We could not find any "
                        "authentication "
                        "agent in your system.<br/>"
                        "Make sure you have "
                        "<b>polkit-gnome-authentication-"
                        "agent-1</b> "
                        "running and try again."),
                error=True)
            self._set_eipstatus_off()
        except EIPNoTunKextLoaded:
            self._status_panel.set_global_status(
                self.tr("Encrypted Internet cannot be started because "
                        "the tuntap extension is not installed properly "
                        "in your system."))
            self._set_eipstatus_off()
        except EIPNoPkexecAvailable:
            self._status_panel.set_global_status(
                self.tr("We could not find <b>pkexec</b> "
                        "in your system."),
                error=True)
            self._set_eipstatus_off()
        except OpenVPNNotFoundException:
            self._status_panel.set_global_status(
                self.tr("We could not find openvpn binary."),
                error=True)
            self._set_eipstatus_off()
        except OpenVPNAlreadyRunning as e:
            self._status_panel.set_global_status(
                self.tr("Another openvpn instance is already running, and "
                        "could not be stopped."),
                error=True)
            self._set_eipstatus_off()
        except AlienOpenVPNAlreadyRunning as e:
            self._status_panel.set_global_status(
                self.tr("Another openvpn instance is already running, and "
                        "could not be stopped because it was not launched by "
                        "Bitmask. Please stop it and try again."),
                error=True)
            self._set_eipstatus_off()
        except VPNLauncherException as e:
            # XXX We should implement again translatable exceptions so
            # we can pass a translatable string to the panel (usermessage attr)
            self._status_panel.set_global_status("%s" % (e,), error=True)
            self._set_eipstatus_off()
        else:
            self._already_started_eip = True

    def _stop_eip(self, abnormal=False):
        """
        SLOT
        TRIGGERS:
          self._status_panel.stop_eip
          self._action_eip_startstop.triggered
        or called from _eip_finished

        Stops vpn process and makes gui adjustments to reflect
        the change of state.

        :param abnormal: whether this was an abnormal termination.
        :type abnormal: bool
        """
        if abnormal:
            logger.warning("Abnormal EIP termination.")

        self.user_stopped_eip = True
        self._vpn.terminate()

        self._set_eipstatus_off()

        self._already_started_eip = False
        self._settings.set_defaultprovider(None)
        if self._logged_user:
            self._status_panel.set_provider(
                "%s@%s" % (self._logged_user,
                           self._get_best_provider_config().get_domain()))

    def _download_eip_config(self):
        """
        Starts the EIP bootstrapping sequence
        """
        leap_assert(self._eip_bootstrapper, "We need an eip bootstrapper!")

        provider_config = self._get_best_provider_config()

        if provider_config.provides_eip() and \
                self._enabled_services.count(self.OPENVPN_SERVICE) > 0 and \
                not self._already_started_eip:

            self._status_panel.set_eip_status(
                self.tr("Starting..."))
            self._eip_bootstrapper.run_eip_setup_checks(
                provider_config,
                download_if_needed=True)
            self._already_started_eip = True
        elif not self._already_started_eip:
            if self._enabled_services.count(self.OPENVPN_SERVICE) > 0:
                self._status_panel.set_eip_status(
                    self.tr("Not supported"),
                    error=True)
            else:
                self._status_panel.set_eip_status(self.tr("Disabled"))
            self._status_panel.set_startstop_enabled(False)

    def _finish_eip_bootstrap(self, data):
        """
        SLOT
        TRIGGER: self._eip_bootstrapper.download_client_certificate

        Starts the VPN thread if the eip configuration is properly
        loaded
        """
        leap_assert(self._eip_config, "We need an eip config!")
        passed = data[self._eip_bootstrapper.PASSED_KEY]

        if not passed:
            error_msg = self.tr("There was a problem with the provider")
            self._status_panel.set_eip_status(error_msg, error=True)
            logger.error(data[self._eip_bootstrapper.ERROR_KEY])
            self._already_started_eip = False
            return

        provider_config = self._get_best_provider_config()

        domain = provider_config.get_domain()

        loaded = self._eip_config.loaded()
        if not loaded:
            eip_config_path = os.path.join("leap", "providers",
                                           domain, "eip-service.json")
            api_version = provider_config.get_api_version()
            self._eip_config.set_api_version(api_version)
            loaded = self._eip_config.load(eip_config_path)

        if loaded:
            self._start_eip()
        else:
            self._status_panel.set_eip_status(
                self.tr("Could not load Encrypted Internet "
                        "Configuration."),
                error=True)

    def _intermediate_stage(self, data):
        """
        SLOT
        TRIGGERS:
          self._provider_bootstrapper.name_resolution
          self._provider_bootstrapper.https_connection
          self._provider_bootstrapper.download_ca_cert
          self._eip_bootstrapper.download_config

        If there was a problem, displays it, otherwise it does nothing.
        This is used for intermediate bootstrapping stages, in case
        they fail.
        """
        passed = data[self._provider_bootstrapper.PASSED_KEY]
        if not passed:
            self._login_widget.set_enabled(True)
            self._login_widget.set_status(
                self.tr("Unable to connect: Problem with provider"))
            logger.error(data[self._provider_bootstrapper.ERROR_KEY])

    def _eip_intermediate_stage(self, data):
        """
        SLOT
        TRIGGERS:
          self._eip_bootstrapper.download_config

        If there was a problem, displays it, otherwise it does nothing.
        This is used for intermediate bootstrapping stages, in case
        they fail.
        """
        passed = data[self._provider_bootstrapper.PASSED_KEY]
        if not passed:
            self._login_widget.set_status(
                self.tr("Unable to connect: Problem with provider"))
            logger.error(data[self._provider_bootstrapper.ERROR_KEY])
            self._already_started_eip = False

    def _eip_finished(self, exitCode):
        """
        SLOT
        TRIGGERS:
          self._vpn.process_finished

        Triggered when the EIP/VPN process finishes to set the UI
        accordingly.
        """
        logger.info("VPN process finished with exitCode %s..."
                    % (exitCode,))

        # Ideally we would have the right exit code here,
        # but the use of different wrappers (pkexec, cocoasudo) swallows
        # the openvpn exit code so we get zero exit in some cases  where we
        # shouldn't. As a workaround we just use a flag to indicate
        # a purposeful switch off, and mark everything else as unexpected.

        # In the near future we should trigger a native notification from here,
        # since the user really really wants to know she is unprotected asap.
        # And the right thing to do will be to fail-close.

        # TODO we should have a way of parsing the latest lines in the vpn
        # log buffer so we can have a more precise idea of which type
        # of error did we have (server side, local problem, etc)
        abnormal = True

        # XXX check if these exitCodes are pkexec/cocoasudo specific
        if exitCode in (126, 127):
            self._status_panel.set_global_status(
                self.tr("Encrypted Internet could not be launched "
                        "because you did not authenticate properly."),
                error=True)
            self._vpn.killit()
        elif exitCode != 0 or not self.user_stopped_eip:
            self._status_panel.set_global_status(
                self.tr("Encrypted Internet finished in an "
                        "unexpected manner!"), error=True)
        else:
            abnormal = False
        if exitCode == 0 and IS_MAC:
            # XXX remove this warning after I fix cocoasudo.
            logger.warning("The above exit code MIGHT BE WRONG.")
        self._stop_eip(abnormal)

    # status ?? ---------------------------------------------

    def _set_eipstatus_off(self):
        """
        Sets eip status to off
        """
        # XXX communicate with status panel via signals !!!
        self._status_panel.set_eip_status(self.tr("OFF"), error=True)
        self._status_panel.set_eip_status_icon("error")
        self._status_panel.set_startstop_enabled(True)
        self._status_panel.eip_stopped()

        self._set_action_eipstart_off()

    def _set_action_eipstart_off(self):
        """
        Sets eip startstop action to OFF status.
        """
        # XXX communicate with status panel via signals !!!
        self._action_eip_startstop.setText(self.tr("Turn ON"))
        self._action_eip_startstop.disconnect(self)
        self._action_eip_startstop.triggered.connect(
            self._start_eip)
