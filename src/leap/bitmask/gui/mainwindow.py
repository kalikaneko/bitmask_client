# -*- coding: utf-8 -*-
# mainwindow.py
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
Main window for Bitmask.
"""
import logging
import os
import platform
import tempfile

import keyring

from PySide import QtCore, QtGui
from twisted.internet import threads

from leap.bitmask.config.leapsettings import LeapSettings
from leap.bitmask.config.providerconfig import ProviderConfig
from leap.bitmask.crypto.srpauth import SRPAuth
from leap.bitmask.gui.login import LoginWidget
from leap.bitmask.gui.statuspanel import StatusPanelWidget

# mixins
from leap.bitmask.gui.eip_mixin import EIPMixin
from leap.bitmask.gui.loggerwindow_mixin import LoggerWindowMixin
from leap.bitmask.gui.login_mixin import LoginMixin
from leap.bitmask.gui.logout_mixin import LogoutMixin
from leap.bitmask.gui.mail_mixin import MailMixin
from leap.bitmask.gui.mail_mixin import SoledadMixin
from leap.bitmask.gui.preferenceswindow import PreferencesMixin
from leap.bitmask.gui.tray_mixin import TrayMixin
from leap.bitmask.gui.updates_mixin import UpdatesMixin
from leap.bitmask.gui.wizard.mixins import WizardMixin
from leap.bitmask.gui.quit_mixin import QuitMixin

# services imports
from leap.bitmask.services.eip.eipbootstrapper import EIPBootstrapper
from leap.bitmask.services.eip.eipconfig import EIPConfig
from leap.bitmask.services.eip.providerbootstrapper import ProviderBootstrapper
# XXX: Soledad might not work out of the box in Windows, issue #2932
from leap.bitmask.services.soledad.soledadbootstrapper import \
    SoledadBootstrapper
from leap.bitmask.services.mail.smtpbootstrapper import SMTPBootstrapper
from leap.bitmask.platform_init import IS_MAC
from leap.bitmask.platform_init import IS_WIN
from leap.bitmask.platform_init.initializers import init_platform

from leap.bitmask.services.eip.vpnprocess import VPN

from leap.bitmask.util.keyring_helpers import has_keyring

from leap.bitmask.services.mail.smtpconfig import SMTPConfig

if IS_WIN:
    from leap.bitmask.platform_init.locks import raise_window_ack

from leap.common.check import leap_assert
from leap.common.events import register
from leap.common.events import events_pb2 as proto

from ui_mainwindow import Ui_MainWindow

logger = logging.getLogger(__name__)


class MainWindow(QtGui.QMainWindow, WizardMixin, LoggerWindowMixin,
                 PreferencesMixin, TrayMixin, LoginMixin, LogoutMixin,
                 UpdatesMixin, QuitMixin,
                 EIPMixin, SoledadMixin, MailMixin):
    """
    Main window for login and presenting status updates to the user
    """

    # StackedWidget indexes
    LOGIN_INDEX = 0
    EIP_STATUS_INDEX = 1

    # Keyring
    KEYRING_KEY = "bitmask"

    # SMTP
    PORT_KEY = "port"
    IP_KEY = "ip_address"

    OPENVPN_SERVICE = "openvpn"
    MX_SERVICE = "mx"

    # Signals
    new_updates = QtCore.Signal(object)
    raise_window = QtCore.Signal([])
    soledad_ready = QtCore.Signal([])
    mail_client_logged_in = QtCore.Signal([])
    logout = QtCore.Signal([])

    # We use this flag to detect abnormal terminations
    user_stopped_eip = False

    def __init__(self, quit_callback,
                 standalone=False,
                 openvpn_verb=1,
                 bypass_checks=False):
        """
        Constructor for the client main window

        :param quit_callback: Function to be called when closing
                              the application.
        :type quit_callback: callable

        :param standalone: Set to true if the app should use configs
                           inside its pwd
        :type standalone: bool

        :param bypass_checks: Set to true if the app should bypass
                              first round of checks for CA
                              certificates at bootstrap
        :type bypass_checks: bool
        """
        QtGui.QMainWindow.__init__(self)

        # register leap events ########################################
        register(signal=proto.UPDATER_NEW_UPDATES,
                 callback=self._new_updates_available,
                 reqcbk=lambda req, resp: None)  # make rpc call async
        register(signal=proto.RAISE_WINDOW,
                 callback=self._on_raise_window_event,
                 reqcbk=lambda req, resp: None)  # make rpc call async
        register(signal=proto.IMAP_CLIENT_LOGIN,
                 callback=self._on_mail_client_logged_in,
                 reqcbk=lambda req, resp: None)  # make rpc call async
        # end register leap events ####################################

        self._quit_callback = quit_callback

        self._updates_content = ""

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self._settings = LeapSettings(standalone)

        self._login_widget = LoginWidget(
            self._settings,
            self.ui.stackedWidget.widget(self.LOGIN_INDEX))
        self.ui.loginLayout.addWidget(self._login_widget)

        # Qt Signal Connections #####################################
        # TODO separate logic from ui signals.

        self._login_widget.login.connect(self._login)
        self._login_widget.cancel_login.connect(self._cancel_login)
        self._login_widget.show_wizard.connect(
            self._launch_wizard)

        # XXX move to loggerwindowmixin
        self.ui.btnShowLog.clicked.connect(self._show_logger_window)
        self.ui.btnPreferences.clicked.connect(self._show_preferences)

        self._status_panel = StatusPanelWidget(
            self.ui.stackedWidget.widget(self.EIP_STATUS_INDEX))
        self.ui.statusLayout.addWidget(self._status_panel)

        self.ui.stackedWidget.setCurrentIndex(self.LOGIN_INDEX)

        self._status_panel.start_eip.connect(self._start_eip)
        self._status_panel.stop_eip.connect(self._stop_eip)

        # This is loaded only once, there's a bug when doing that more
        # than once
        self._standalone = standalone
        self._provider_config = ProviderConfig()
        # Used for automatic start of EIP
        self._provisional_provider_config = ProviderConfig()
        self._eip_config = EIPConfig()

        self._already_started_eip = False

        # This is created once we have a valid provider config
        self._srp_auth = None
        self._logged_user = None

        # This thread is always running, although it's quite
        # lightweight when it's done setting up provider
        # configuration and certificate.
        self._provider_bootstrapper = ProviderBootstrapper(bypass_checks)

        # Intermediate stages, only do something if there was an error
        self._provider_bootstrapper.name_resolution.connect(
            self._intermediate_stage)
        self._provider_bootstrapper.https_connection.connect(
            self._intermediate_stage)
        self._provider_bootstrapper.download_ca_cert.connect(
            self._intermediate_stage)

        # Important stages, loads the provider config and checks
        # certificates
        self._provider_bootstrapper.download_provider_info.connect(
            self._load_provider_config)
        self._provider_bootstrapper.check_api_certificate.connect(
            self._provider_config_loaded)

        # This thread is similar to the provider bootstrapper
        self._eip_bootstrapper = EIPBootstrapper()

        # TODO change the name of "download_config" signal to
        # something less confusing (config_ready maybe)
        self._eip_bootstrapper.download_config.connect(
            self._eip_intermediate_stage)
        self._eip_bootstrapper.download_client_certificate.connect(
            self._finish_eip_bootstrap)

        self._soledad_bootstrapper = SoledadBootstrapper()
        self._soledad_bootstrapper.download_config.connect(
            self._soledad_intermediate_stage)
        self._soledad_bootstrapper.gen_key.connect(
            self._soledad_bootstrapped_stage)
        self._soledad_bootstrapper.soledad_timeout.connect(
            self._retry_soledad_connection)

        self._smtp_bootstrapper = SMTPBootstrapper()
        self._smtp_bootstrapper.download_config.connect(
            self._smtp_bootstrapped_stage)

        self._vpn = VPN(openvpn_verb=openvpn_verb)
        self._vpn.qtsigs.state_changed.connect(
            self._status_panel.update_vpn_state)
        self._vpn.qtsigs.status_changed.connect(
            self._status_panel.update_vpn_status)
        self._vpn.qtsigs.process_finished.connect(
            self._eip_finished)

        self.ui.action_log_out.setEnabled(False)
        self.ui.action_log_out.triggered.connect(self._logout)
        self.ui.action_about_leap.triggered.connect(self._about)
        self.ui.action_quit.triggered.connect(self.quit)
        self.ui.action_wizard.triggered.connect(self._launch_wizard)
        self.ui.action_show_logs.triggered.connect(self._show_logger_window)
        self.raise_window.connect(self._do_raise_mainwindow)

        # Used to differentiate between real quits and close to tray
        self._really_quit = False

        self._systray = None

        self._action_eip_provider = QtGui.QAction(
            self.tr("No default provider"), self)
        self._action_eip_provider.setEnabled(False)

        self._action_eip_status = QtGui.QAction(
            self.tr("Encrypted Internet is OFF"),
            self)
        self._action_eip_status.setEnabled(False)
        self._status_panel.set_action_eip_status(
            self._action_eip_status)

        self._action_mail_status = QtGui.QAction(
            self.tr("Encrypted Mail is OFF"), self)
        self._action_mail_status.setEnabled(False)
        self._status_panel.set_action_mail_status(
            self._action_mail_status)

        self._action_eip_startstop = QtGui.QAction(
            self.tr("Turn OFF"), self)
        self._action_eip_startstop.triggered.connect(
            self._stop_eip)
        self._action_eip_startstop.setEnabled(False)
        self._status_panel.set_action_eip_startstop(
            self._action_eip_startstop)

        # XXX move to preferencesmixin
        self._action_preferences = QtGui.QAction(self.tr("Preferences"), self)
        self._action_preferences.triggered.connect(self._show_preferences)

        self._action_visible = QtGui.QAction(self.tr("Hide Main Window"), self)
        self._action_visible.triggered.connect(self._toggle_visible)

        self._enabled_services = []

        self._center_window()

        self.ui.lblNewUpdates.setVisible(False)
        self.ui.btnMore.setVisible(False)
        self.ui.btnMore.clicked.connect(self._updates_details)

        # Services signals/slots connection
        self.new_updates.connect(self._react_to_new_updates)
        self.soledad_ready.connect(self._start_imap_service)
        self.soledad_ready.connect(self._set_soledad_ready)
        self.mail_client_logged_in.connect(self._fetch_incoming_mail)
        self.logout.connect(self._stop_imap_service)
        self.logout.connect(self._stop_smtp_service)

        ################################# end Qt Signals connection ########

        init_platform()

        self._wizard = None
        self._wizard_firstrun = False

        self._logger_window = None

        self._bypass_checks = bypass_checks

        self._soledad = None
        self._soledad_ready = False
        self._keymanager = None
        self._smtp_service = None
        self._imap_service = None

        self._login_defer = None
        self._download_provider_defer = None

        self._smtp_config = SMTPConfig()

        if self._first_run():
            # XXX get standalone flag from inside function call
            self._init_wizard(standalone=standalone,
                              bypass_checks=bypass_checks)
        else:
            self._finish_init()

    # TODO SPLIT AND REFACTOR THIS METHOD -----

    def _finish_init(self):
        """
        SLOT
        TRIGGERS:
          self._wizard.accepted

        Also called at the end of the constructor if not first run,
        and after _rejected_wizard if not first run.

        Implements the behavior after either constructing the
        mainwindow object, loading the saved user/password, or after
        the wizard has been executed.
        """

        providers = self._settings.get_configured_providers()
        self._login_widget.set_providers(providers)
        self._show_systray()
        self.show()
        if IS_MAC:
            self.raise_()

        if self._wizard:
            possible_username = self._wizard.get_username()
            possible_password = self._wizard.get_password()

            # select the configured provider in the combo box
            domain = self._wizard.get_domain()
            self._login_widget.select_provider_by_name(domain)

            self._login_widget.set_remember(self._wizard.get_remember())
            self._enabled_services = list(self._wizard.get_services())
            self._settings.set_enabled_services(
                self._login_widget.get_selected_provider(),
                self._enabled_services)
            if possible_username is not None:
                self._login_widget.set_user(possible_username)
            if possible_password is not None:
                self._login_widget.set_password(possible_password)
                self._login()
            self._wizard = None
            self._settings.set_properprovider(True)
        else:
            self._try_autostart_eip()
            if not self._settings.get_remember():
                # nothing to do here
                return

            saved_user = self._settings.get_user()

            try:
                username, domain = saved_user.split('@')
            except (ValueError, AttributeError) as e:
                # if the saved_user does not contain an '@' or its None
                logger.error('Username@provider malformed. %r' % (e, ))
                saved_user = None

            if saved_user is not None and has_keyring():
                # fill the username
                self._login_widget.set_user(username)

                # select the configured provider in the combo box
                self._login_widget.select_provider_by_name(domain)

                self._login_widget.set_remember(True)

                saved_password = None
                try:
                    saved_password = keyring.get_password(self.KEYRING_KEY,
                                                          saved_user
                                                          .encode("utf8"))
                except ValueError, e:
                    logger.debug("Incorrect Password. %r." % (e,))

                if saved_password is not None:
                    self._login_widget.set_password(
                        saved_password.decode("utf8"))
                    self._login()

    def _first_run(self):
        """
        Returns True if there are no configured providers. False otherwise

        :rtype: bool
        """
        providers = self._settings.get_configured_providers()
        has_provider_on_disk = len(providers) != 0
        is_proper_provider = self._settings.get_properprovider()
        return not (has_provider_on_disk and is_proper_provider)

    # providerconfig methods

    def _download_provider_config(self):
        """
        Starts the bootstrapping sequence. It will download the
        provider configuration if it's not present, otherwise will
        emit the corresponding signals inmediately
        """
        # TODO rename to "start_boostrapping" or similar?
        provider = self._login_widget.get_selected_provider()

        pb = self._provider_bootstrapper
        d = pb.run_provider_select_checks(provider, download_if_needed=True)
        self._download_provider_defer = d

    def _load_provider_config(self, data):
        """
        SLOT
        TRIGGER: self._provider_bootstrapper.download_provider_info

        Once the provider config has been downloaded, this loads the
        self._provider_config instance with it and starts the second
        part of the bootstrapping sequence

        :param data: result from the last stage of the
        run_provider_select_checks
        :type data: dict
        """
        if data[self._provider_bootstrapper.PASSED_KEY]:
            provider = self._login_widget.get_selected_provider()

            # If there's no loaded provider or
            # we want to connect to other provider...
            if (not self._provider_config.loaded() or
                    self._provider_config.get_domain() != provider):
                self._provider_config.load(
                    os.path.join("leap", "providers",
                                 provider, "provider.json"))

            if self._provider_config.loaded():
                self._provider_bootstrapper.run_provider_setup_checks(
                    self._provider_config,
                    download_if_needed=True)
            else:
                self._login_widget.set_status(
                    self.tr("Unable to login: Problem with provider"))
                logger.error("Could not load provider configuration.")
                self._login_widget.set_enabled(True)
        else:
            self._login_widget.set_status(
                self.tr("Unable to login: Problem with provider"))
            logger.error(data[self._provider_bootstrapper.ERROR_KEY])
            self._login_widget.set_enabled(True)


    def _get_best_provider_config(self):
        """
        Returns the best ProviderConfig to use at a moment. We may
        have to use self._provider_config or
        self._provisional_provider_config depending on the start
        status.

        :rtype: ProviderConfig
        """
        leap_assert(self._provider_config is not None or
                    self._provisional_provider_config is not None,
                    "We need a provider config")

        provider_config = None
        if self._provider_config.loaded():
            provider_config = self._provider_config
        elif self._provisional_provider_config.loaded():
            provider_config = self._provisional_provider_config
        else:
            leap_assert(False, "We could not find any usable ProviderConfig.")

        return provider_config

    def _provider_config_loaded(self, data):
        """
        SLOT
        TRIGGER: self._provider_bootstrapper.check_api_certificate

        Once the provider configuration is loaded, this starts the SRP
        authentication
        """
        leap_assert(self._provider_config, "We need a provider config!")

        if data[self._provider_bootstrapper.PASSED_KEY]:
            username = self._login_widget.get_user().encode("utf8")
            password = self._login_widget.get_password().encode("utf8")

            if self._srp_auth is None:
                self._srp_auth = SRPAuth(self._provider_config)
                self._srp_auth.authentication_finished.connect(
                    self._authentication_finished)
                self._srp_auth.logout_finished.connect(
                    self._done_logging_out)

            # TODO Add errback!
            self._login_defer = self._srp_auth.authenticate(username, password)
        else:
            self._login_widget.set_status(
                "Unable to login: Problem with provider")
            logger.error(data[self._provider_bootstrapper.ERROR_KEY])
            self._login_widget.set_enabled(True)

    def _authentication_finished(self, ok, message):
        """
        SLOT
        TRIGGER: self._srp_auth.authentication_finished

        Once the user is properly authenticated, try starting the EIP
        service
        """

        # In general we want to "filter" likely complicated error
        # messages, but in this case, the messages make more sense as
        # they come. Since they are "Unknown user" or "Unknown
        # password"

        # XXX FIX UNKNOWN USER MESSAGE -- see #3656
        self._login_widget.set_status(message, error=not ok)

        if ok:
            self._logged_user = self._login_widget.get_user()
            self.ui.action_log_out.setEnabled(True)
            # We leave a bit of room for the user to see the
            # "Succeeded" message and then we switch to the EIP status
            # panel
            QtCore.QTimer.singleShot(1000, self._switch_to_status)
            self._login_defer = None
        else:
            self._login_widget.set_enabled(True)

    # window handling

    def _on_raise_window_event(self, req):
        """
        Callback for the raise window event
        """
        if IS_WIN:
            raise_window_ack()
        self.raise_window.emit()

    def _do_raise_mainwindow(self):
        """
        SLOT
        TRIGGERS:
            self._on_raise_window_event

        Triggered when we receive a RAISE_WINDOW event.
        """
        TOPFLAG = QtCore.Qt.WindowStaysOnTopHint
        self.setWindowFlags(self.windowFlags() | TOPFLAG)
        self.show()
        self.setWindowFlags(self.windowFlags() & ~TOPFLAG)
        self.show()
        if IS_MAC:
            self.raise_()

    # Display methods

    def _switch_to_status(self):
        """
        Changes the stackedWidget index to the EIP status one and
        triggers the eip bootstrapping
        """
        if not self._already_started_eip:
            self._status_panel.set_provider(
                "%s@%s" % (self._login_widget.get_user(),
                           self._get_best_provider_config().get_domain()))

        self.ui.stackedWidget.setCurrentIndex(self.EIP_STATUS_INDEX)

        # XXX this does not make much sense to me HERE at
        # this point. We should communicate CLEAR_TO_PROCEED or
        # something similar to soledad and eip, but only when the connection
        # has been made, I think.

        # FIXME refactor with State Machine --- move to
        # services triggered method ------------------------

        self._soledad_bootstrapper.run_soledad_setup_checks(
            self._provider_config,
            self._login_widget.get_user(),
            self._login_widget.get_password(),
            download_if_needed=True,
            standalone=self._standalone)

        self._download_eip_config()
        # end refactor: services triggered method -----------

    # -------------------------------------------------------
    # XXX undecided

    def _get_socket_host(self):
        """
        Returns the socket and port to be used for VPN

        :rtype: tuple (str, str) (host, port)
        """
        # TODO make this properly multiplatform
        # TODO get this out of gui/ ---> move to util

        if platform.system() == "Windows":
            host = "localhost"
            port = "9876"
        else:
            # XXX cleanup this on exit too
            host = os.path.join(tempfile.mkdtemp(prefix="leap-tmp"),
                                'openvpn.socket')
            port = "unix"

        return host, port

    # for some reasons, the methods for the Events below cannot be
    # inside mixins. So lets leave them here in peace.

    def changeEvent(self, e):
        """
        Reimplements the changeEvent method to minimize to tray
        """
        if QtGui.QSystemTrayIcon.isSystemTrayAvailable() and \
                e.type() == QtCore.QEvent.WindowStateChange and \
                self.isMinimized():
            self._toggle_visible()
            e.accept()
            return
        QtGui.QMainWindow.changeEvent(self, e)

    def closeEvent(self, e):
        """
        Reimplementation of closeEvent to close to tray
        """
        if QtGui.QSystemTrayIcon.isSystemTrayAvailable() and \
                not self._really_quit:
            self._toggle_visible()
            e.ignore()
            return

        self._settings.set_geometry(self.saveGeometry())
        self._settings.set_windowstate(self.saveState())

        QtGui.QMainWindow.closeEvent(self, e)
