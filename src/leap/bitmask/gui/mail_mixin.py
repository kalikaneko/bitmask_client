# -*- coding: utf-8 -*-
# mail_mixin.py
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
Methods dealing with mail services.
"""
import logging

from PySide import QtCore

from leap.bitmask.services.mail import imap

logger = logging.getLogger(__name__)


class SoledadMixin(QtCore.QObject):
    """
    Methods related to the control of the soledad instance.
    """
    # XXX declare here soledad signal?

    def _set_soledad_ready(self):
        """
        SLOT
        TRIGGERS:
            self.soledad_ready

        It sets the soledad object as ready to use.
        """
        self._soledad_ready = True

    def _soledad_intermediate_stage(self, data):
        """
        SLOT
        TRIGGERS:
          self._soledad_bootstrapper.download_config

        If there was a problem, displays it, otherwise it does nothing.
        This is used for intermediate bootstrapping stages, in case
        they fail.
        """
        passed = data[self._soledad_bootstrapper.PASSED_KEY]
        if not passed:
            # TODO display in the GUI:
            # should pass signal to a slot in status_panel
            # that sets the global status
            logger.error("Soledad failed to start: %s" %
                         (data[self._soledad_bootstrapper.ERROR_KEY],))
            self._retry_soledad_connection()

    def _retry_soledad_connection(self):
        """
        Retries soledad connection.
        """
        logger.debug("Retrying soledad connection.")
        if self._soledad_bootstrapper.should_retry_initialization():
            self._soledad_bootstrapper.increment_retries_count()
            threads.deferToThread(
                self._soledad_bootstrapper.load_and_sync_soledad)
        else:
            logger.warning("Max number of soledad initialization "
                           "retries reached.")

    def _soledad_bootstrapped_stage(self, data):
        """
        SLOT
        TRIGGERS:
          self._soledad_bootstrapper.gen_key

        If there was a problem, displays it, otherwise it does nothing.
        This is used for intermediate bootstrapping stages, in case
        they fail.

        :param data: result from the bootstrapping stage for Soledad
        :type data: dict
        """
        passed = data[self._soledad_bootstrapper.PASSED_KEY]
        if not passed:
            logger.debug("ERROR on soledad bootstrapping:")
            logger.error(data[self._soledad_bootstrapper.ERROR_KEY])
            return
        else:
            logger.debug("Done bootstrapping Soledad")

            self._soledad = self._soledad_bootstrapper.soledad
            self._keymanager = self._soledad_bootstrapper.keymanager

        # Ok, now soledad is ready, so we can allow other things that
        # depend on soledad to start.

        # this will trigger start_imap_service
        self.soledad_ready.emit()

        # TODO connect all these activations to the soledad_ready
        # signal so the logic is clearer to follow.

        if self._provider_config.provides_mx() and \
                self._enabled_services.count(self.MX_SERVICE) > 0:
            self._smtp_bootstrapper.run_smtp_setup_checks(
                self._provider_config,
                self._smtp_config,
                True)
        else:
            if self._enabled_services.count(self.MX_SERVICE) > 0:
                pass  # TODO show MX status
                #self._status_panel.set_eip_status(
                #    self.tr("%s does not support MX") %
                #    (self._provider_config.get_domain(),),
                #                     error=True)
            else:
                pass  # TODO show MX status
                #self._status_panel.set_eip_status(
                #    self.tr("MX is disabled"))


class MailMixin(QtCore.QObject):
    """
    Methods related to mail services control (imap and smtp).
    """
    # XXX move here the initialization also.

    # Service control methods: smtp

    # TODO refactor this method ---
    def _smtp_bootstrapped_stage(self, data):
        """
        SLOT
        TRIGGERS:
          self._smtp_bootstrapper.download_config

        If there was a problem, displays it, otherwise it does nothing.
        This is used for intermediate bootstrapping stages, in case
        they fail.

        :param data: result from the bootstrapping stage for Soledad
        :type data: dict
        """
        passed = data[self._smtp_bootstrapper.PASSED_KEY]
        if not passed:
            logger.error(data[self._smtp_bootstrapper.ERROR_KEY])
            return
        logger.debug("Done bootstrapping SMTP")

        hosts = self._smtp_config.get_hosts()
        # TODO handle more than one host and define how to choose
        if len(hosts) > 0:
            hostname = hosts.keys()[0]
            logger.debug("Using hostname %s for SMTP" % (hostname,))
            host = hosts[hostname][self.IP_KEY].encode("utf-8")
            port = hosts[hostname][self.PORT_KEY]
            # TODO move the start to _start_smtp_service

            # TODO Make the encrypted_only configurable
            # TODO pick local smtp port in a better way
            # TODO remove hard-coded port and let leap.mail set
            # the specific default.

            from leap.mail.smtp import setup_smtp_relay
            client_cert = self._eip_config.get_client_cert_path(
                self._provider_config)
            self._smtp_service = setup_smtp_relay(
                port=2013,
                keymanager=self._keymanager,
                smtp_host=host,
                smtp_port=port,
                smtp_cert=client_cert,
                smtp_key=client_cert,
                encrypted_only=False)

    def _stop_smtp_service(self):
        """
        SLOT
        TRIGGERS:
            self.logout
        """
        # There is a subtle difference here:
        # we are stopping the factory for the smtp service here,
        # but in the imap case we are just stopping the fetcher.
        if self._smtp_service is not None:
            logger.debug('Stopping smtp service.')
            self._smtp_service.doStop()

    #
    # Service control methods: imap
    #

    def _start_imap_service(self):
        """
        SLOT
        TRIGGERS:
            self.soledad_ready
        """
        if self._provider_config.provides_mx() and \
                self._enabled_services.count(self.MX_SERVICE) > 0:
            logger.debug('Starting imap service')

            self._imap_service = imap.start_imap_service(
                self._soledad,
                self._keymanager)

    def _on_mail_client_logged_in(self, req):
        """
        Triggers qt signal when client login event is received.
        """
        self.mail_client_logged_in.emit()

    def _fetch_incoming_mail(self):
        """
        SLOT
        TRIGGERS:
            self.mail_client_logged_in
        """
        if self._imap_service:
            logger.debug('Client connected, fetching mail...')
            self._imap_service.fetch()

    def _stop_imap_service(self):
        """
        SLOT
        TRIGGERS:
            self.logout
        """
        # There is a subtle difference here:
        # we are just stopping the fetcher here,
        # but in the smtp case we are stopping the factory.
        # We should homogenize both services.
        if self._imap_service is not None:
            logger.debug('Stopping imap service.')
            self._imap_service.stop()
