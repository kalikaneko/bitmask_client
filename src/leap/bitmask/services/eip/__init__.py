# -*- coding: utf-8 -*-
# __init__.py
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
Init module for leap.services.eip
"""
import os
import tempfile

from leap.bitmask.platform_init import IS_WIN


def get_eip_socket_host_and_port():
    """
    Returns the socket and port to be used for the EIP
    invocation.

    :returns: A tuple with host and port (host, port)
    :rtype: (str, str)
    """
    # TODO make this properly multiplatform
    # TODO get this out of gui/ ---> move to util

    if IS_WIN:
        host = "localhost"
        port = "9876"
    else:
        # XXX cleanup this on exit too
        host = os.path.join(tempfile.mkdtemp(prefix="leap-tmp"),
                            'openvpn.socket')
        port = "unix"
    return host, port

