#!/usr/bin/env python
"""
"""

import re
import socket
import sys


_TYPES = {
    'pemlinweb': 'linweb',
    'pemlinng': 'lwng',
    'pemdublinng': 'lwng',
}


def get_host_type(hostname):
    for prefix, host_type in _TYPES.iteritems():
        if hostname.startswith(prefix):
            return host_type
    return 'other'


def main():
    print get_host_type(socket.getfqdn())
    return 0


if __name__ == '__main__':
    sys.exit(main())
