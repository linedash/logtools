#!/usr/bin/env python
"""
"""

import socket
import re

hostname = socket.getfqdn()

def main():
  if re.match('^pemlinweb', hostname):
    hosttype = "linweb"
  elif re.match('^pemlinng', hostname):
    hosttype = "lwng"
  elif re.match('^pemdublinng', hostname):
    hosttype = "lwng"
  else:
    hosttype = "other"

  return hosttype
