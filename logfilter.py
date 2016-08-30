#!/usr/bin/env python
"""
"""

import atexit
import glob
import os
import os.path
import re
import signal
import subprocess
import sys
import socket

# Rough and ready regex for parsing log lines.
LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+?\] '
    r'"(?P<method>\S+) (?P<uri>\S+?) HTTP/')


def filter_logs(log_iter, geoip_db):
    """
    Filter the logs, adding the country code corresponding to the IP.
    """
    for item in log_iter:
        cc = geoip_lookup(item['ip'], geoip_db) or 'O1'
        item['cc'] = cc
        yield item

def follow_logs(paths):
    """
    Follow the given list of logs.
    """
    proc = subprocess.Popen(['tail', '-q', '-F', '-n0'] + paths,
                            stdout=subprocess.PIPE)

    def at_exit():
        os.kill(proc.pid, signal.SIGTERM)
        proc.wait()
    atexit.register(at_exit)

    for line in proc.stdout:
        match = LOG_LINE.match(line)
        if match is not None:
            yield match.groupdict()

def glob_logs(webroots_path):
    """
    Glob the log files.
    """
    paths = []
    for filename in ('access_log', 'ssl_access_log'):
        paths += glob.glob(os.path.join(webroots_path, '*/log', filename))
    return paths

    
def is_valid_addr(addr, family):
   try:
       socket.inet_pton(family, addr)
   except socket.error:
       return False
   return True


def is_valid_ipv4(addr):
   return is_valid_addr(addr, socket.AF_INET)


def is_valid_ipv6(addr):
   return is_valid_addr(addr, socket.AF_INET6)


def geoip_lookup(ip, path):
    """
    Do a GeoIP lookup of an IP against a given database.
    """
    # It's likely that we're going to be seeing the same IPs a lot in the same
    # short timespan, so some kind of memoisation would be good. This seems
    # like a good option that doesn't require any external dependencies:
    # http://seanblanchfield.com/python-memoize-with-expiry/
    if is_valid_ipv4(ip):
      proc = subprocess.Popen(['geoiplookup', '-f', path, ip],
                              stdout=subprocess.PIPE)
    elif is_valid_ipv6(ip):
      proc = subprocess.Popen(['geoiplookup6', '-f',  'GeoIPv6.dat', ip],
                              stdout=subprocess.PIPE)
    else:
      print "IP address : %s not parsable"
    for line in proc.stdout:
        return geoip_parse(line)

def geoip_parse(line):
    r"""
    >>> geoip_parse("GeoIP Country Edition: IP Address not found\n") is None
    True
    >>> geoip_parse("GeoIP Country Edition: ES, Spain\n")
    'ES'
    """
    #print >> sys.stderr, "[%s]" % line
    _, data = line.strip().split(': ', 1)
    if data == 'IP Address not found':
        return None
    return data.split(',', 1)[0]


def main():
    if len(sys.argv) < 2:
        print >> sys.stderr, "Please provide a webroots path."
        return 1

    # Get the webroots path as first argument
    webroots = sys.argv[1]
    # Get the GeoIP database path as the second argument, if present.
    geoip_db = 'GeoIP.dat' if len(sys.argv) == 2 else sys.argv[2]

    for item in filter_logs(follow_logs(glob_logs(webroots)), geoip_db):
        print "%(cc)s %(ip)s %(method)s %(uri)s" % item

    return 0


if __name__ == '__main__':
    sys.exit(main())
