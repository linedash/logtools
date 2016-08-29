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


# Rough and ready regex for parsing log lines.
LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+?\] '
    r'"(?P<method>\S+) (?P<uri>\S+?) HTTP/')


def glob_logs(webroots_path):
    """
    Glob the log files.
    """
    paths = []
    for filename in ('access_log', 'ssl_access_log'):
        paths += glob.glob(os.path.join(webroots_path, '*/log', filename))
    return paths


def follow_logs(paths):
    """
    Follow the given list of logs.
    """
    proc = subprocess.Popen(['tail', '-F', '-n0'] + paths,
                            stdout=subprocess.PIPE)

    def at_exit():
        os.kill(proc.pid, signal.SIGTERM)
        proc.wait()
    atexit.register(at_exit)

    for line in proc.stdout:
        match = LOG_LINE.match(line)
        if match is not None:
            yield match.groupdict()


def geoip_lookup(ip, path):
    """
    Do a GeoIP lookup of an IP against a given database.
    """
    # It's likely that we're going to be seeing the same IPs a lot in the same
    # short timespan, so some kind of memoisation would be good. This seems
    # like a good option that doesn't require any external dependencies:
    # http://seanblanchfield.com/python-memoize-with-expiry/
    proc = subprocess.Popen(['geoiplookup', '-F', path, ip],
                            stdout=subprocess.PIPE)
    for line in proc.stdout:
        _, data = line.split(': ', 1)
        if data == 'IP Address not found':
            return None
        cc, _ = data.split(',', 1)
        return cc


def filter_logs(log_iter, geoip_db):
    """
    Filter the logs, adding the country code corresponding to the IP.
    """
    for item in log_iter:
        cc = geoip_lookup(item['id'], geoip_db)
        if cc is None:
            continue
        item['cc'] = cc
        yield item


def main():
    if len(sys.argv) < 2:
        print >> sys.stderr, "Please provide a webroots path."
        return 1

    # Get the webroots path as first argument
    webroots = sys.argv[1]
    # Get the GeoIP database path as the second argument, if present.
    geoip_db = 'GeoIP.dat' if len(sys.argv) == 2 else sys.argv[2]

    for item in filter_logs(follow_logs(glob_logs(webroots)), geoip_db):
        print "%(cc)s %(ip)s %(method) %(uri)" % item

    return 0


if __name__ == '__main__':
    sys.exit(main())