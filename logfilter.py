#!/usr/bin/env python
"""
"""

import atexit
import collections
import glob
import os
import os.path
import re
import signal
import socket
import subprocess
import sys
import time
import threading

import findhost


# Rough and ready regex for parsing log lines.
LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+?\] '
    r'"(?P<method>\S+) (?P<uri>\S+?) HTTP/')


# Preset attack types in regex form
regexes = {
    "wp-login": re.compile("wp-login\.php"),
    "xmlrpc": re.compile("xmlrpc\.php"),
    "administrator": re.compile("administrator\.php$"),
}

# Bag of dics
matched = collections.defaultdict(lambda: collections.defaultdict(list))


# Threat list file containing short-form country-code, threat level, full country code name.
# We discard the third field.  It exists for reference purposes only.

threatfile = "threatfile"


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
        proc = subprocess.Popen(['geoiplookup6', '-f', 'GeoIPv6.dat', ip],
                                stdout=subprocess.PIPE)
    else:
        print >> sys.stderr, "IP address : %s not parsable"
    for line in proc.stdout:
        return geoip_parse(line)


def geoip_parse(line):
    r"""
    >>> geoip_parse("GeoIP Country Edition: IP Address not found\n") is None
    True
    >>> geoip_parse("GeoIP Country Edition: ES, Spain\n")
    'ES'
    """
    _, data = line.strip().split(': ', 1)
    if data == 'IP Address not found':
        return None
    return data.split(',', 1)[0]


def findlwngwebroot():
    p1 = subprocess.Popen(["redis-cli", '-s', '/var/lib/redis/redis.sock', 'KEYS', 'website-by-name:*'], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["tail", "-1"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    output,err = p2.communicate()
    p2.stdout.close()
    p3 = subprocess.Popen(["redis-cli", '-s', '/var/lib/redis/redis.sock', 'get', output.strip()], stdout=subprocess.PIPE)
    p4 = subprocess.Popen(['redis-decode-obj', '--type=vh_info_t'], stdin=p3.stdout, stdout=subprocess.PIPE)
    p3.stdout.close()
    p5 = subprocess.Popen(['awk', '/m_homedir/ { gsub(/"/,"") ; print $2 }'], stdin=p4.stdout, stdout=subprocess.PIPE)
    p4.stdout.close()
    output2,err = p5.communicate()
    p5.stdout.close()
    lwng_webroot_random_string = output2.split('/',5)[4]
    lwngwebroot = "/var/www/vhosts/" + lwng_webroot_random_string
    return lwngwebroot


# Creates threat[COUNTRYCODE] = [THREAT-LEVEL]
def threatlist_import():
    threat = {}
    f = open('threatfile')
    try:
        for line in f:
             key, val, _ = line.strip().split(' ', 2)
             threat[key] = val
    finally:
        f.close()
    return threat


# Threaded load monitor
def monitor_load():
    current_load = int(os.getloadavg()[0]) 
    print current_load
    start_load_monitor()


# Timer for load monitor
def start_load_monitor():
    thr = threading.Timer(5.0, monitor_load)
    thr.setDaemon(True)
    thr.start()


# Checked against preset regexes, stores in form matched[regexname][ip] = [epoch-time]
# i.e ; matched[wp-login][1.2.3.4] = [1472653064]
def preset_monitor(uri,ip,cc):
    for key, regex in regexes.iteritems():
        if regex.search(uri):
            print "matched key", key
            matched[key][ip].append(int(time.time()))
            print matched[key][ip]
            if len(matched[key][ip]) >= 2:
                if cleanup_matches(cc,key,ip,matched[key][ip]):
                    del matched[key][ip]


# Function for checking when a single IP has more than X hits on preset attack types
def cleanup_matches(cc,key,ip,match):
    print "Match =", cc, key, ip, len(match)
    curtime = int(time.time())
    print curtime
    print "Cleanup called on", ip, match
    flagged = 0
    should_delete = False
    for hit_time in match:
        if curtime - hit_time <= 60:
            flagged += 1
        if flagged >= 2:
            print "Blocking %s with %s bad flags"% (ip, flagged)
            print type(matched[key][ip])
            print matched[key][ip]
            block_single_ip(ip)
            should_delete = True
            return should_delete
            break


# Handler to determine IPv4 / IPv6 for blocker
def block_single_ip(ip):
    if is_valid_ipv4(ip):
        block_single_ipv4(ip)
    elif is_valid_ipv6(ip):
        block_single_ipv6(ip)


# Function for blocking single IPv4 IP in iptables.  No error checking, etc.
def block_single_ipv4(ip):
    p1 = subprocess.Popen(["iptables", "-A", "CHINATEST", "-s", ip, "-j", "DROP"])
    print "Blocked ipv4:", ip


# Function for blocking single IPv6 IP in iptables.  No error checking.
def block_single_ipv6(ip):
    p1 = subprocess.Popen(["ip6tables", "-A", "CHINATEST", "-s", ip, "-j", "DROP"])
    print "Blocked ipv6:", ip


def main():
    # auto-detect host type and set webroot accordingly.  Also accept from first argument
    host_type = findhost.get_host_type(socket.getfqdn())
    # Import threat list
    threatlist_import()
    # Start timer for checking load
    monitor_load()

    # Argument handlers
    if len(sys.argv) >= 2:
        webroots = sys.argv[1]
    elif host_type == "linweb":
        webroots = "/usr/local/pem/vhosts/"
    elif host_type == "lwng":
        webroots = findlwngwebroot()
    else:
        print >> sys.stderr, "Invalid host type '%s' for script" % host_type
        return 1
    
    # Get the GeoIP database path as the second argument, if present.

    geoip_db = "GeoIP.dat"
    if len(sys.argv) >= 3: 
        geoip_db = sys.argv[2]

    for item in filter_logs(follow_logs(glob_logs(webroots)), geoip_db):
        preset_monitor(item['uri'],item['ip'],item['cc'])
#       print "%(cc)s %(ip)s %(method)s %(uri)s" % item

    return 0


if __name__ == '__main__':
    sys.exit(main())
