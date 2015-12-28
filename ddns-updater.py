#!/usr/bin/python
"""
Updater for Dynamic DNS on Namecheap Domains
Performs an update for each given domain access token in
the hosts.json file.
"""
import ctypes
import json
import logging
import os
import sys
import xml.etree.ElementTree as ET
from urllib.request import urlopen

import requests


class SearchStack(list):
    found_top = False

    def peek(self):
        val = self.pop()
        self.append(val)
        return val


FILE_ATTRIBUTE_HIDDEN = 0x02
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_FILENAME = 'cachedip.txt'
CACHE_FILE_PATH = os.path.join(SCRIPT_PATH, CACHE_FILENAME)
LOG_LOCATION = os.path.join(SCRIPT_PATH, "logs")

# Create log location if it does not exist
locations = SearchStack((LOG_LOCATION,))
while len(locations) > 0:
    if os.path.exists(locations.peek()):
        locations.pop()
        locations.found_top = True
    elif locations.found_top:
        os.mkdir(locations.pop())
    else:
        head, tail = os.path.split(locations.peek())
        locations.append(head)
del locations

# Logging
log_format = logging.Formatter("[%(levelname)s] %(asctime)s -- %(message)s")  # set log format
stdout_handler = logging.StreamHandler(sys.stdout)  # setup destinations for logger
stderr_handler = logging.StreamHandler(sys.stderr)
outfile_handler = logging.FileHandler(os.path.join(LOG_LOCATION, "output.log"))
errfile_handler = logging.FileHandler(os.path.join(LOG_LOCATION, "errors.log"))
stderr_handler.setFormatter(log_format)  # setup output format for destinations
stdout_handler.setFormatter(log_format)
outfile_handler.setFormatter(log_format)
errfile_handler.setFormatter(log_format)
stdout_handler.setLevel(logging.INFO)  # setup logging levels for destinations
stderr_handler.setLevel(logging.ERROR)
outfile_handler.setLevel(logging.INFO)
errfile_handler.setLevel(logging.ERROR)

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)
log.addHandler(outfile_handler)
log.addHandler(errfile_handler)
log.addHandler(stderr_handler)
log.addHandler(stdout_handler)


def hide_file_windows(filename):
    """
    Sets the FILE_ATTRIBUTE_HIDDEN flag on a file on Windows platforms. (Deprecated)

    Args:
        filename: The full path to the file to be hidden
    Raises:
        WinError: The file could not be hidden
    """
    ret = ctypes.windll.kernel32.SetFileAttributes(filename, FILE_ATTRIBUTE_HIDDEN)
    if ret:
        log.info('Cache attribute set to Hidden')
    else:  # return code of zero indicates failure, raise Windows error
        log.error("File could not be set to Hidden!")
        raise ctypes.WinError(ret)


def get_cached_ip():
    """
    Retrieve Cached IP From File, cuts down on API requests if
    IP Address hasn't changed.

    Returns: 
        cached_ip: Cached IP or 0 to force refresh of public IP
    """
    try:
        cached_file = open(CACHE_FILE_PATH, 'r')
        cached_ip = cached_file.read()
        cached_file.close()
        return cached_ip
    except IOError as error:
        log.error("Error reading cache. Errno error: {0}".format(error.errno))
        return "0"


def set_cached_ip(ip):
    """
    Stores IP Address in the Cache

    Args:
        ip: Address to be Cached
    Raises:

    """
    try:
        cached_file = open(CACHE_FILE_PATH, 'w')
        cached_file.write(ip)
        cached_file.close()
        # hide_file_windows(CACHE_FILE_PATH)
    except (IOError or ctypes.WinError) as e:
        log.error("{0}".format(e))


def get_ip():
    """
    Retrieves public IP (from httpbin) with cached IP and returns import

    Returns:
        Public IP as a string
    """

    response = urlopen('https://httpbin.org/ip')
    if response.status != 200:
        log.error("Status: {0} Reason: {1}}".format(response.status, response.reason))
        sys.exit(2)
    response_text = (response.read()).decode("utf-8")

    public_ip = json.loads(response_text)['origin']
    return public_ip


def load_hosts():
    """
    Loads the hosts.json file containing access tokens for EasyDNS

    Returns: 
        A dictionary of hosts and access tokens, e.g 

        {
            "example-host": [
                {
                    "subdomain": "test",
                    "token": "678dxjvid928skf"
                },
                {
                    "subdomain": "test2",
                    "token": "567doj049928s35"
                }
            ],
            "example-host2": [
                {
                    "subdomain": "@",
                    "token": "8299fd0as88fd8d"
                }
            ]
        }
        Note: submit @ for subdomain if there isn't one.
    """
    try:
        hosts_file = open(os.path.join(SCRIPT_PATH, 'hosts.json'), 'r')
        hosts_data = json.load(hosts_file)
        return hosts_data
    except IOError as e:
        log.error("{0}".format(e))
        sys.exit(1)


def update_host(token, current_ip, domain, subdomain='@'):
    """
    Formulate and Execute an Update request on EntryDNS API for a given access token / IP

    Args:
        token: (string) Access Token for an EntryDNS Domain
        current_ip: (string) IP to point EasyDNS Domain to
        domain: the domain name to be updated
        subdomain: the subdomain to be updated

    Returns: 
        Status (Either OK, or Error + Code)
    """
    url = 'https://dynamicdns.park-your-domain.com/update?' \
          'host={1}&domain={0}&password={2}&ip={3}'.format(domain, subdomain, token, current_ip)
    response = requests.get(url)
    rootET = ET.fromstring(response.text)
    error_count = int(rootET.find("ErrCount").text)
    if error_count == 0:
        return "OK"
    else:
        errtext = rootET.find("errors").find("Err1").text
        return "ERROR: {0}".format(errtext)


def main():
    current_ip = get_ip()
    cached_ip = get_cached_ip()
    if cached_ip != current_ip:
        set_cached_ip(current_ip)
        hosts = load_hosts()
        for host in hosts:
            for sub in hosts[host]:
                result = update_host(domain=host, subdomain=sub['subdomain'], token=sub['token'], current_ip=current_ip)
                if result == "OK":
                    log.info("Updating %s: %s" % (sub['subdomain'] + '.' + host, result))
                else:
                    log.error("Updating %s: %s" % (sub['subdomain'] + '.' + host, result))
    else:
        log.info("Public IP Matches Cache ({0}), Nothing to Do...".format(current_ip))


if __name__ == "__main__":
    main()
