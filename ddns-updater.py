#!/usr/bin/python
"""
Updater for Dynamic DNS on Namecheap Domains
Performs an update for each given domain access token in
the hosts.json file.
"""
import ctypes
import json
import os
import sys
import xml.etree.ElementTree as ET
from time import strftime
from urllib.request import urlopen

import requests

FILE_ATTRIBUTE_HIDDEN = 0x02
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_FILENAME = 'cachedip.txt'
CACHE_FILE_PATH = os.path.join(SCRIPT_PATH, CACHE_FILENAME)


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
        print('Cache attribute set to Hidden')
    else:  # return code of zero indicates failure, raise Windows error
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
        print("{0} -- Error reading cache. Errno error: {1}".format(strftime("%Y-%m-%d %H:%M:%S"), error.errno),
              file=sys.stderr)
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
        print("{0} -- {1}".format(strftime("%Y-%m-%d %H:%M:%S"), e), file=sys.stderr)


def get_ip():
    """
    Retrieves public IP (from httpbin) with cached IP and returns import

    Returns:
        Public IP as a string
    """

    response = urlopen('https://httpbin.org/ip')
    if response.status != 200:
        print("{0} -- Status: {1}Reason: {2}}".format(strftime("%Y-%m-%d %H:%M:%S"),
                                                      response.status,
                                                      response.reason), file=sys.stderr)
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
        print("{0} -- {1}".format(strftime("%Y-%m-%d %H:%M:%S"), e), file=sys.stderr)
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
                print("%s -- Updating %s: %s" % (strftime("%Y-%m-%d %H:%M:%S"), sub['subdomain'] + '.' + host, result))
    else:
        print("%s -- Public IP Matches Cache (%s), Nothing to Do..." % (strftime("%Y-%m-%d %H:%M:%S"), current_ip))


if __name__ == "__main__":
    main()
