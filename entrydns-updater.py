#!/usr/bin/python
"""
entrydns-updater.py ~ ajclarkson.co.uk

Updater for Dynamic DNS on EntryDNS Domains
Performs an update for each given domain access token in
the hosts.json file.
"""
import ctypes
import json
import os
import sys
from time import strftime
from urllib.request import urlopen
import xml.etree.ElementTree as ET

import requests

FILE_ATTRIBUTE_HIDDEN = 0x02


def hide_file_windows(filename):
    ret = ctypes.windll.kernel32.SetFileAttributesA(filename, FILE_ATTRIBUTE_HIDDEN)
    if ret:
        print('Cache attribute set to Hidden')
    else:  # return code of zero indicates failure, raise Windows error
        raise ctypes.WinError()


SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__)) + "\\"


def get_cached_ip():
    """
    Retrieve Cached IP From File, cuts down on API requests to EasyDNS if
    IP Address hasn't changed.

    Returns: 
        cached_ip: Cached IP or 0 to force refresh of public IP
    """
    try:
        cached_file = open(SCRIPT_PATH + 'entrydns-cachedip.txt', 'r')
        cached_ip = cached_file.read()
        cached_file.close()
        return cached_ip
    except IOError as error:
        print("Error reading cache. Errno error: " + error.errno, file=sys.stderr)
        return "0"


def set_cached_ip(ip):
    """
    Stores IP Address in the Cached

    Args:
        ip: Address to be Cached
    """
    try:
        cached_file = open(SCRIPT_PATH + 'entrydns-cachedip.txt', 'w')
        cached_file.write(ip)
        cached_file.close()
        #hide_file_windows(SCRIPT_PATH + 'entrydns-cachedip.txt')
    except IOError as e:
        print(e)


def get_ip():
    """
    Retrieves public IP (from httpbin) with cached IP and returns import

    Returns:
        Public IP as a string
    """
    public_ip = json.load(urlopen('https://httpbin.org/ip'))['origin']
    return public_ip


def load_hosts():
    """
    Loads the hosts.json file containing access tokens for EasyDNS

    Returns: 
        A dictionary of hosts and access tokens, e.g 

        {'example-host':'678dxjvid928skf',
         'example-host2':'8299fd0as88fd8d'}
    """
    try:
        hosts_file = open(SCRIPT_PATH + 'hosts.json', 'r')
        hosts_data = json.load(hosts_file)
        return hosts_data
    except IOError as e:
        print(e, file=sys.stderr)


def update_host(domain, token, current_ip):
    """
    Formulate and Execute an Update request on EntryDNS API for a given access token / IP

    Args:
        token: (string) Access Token for an EntryDNS Domain
        current_ip: (string) IP to point EasyDNS Domain to

    Returns: 
        Status (Either OK, or Error + Code)
    """
    url = 'https://dynamicdns.park-your-domain.com/update?host=@&domain={0}&password={1}&ip={2}'.format(domain, token, current_ip)
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
            result = update_host(host, hosts[host], current_ip)
            print("%s -- Updating %s: %s" % (strftime("%Y-%m-%d %H:%M:%S"), host, result))
    else:
        print("%s -- Public IP Matches Cache (%s), Nothing to Do..." % (strftime("%Y-%m-%d %H:%M:%S"), current_ip))


if __name__ == "__main__":
    main()
