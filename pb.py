#!/usr/bin/env python2.7
#Panorama Backups

from sys import argv
from getpass import getpass

try:
    import xmltodict
except ImportError as e:
    print e

import requests
import json
import hashlib

def _REQ(URL,FILENAME):
    R = requests.get(URL, verify=False, timeout=5)
    if R.status_code is requests.codes.ok:
        with open(FILENAME, 'wb') as f:
            f.write(R.content)
        with open(FILENAME) as x:
            dict = xmltodict.parse(x.read())
        return dict
    elif R.status_code == 403:
        print "Invalid credentials"
        exit(2)
    else:
        print "Wonk wonk wonnnnnkkkkk"
        print R.raise_for_status()
        exit(2)

def _GET_TOKEN(D, U, p):
    TOKEN_URL = "{}type=keygen&user={}&password={}".format(D, U, p)
    TOKEN = _REQ(TOKEN_URL, 'token.xml')

    if TOKEN['response']['@status'] == "success":
        return str(TOKEN['response']['result']['key'])
    else:
        print "something went wrong"
        print TOKEN['response']
        exit(2)

def _GET_BACKUP(F, D, T):
    PULL_CONFIG = "{}type=export&category=configuration&key={}".format(D, T)
    CONFIG = _REQ(PULL_CONFIG, '{}_backup.xml'.format(F))
    HASH = hashlib.md5(json.dumps(CONFIG))
    return HASH.hexdigest()

def main():
    FW = argv[1]
    USER = argv[2]
    P = getpass(prompt='Enter your passphrase: ')
    dev = "https://{}/api/?".format(FW)
    token = _GET_TOKEN(dev, USER, P)
    conf_fp = _GET_BACKUP(FW, dev, token)
    print conf_fp

if __name__ == "__main__":
    if len(argv) != 3:
        print "Usage: {} $firewall $username".format(argv[0])
        exit(2)
    else:
        main()
