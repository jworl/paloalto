#!/usr/bin/env python2.7
#Panorama Backups

from sys import argv
from getpass import getpass
# import xml.etree.ElementTree as ET
try:
    import xmltodict
except ImportError as e:
    print e
import requests

if len(argv) != 3:
    print "Usage: {} $firewall $username".format(argv[0])
    exit(2)

FW = argv[1]
USER = argv[2]
P = getpass(prompt='Enter your passphrase: ')
dev = "https://{}/api/?".format(FW)
url = "{}?type=keygen&user={}&password={}".format(dev, USER, P)

try:
    resp = requests.get(url, verify=False)
    with open('token.xml', 'wb') as f:
        f.write(resp.content)
except IOError as e:
    print e.error_code

with open('token.xml') as x:
    tree = xmltodict.parse(x.read())

if tree['response']['@status'] == "success":
    token = str(tree['response']['result']['key'])
else:
    print "something went wrong"
    print tree['response']

url = "{}?type=export&category=configuration&key={}".format(dev, token)
resp = requests.get(url, verify=False)
print resp.content
