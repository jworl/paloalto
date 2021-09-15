#!/usr/bin/env python3

# Joshua Worley
# Automated method for non-compliance checking

"""
helpful links
https://live.paloaltonetworks.com/t5/automation-api-discussions/querying-for-detailed-hip-report-on-xml-api/td-p/389161
https://avleonov.com/2016/12/17/retrieving-palo-alto-ngfw-security-events-via-api/
Also, check CLI reference page. show log commands are relevant for queries:
https://docs.paloaltonetworks.com/pan-os/9-0/cli-reference/pan-os-9-0-cli-ops-command-hierarchy.html
"""

import requests
import argparse
import xmltodict
import pprint
import urllib.parse

from datetime import datetime
from datetime import timedelta
from getpass import getpass
from time import sleep

pp = pprint.PrettyPrinter(indent=1)

def _GET(dev, pl):
    r = requests.get("https://{}/api".format(dev),params=pl,verify=False)
    d = xmltodict.parse(r.text)
    if d["response"]["@status"] == "success":
        return d
    else:
        print("Something went wrong")
        print(d)
        exit(2)

def _TOKEN(P):
    PAYLOAD = {
        "type": "keygen",
        "user": P.USER,
        "password": P.PASS
    }

    d = _GET(P.DEVICE, PAYLOAD)
    return str(d["response"]["result"]["key"])

def _CREATEJOB(dev, T, Q):
    # t = datetime.now()
    # q = t - timedelta(1)
    # QUERY = "receive_time geq '{}'".format(q.strftime("%Y/%m/%d %H:%M:%S"))
    PAYLOAD = {
        "key": T,
        "type": "log",
        "log-type": "hipmatch",
        "query": Q,
        "nlogs": "5000",
        "dir": "forward"
    }

    d = _GET(dev, PAYLOAD)
    return str(d["response"]["result"]["job"])

def _PULLDATA(dev, T, J):
    PAYLOAD = {
        "key": T,
        "type": "log",
        "action": "get",
        "job-id": J
    }

    d = _GET(dev, PAYLOAD)
    while ( d["response"]["result"]["job"]["status"] ) != "FIN" and ( d["response"]["result"]["log"]["logs"]["@progress"] != "100" ):
        sleep(1)
        print("Job Status: {}".format(d["response"]["result"]["job"]["status"]))
        print("Count: {}".format(d["response"]["result"]["log"]["logs"]["@count"]))
        print("Progress: {}".format(d["response"]["result"]["log"]["logs"]["@progress"]))
        d = _GET(dev, PAYLOAD)

    if "entry" in d["response"]["result"]["log"]["logs"]:
        return d["response"]["result"]["log"]["logs"]["entry"]
    else:
        return d["response"]

def main(P):
    TOKEN = _TOKEN(P)
    NONCOMPLIANT_QUERY = "( receive_time in last-24-hrs ) and ( matchname eq non-compliant )"
    NONCOMPLIANT_JOBID = _CREATEJOB(P.DEVICE, TOKEN, NONCOMPLIANT_QUERY)
    print("Generated Non-compliant JobID: {}".format(NONCOMPLIANT_JOBID))
    NONCOMPLIANT_DATA = _PULLDATA(P.DEVICE, TOKEN, NONCOMPLIANT_JOBID)
    print("Total non-compliant returns: {}".format(len(NONCOMPLIANT_DATA)))
    UNIQUE = []
    for d in NONCOMPLIANT_DATA:
        t = (d['srcuser'], d['machinename'], d['matchname'])
        if t not in UNIQUE:
            UNIQUE.append(t)
    pp.pprint(UNIQUE)
    SANITY = {}
    for t in UNIQUE:
        SANITY[t[0]] = {}
        SANITY[t[0]]["query"] = "( receive_time in last-24-hrs ) and ( matchname eq compliant ) and ( user.src eq '{}' ) and ( machinename eq {} )".format(t[0], t[1])
        SANITY[t[0]]["jobid"] = _CREATEJOB(P.DEVICE, TOKEN, SANITY[t[0]]["query"])
        SANITY[t[0]]["data"] = _PULLDATA(P.DEVICE, TOKEN, SANITY[t[0]]["jobid"])
        pp.pprint(SANITY[t[0]]["data"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Palo Alto log exporter')
    parser.add_argument('-u', action='store', required=True,
                        dest='USER', help='PanOS username')
    parser.add_argument('-d', action='store', required=True,
                        dest='DEVICE', help='Palo Alto device IP')
    parser.add_argument('-p', action='store', required=False,
                        dest='PASS', help='Password (not recommended)')
    args = parser.parse_args()
    if args.PASS is None:
        args.PASS = getpass('{} passphrase: '.format(args.USER))
    main(args)
