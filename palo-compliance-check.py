#!/usr/bin/env python3

# Joshua Worley
# Automated method for non-compliance checking

"""
helpful links
https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/pan-os-xml-api-request-types/retrieve-logs-api/api-log-retrieval-parameters.html
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

pp = pprint.PrettyPrinter(indent=2)

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
        # "dir": "forward", # oldest first, newest last
        "dir": "backward" # newest first, oldest last
    }

    d = _GET(dev, PAYLOAD)
    return str(d["response"]["result"]["job"])

def _PULLDATA(dev, T, J, D):
    PAYLOAD = {
        "key": T,
        "type": "log",
        "action": "get",
        "job-id": J
    }

    d = _GET(dev, PAYLOAD)
    while ( d["response"]["result"]["job"]["status"] ) != "FIN" and ( d["response"]["result"]["log"]["logs"]["@progress"] != "100" ):
        sleep(1)
        if D is True:
            print("[d] Job Status: {}".format(d["response"]["result"]["job"]["status"]))
            print("[d] Count: {}".format(d["response"]["result"]["log"]["logs"]["@count"]))
            print("[d] Progress: {}".format(d["response"]["result"]["log"]["logs"]["@progress"]))
        d = _GET(dev, PAYLOAD)

    if int(d["response"]["result"]["log"]["logs"]["@count"]) > 0:
        return d["response"]["result"]["log"]["logs"]["entry"]
    else:
        return None

def main(P):
    TOKEN = _TOKEN(P)
    NONCOMPLIANT_QUERY = "( receive_time in {} ) and ( matchname eq non-compliant )".format(P.TIMERANGE)
    NONCOMPLIANT_JOBID = _CREATEJOB(P.DEVICE, TOKEN, NONCOMPLIANT_QUERY)
    print("[i] Generated Non-compliant JobID: {}".format(NONCOMPLIANT_JOBID))
    NONCOMPLIANT_DATA = _PULLDATA(P.DEVICE, TOKEN, NONCOMPLIANT_JOBID, P.DEBUG)
    if NONCOMPLIANT_DATA is None:
        print("[i] No results from non-compliant search")
        exit(0)
    print("[+] Total non-compliant returns: {}".format(len(NONCOMPLIANT_DATA)))
    UNIQUE = []
    for d in NONCOMPLIANT_DATA:
        t = (d['srcuser'], d['machinename'], d['matchname'])
        if t not in UNIQUE:
            UNIQUE.append(t)
    # pp.pprint(UNIQUE)
    SANITY = {}
    TRUE_POSITIVE = []
    QUESTIONABLE = []
    for t in UNIQUE:
        SANITY[t[0]] = {}
        SANITY[t[0]]["query"] = "( receive_time in {} ) and ( matchname eq compliant ) and ( user.src eq '{}' ) and ( machinename eq {} )".format(P.TIMERANGE, t[0], t[1])
        SANITY[t[0]]["jobid"] = _CREATEJOB(P.DEVICE, TOKEN, SANITY[t[0]]["query"])
        print("[i] Check {} {} JobID: {}".format(t[0], t[1], SANITY[t[0]]["jobid"]))
        SANITY[t[0]]["data"] = _PULLDATA(P.DEVICE, TOKEN, SANITY[t[0]]["jobid"], P.DEBUG)
        if SANITY[t[0]]["data"] is None:
            TRUE_POSITIVE.append(t)
        else:
            QUESTIONABLE.append(t)
    print("\n[!] High confidence:")
    pp.pprint(TRUE_POSITIVE)
    print('\n')

    if len(QUESTIONABLE) > 0:
        STAGE3 = {}
        for t in QUESTIONABLE:
            STAGE3[t[0]] = {}
            STAGE3[t[0]]["query"] = "( receive_time in {} ) and (( matchname eq compliant ) or ( matchname eq non-compliant )) and ( user.src eq '{}' ) and ( machinename eq {} )".format(P.TIMERANGE, t[0], t[1])
            STAGE3[t[0]]["jobid"] = _CREATEJOB(P.DEVICE, TOKEN, STAGE3[t[0]]["query"])
            STAGE3[t[0]]["data"] = _PULLDATA(P.DEVICE, TOKEN, STAGE3[t[0]]["jobid"], P.DEBUG)
            if STAGE3[t[0]]["data"] is None:
                print("[&] Something went wrong")
                print(t)
            else:
                VERBOSE_CHECK = []
                for d in STAGE3[t[0]]["data"]:
                    T = (d['time_generated'], d['srcuser'], d['machinename'], d['matchname'])
                    if T not in VERBOSE_CHECK:
                        VERBOSE_CHECK.append(T)
                STAGE3[t[0]]["tuples"] = VERBOSE_CHECK

        MEDIUM_POSITIVE = []
        LOW_POSITIVE = []
        LIKELY_REMEDIATED = []
        for user, data in STAGE3.items():
            print("[i] analyzing {}".format(user))
            PASS = 0
            FAIL = 0
            for i in range(0, len(data['tuples'])//2):
                if data['tuples'][i][3] == "compliant":
                    PASS += 1
                else:
                    FAIL += 1
            if FAIL > 0 and PASS == 0:
                MEDIUM_POSITIVE.append((data["tuples"][0][1],data["tuples"][0][2],data["tuples"][0][3]))
            elif FAIL > 0 and PASS > 0:
                if data['tuples'][0][3] == "non-compliant":
                    MEDIUM_POSITIVE.append((data["tuples"][0][1],data["tuples"][0][2],data["tuples"][0][3]))
                else:
                    LOW_POSITIVE.append((data["tuples"][0][1],data["tuples"][0][2],data["tuples"][0][3]))
            elif FAIL == 0 and PASS > 0:
                LIKELY_REMEDIATED.append((data["tuples"][0][1],data["tuples"][0][2],data["tuples"][0][3]))
            else:
                print("[&] This should not have happened.")
                print("[&] user: {}".format(user))
                pp.pprint(data['tuples'])
                print("\n")
            if P.DEBUG is True:
                pp.pprint(data["tuples"])
                print('\n')

        if len(MEDIUM_POSITIVE) > 0:
            print("\n[!] Medium confidence:")
            pp.pprint(MEDIUM_POSITIVE)
        if len(LOW_POSITIVE) > 0:
            print("\n[!] Low confidence:")
            pp.pprint(LOW_POSITIVE)
        if len(LIKELY_REMEDIATED) > 0:
            print("\n[i] Likely remediated:")
            pp.pprint(LIKELY_REMEDIATED)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Palo Alto log exporter')
    parser.add_argument('-u', action='store', required=True, dest='USER', help='PanOS username')
    parser.add_argument('-d', action='store', required=True, dest='DEVICE', help='Palo Alto device IP')
    parser.add_argument('-p', action='store', required=False, dest='PASS', help='Password (not recommended)')
    parser.add_argument('-t', choices=['last-60-seconds','last-15-minutes','last-hour','last-6-hours','last-12-hrs','last-24-hrs','last-calendar-day','last-7-days','last-30-days','last-calendar-month'], required=True, dest='TIMERANGE')
    parser.add_argument('--verbose', dest='DEBUG', action='store_true')
    # parser.set_default(D=False)
    args = parser.parse_args()
    if args.PASS is None:
        args.PASS = getpass('{} passphrase: '.format(args.USER))
    main(args)
