#!/usr/bin/env python2.7
#PaloAlto Backups

from sys import argv
# from getpass import getpass
from datetime import datetime

try:
    import xmltodict
    import boto3
    import salt.client
except ImportError as e:
    print "missing xmltodict, boto3, or salt library"
    exit(2)

import requests
import json
import hashlib
import logging

logger = logging.getLogger(__name__)
fh = logging.FileHandler('/root/pan_backups.log')
fh.setLevel(logging.INFO)
logger.addHandler(fh)


def _CONVERT(FILENAME):
    with open(FILENAME) as x:
        dict = xmltodict.parse(x.read())
    return dict

def _REQ(URL,FILENAME):
    R = requests.get(URL, verify=False, timeout=5)
    if R.status_code is requests.codes.ok:
        with open(FILENAME, 'wb') as f:
            f.write(R.content)
        return _CONVERT(FILENAME)
    elif R.status_code == 403:
        logging.error("[{}] Invalid credentials".format(URL))
        exit(2)
    else:
        logging.critical('[{}] {}'.format(URL, R.raise_for_status()))
        exit(2)

def _GET_KEYS(user):
    caller = salt.client.Caller()
    data = caller.function('pillar.item', 'pan-backups')
    A = data['pan-backups']['aws']['s3']['access']
    S = data['pan-backups']['aws']['s3']['secret']
    P = data['pan-backups']['pa'][user]
    return A, S, P

def _GET_HASH(C):
    HASH = hashlib.md5(json.dumps(C))
    return HASH.hexdigest()

def _GET_TOKEN(FW, D, U, p):
    TOKEN_URL = "{}type=keygen&user={}&password={}".format(D, U, p)
    TOKEN = _REQ(TOKEN_URL, 'token.xml')

    if TOKEN['response']['@status'] == "success":
        return str(TOKEN['response']['result']['key'])
    else:
        logging.critical('[{}] {}'.format(FW, TOKEN['response']))
        exit(2)

def _GET_BACKUP(F, D, T, N):
    PULL_CONFIG = "{}type=export&category=configuration&key={}".format(D, T)
    CONFIG = _REQ(PULL_CONFIG, '/tmp/{}_{}.xml'.format(F, N))
    return _GET_HASH(CONFIG)

def _S3_CONN(L, A, S):
    client = boto3.client('s3', L,
                        aws_access_key_id = A,
                        aws_secret_access_key = S)

    resource = boto3.resource('s3', L,
                        aws_access_key_id = A,
                        aws_secret_access_key = S)

    return client, resource

def _EXISTING_BACKUP(s3c, s3r, B, F, P):
    s3c.download_file(B, F, P + F)
    ts_obj = s3r.Object(B, F).last_modified
    ts_ext = datetime.strftime(ts_obj,'%Y%m%d%H%M%S')
    existing = _CONVERT(P + F)
    return _GET_HASH(existing), ts_ext

def main():
    now = datetime.utcnow().isoformat()
    FW = argv[1]
    USER = argv[2]
    ZONE = argv[3]
    # P = getpass(prompt='Enter your passphrase: ')
    access_key, secret_key, P = _GET_KEYS(USER)

    bucket = "netsec-pan-backups"
    existing_file = "{}_latest.xml".format(FW)
    local_path = "/tmp/"
    s3c, s3r = _S3_CONN(ZONE, access_key, secret_key)
    existing_hash, existing_ts = _EXISTING_BACKUP(s3c, s3r, bucket, existing_file, local_path)

    dev = "https://{}/api/?".format(FW)
    token = _GET_TOKEN(FW, dev, USER, P)
    new_hash = _GET_BACKUP(FW, dev, token, now)

    if existing_hash == new_hash:
        logging.info("[{}] No changes".format(FW))
        exit(0)
    else:
        logging.info("[{}] Existing: {}".format(FW, existing_hash))
        logging.info("[{}] New: {}".format(FW, new_hash))
        old_path = '{}/{}'.format(bucket, existing_file)
        new_key = '{}_{}.xml'.format(FW, existing_ts)
        s3r.Object(bucket, new_key).copy_from(CopySource=old_path)
        s3r.Object(bucket, existing_file).delete()
        s3c.upload_file('{}{}_{}.xml'.format(local_path, FW, now), bucket, existing_file)

if __name__ == "__main__":
    if len(argv) != 4:
        logging.warning("Usage: {} $firewall $username $aws-zone".format(argv[0]))
        exit(2)
    else:
        main()
