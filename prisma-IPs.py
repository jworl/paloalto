#!/usr/bin/env python3

'''
written by: Joshua Worley

HEADERS should contain API token in expected format

expected format of HEADERS file:
{
    "header-api-key": "yOUr0k3nH3rE"
}

best wise. chmod 400 your token file.
'''

import argparse, requests, json, pprint
pp = pprint.PrettyPrinter(indent=1)

def TOKEN(t):
    '''
    t is path to token
    '''
    with open(t) as f:
        T = json.load(f)
    return T

def PULL(URL, DATA, HEADERS):
    x = requests.post(URL, data=DATA, headers=HEADERS)
    if x.status_code == 200:
        return True, x.json()['result']
    else:
        return False, x

def main(A):
    '''
    documentation:
    https://docs.paloaltonetworks.com/prisma/prisma-access/prisma-access-panorama-admin/prisma-access-overview/retrieve-ip-addresses-for-prisma-access
    '''
    HEADERS = TOKEN(A.TOKEN)

    DATA = {
        "addrType":"all",
        "location":"deployed",
        "serviceType":"gp_gateway"
    }

    JSON = json.dumps(DATA)
    R,D = PULL(A.URL, JSON, HEADERS)
    if R is False:
        print("[&] Error occurred")
        pp.pprint(D.__dict__)
        exit(2)
    else:
        print(json.dumps(D))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='script for gathering addresses from Prisma Access')
    parser.add_argument('-u', action='store', required=True, dest='URL', help='Prisma Access API URL', nargs="?", const='https://api.prod.datapath.prismaaccess.com/getPrismaAccessIP/v2')
    parser.add_argument('-t', action='store', required=True, dest='TOKEN', help='path to Prisma Access token')

    args = parser.parse_args()
    main(args)
