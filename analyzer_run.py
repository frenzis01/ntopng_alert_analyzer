#!/usr/bin/env python3

# ntopng related imports
import os
import sys
import getopt
import time
import ipaddress
import struct
import socket

from ntopng.ntopng import Ntopng
from ntopng.interface import Interface
from ntopng.host import Host
from ntopng.historical import Historical
from ntopng.flow import Flow

# My imports
import datetime
import json
import pandas as pd
from types import SimpleNamespace
import myenv
from IPython.display import display
import math
from scipy.stats import entropy
from collections import Counter
from math import log2
import ast


# Defaults
username = myenv.myusr
password = myenv.mykey
ntopng_url = myenv.myurl
iface_id = 12  # 12 = all
auth_token = None
enable_debug = False
host_ip = "192.168.1.1"  # useful only for -H option

##########


def usage():
    print("test.py [-h] [-d] [-u <username>] [-p <passwrd>] [-n <ntopng_url>]")
    print("         [-i <iface id>] [-t <auth token>]")
    print("")
    print("Example: ./test.py -t ce0e284c774fac5a3e981152d325cfae -i 4")
    print("         ./test.py -u ntop -p mypassword -i 4")
    sys.exit(0)

##########


try:
    opts, args = getopt.getopt(sys.argv[1:],
                               "hdu:p:n:i:H:t:",
                               ["help",
                                "debug",
                                "username=",
                                "password=",
                                "ntopng_url=",
                                "iface_id=",
                                "host_ip=",
                                "auth_token="]
                               )
except getopt.GetoptError as err:
    print(err)
    usage()
    sys.exit(2)

for o, v in opts:
    if (o in ("-h", "--help")):
        usage()
    elif (o in ("-d", "--debug")):
        enable_debug = True
    elif (o in ("-u", "--username")):
        username = v
    elif (o in ("-p", "--password")):
        password = v
    elif (o in ("-n", "--ntopng_url")):
        ntopng_url = v
    elif (o in ("-i", "--iface_id")):
        iface_id = v
    elif (o in ("-H", "--host_ip")):
        host_ip = v
    elif (o in ("-t", "--auth_token")):
        auth_token = v

try:
    my_ntopng = Ntopng(username, password, auth_token, ntopng_url)

    if (enable_debug):
        my_ntopng.enable_debug()
except ValueError as e:
    print(e)
    os._exit(-1)

try:

    print("\tSending request")
    my_historical = Historical(my_ntopng)
    last15minutes = (datetime.datetime.now() -
                     datetime.timedelta(minutes=30)).strftime('%s')
    raw_alerts = my_historical.get_flow_alerts(iface_id, last15minutes, datetime.datetime.now().strftime(
        '%s'), "*", "severity = 5", 10000, "", "")
except ValueError as e:
    print(e)
    os._exit(-1)


# from analyzer.alertdb import *
from analyzer.handler import *
print("Handling alerts")
for a in raw_alerts:
    alert_handler(a)

bsrv = get_bkt(GRP_SRV)
k_stats = {k : stats for (k,v) in bsrv.items() if (stats := get_bkt_stats(v,GRP_SRV))}
# print(k_stats)
print(json.dumps({str(k): v for (k,v) in k_stats.items()},indent=2))
# print(json.dumps({str(k) : str(v) for (k,v) in filter(lambda x: x[1],k_stats.items())},indent=2))
print(get_higher_alert_types(bsrv))
print(json.dumps({str(k): v for (k,v) in get_cs_paradigm_odd(bsrv,GRP_SRV).items()},indent=2))
print(json.dumps({str(k): v for (k,v) in get_blk_peer(bsrv,GRP_SRV).items()},indent=2))
print(json.dumps({str(k): v for (k,v) in get_periodic(bsrv).items()},indent=2))
print(json.dumps({str(k): v for (k,v) in get_bat_samefile(bsrv).items()},indent=2))
print(json.dumps({str(k): v for (k,v) in get_bat_missingUA(bsrv).items()},indent=2))
print(json.dumps(get_similar_periodicity(bsrv),indent=2))
