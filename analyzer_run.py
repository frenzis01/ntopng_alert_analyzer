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

    my_historical = Historical(my_ntopng,iface_id)
    t_end = datetime.datetime.now() - datetime.timedelta(minutes=0)
    t_start = t_end - datetime.timedelta(minutes=30)
    time_dict = {
        "start" : t_start.strftime("%d/%m/%Y %H:%M:%S"),
        "end" : t_end.strftime("%d/%m/%Y %H:%M:%S")
    }
    from utils import set_historical
    set_historical(my_historical,iface_id,t_start,t_end)
    # print(my_historical.get_flow_alerts(iface_id, t_start.strftime('%s'), t_end.strftime(
    #     '%s'), "*", "alert_id = 26", 20, "", ""))
    # print("\tSending request "  + t_start.strftime("%d/%m/%Y %H:%M:%S") + " --> " + t_end.strftime("%d/%m/%Y %H:%M:%S") )
    # my_historical.self_test("192.168.1.12")

    # rsp = my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime('%s'), '*', "(alert_id=11 OR alert_id=12) AND (cli_name='ad01srvr.arcaspa.intra' AND vlan_id=11) OR (cli_ip = '172.30.11.12' AND vlan_id=11) OR (cli_name='srvunicommdc.unicomm.intra' AND vlan_id=2)", 10, '', '')
    # rsp = my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime('%s'), '*', "((alert_id=11 OR alert_id=12) AND ((cli_name='ad01srvr.arcaspa.intra' AND vlan_id=11) OR (cli_ip = '172.30.11.12' AND vlan_id=11) OR (cli_name='srvunicommdc.unicomm.intra' AND vlan_id=2)))", 10, '', '')
    # for a in rsp:
    #     print(a)

    raw_alerts = my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
        '%s'), "*", "severity >= 5 AND NOT alert_id = 91", 200000, "", "tstamp")

    print("First request done")
    raw_alerts += my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
        '%s'), "*", "alert_id = 26", 2000000, "", "")
    print("Second request done")
    
except ValueError as e:
    print(e)
    os._exit(-1)


# from analyzer.alertdb import *
from analyzer.alertdb import *
# print("\tHandling alerts")
for a in raw_alerts:
    new_alert(a)
update_bkts_stats()

print(json.dumps({"time" : time_dict} | get_sup_level_alerts(),indent=2))

from utils import str_key

# print(json.dumps(str_key(longlived), indent=2))
# print(json.dumps(str_key(lowgoodput), indent=2))
print(list(longlived.keys()))
print(list(lowgoodput.keys()))

# def str_key(d:dict):
#         return {str(k): v for (k,v) in d.items()}

# from utils import str_key

# print(json.dumps(bat_server,indent=2))
# print(json.dumps(str_key({k:v for k,v in dga_suspicious_domains.items() if len(v) > 1}),indent=2))
# print(json.dumps(str_key(get_unidir_probed()),indent=2))
# print(json.dumps(str_key(get_singleton()),indent=2))
# print(json.dumps(str_key(get_singleton_alertview()),indent=2))