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
import deepdiff
import dictdiffer
import utils


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
    # from analyzer.alertdb import *
    from analyzer.alertdb import *

    prev = {"t_end" : datetime.datetime.now() - datetime.timedelta(minutes=5),"t_start" : datetime.datetime.now()}
    curr = {}
    prev["sup_level_alerts"] = (get_sup_level_alerts())
    prev["secondary_groupings"] = (get_secondary_groupings())
    prev["singleton_alerts"] = (get_singleton_alertview())
    while (True):
        now = datetime.datetime.now()
        harvest_bound = datetime.datetime.now() - datetime.timedelta(minutes=30)
        curr["t_start"] = prev["t_end"].strftime("%d/%m/%Y %H:%M:%S")
        curr["t_end"] = now.strftime("%d/%m/%Y %H:%M:%S")
        my_historical = Historical(my_ntopng)
        # print("\tSending request "  + last15minutes.strftime("%d/%m/%Y %H:%M:%S") + " --> " + datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S") )
        raw_alerts = my_historical.get_flow_alerts(iface_id, prev["t_end"].strftime('%s'), now.strftime(
            '%s'), "*", "severity = 5", 10000, "", "")
        harvesting(prev["t_end"])
        for a in raw_alerts:
            new_alert(a)
        update_bkts_stats()
        prev_alerts = curr
        sup_alert = (get_sup_level_alerts())
        sin_alert = (get_singleton_alertview())
        # sec_alert = (get_secondary_groupings())
        curr["sup_level_alerts"] = (get_sup_level_alerts())
        # curr["secondary_groupings"] = (get_secondary_groupings())
        curr["singleton_alerts"] = (get_singleton_alertview())
        prev["t_end"] = prev["t_end"].strftime("%d/%m/%Y %H:%M:%S")
        diff = deepdiff.DeepDiff(prev,curr,verbose_level=0)
        # print(diff)
        keys = []
        if ("dictionary_item_added" in diff):
            keys += (diff["dictionary_item_added"])
        if ("values_changed" in diff):
            keys += (diff["values_changed"])
        
        alerts_update = {}
        keys_l = list(map(utils.parse_keys_from_path,keys))
        # print(keys_l)
        if len(keys_l):
            alerts_update['t_start'] = curr["t_start"]
            alerts_update['t_end'] = curr["t_end"]
        for k in keys_l:
            # if type(val := utils.get_value_from_keys(curr,list(k))) is not dict:
                # print("DICT!" + str(k))
                # print(json.dumps(val,indent=2))
            # else:
                # str(val)
            val = utils.get_value_from_keys(curr,list(k))
            alerts_update[str(k)] = val
        

        print(json.dumps(alerts_update,indent=2))

        prev["t_end"] = now
        prev["sup_level_alerts"] = sup_alert
        # prev["secondary_groupings"] = sec_alert
        prev["singleton_alerts"] = sin_alert
        time.sleep(60)

    

except ValueError as e:
    print(e)
    os._exit(-1)
