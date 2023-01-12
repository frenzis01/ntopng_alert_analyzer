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

# currently unused
dtypes = {
    "srv_port":             "int",
    "tstamp_end":           "datetime64[s]",
    "probe_ip":             "string",
    "severity":             "int",
    "info":                 "object",
    "cli2srv_bytes":        "int",
    "l7_cat":               "object",
    "is_srv_victim":        "bool",
    "cli_ip":               "string",
    "vlan_id":              "int",
    "cli_host_pool_id":     "int",
    "srv_host_pool_id":     "int",
    "rowid":                "int",
    "tstamp":               "datetime64[ns]",
    "community_id":         "int",
    "input_snmp":           "object",
    "l7_master_proto":      "object",
    "srv_network":          "object",
    "flow_risk_bitmap":     "object",
    "user_label":           "object",
    "proto":                "object",
    "ip_version":           "int",
    "srv2cli_pkts":         "int",
    "srv_name":             "string",
    "alerts_map":           "object",
    "srv_location":         "object",
    "json":                 "object",
    "cli_location":         "object",
    "srv_blacklisted":      "int",
    "interface_id":         "int",
    "cli_blacklisted":      "int",
    "is_srv_attacker":      "bool",
    "is_cli_victim":        "bool",
    "srv_ip":               "string",
    "is_cli_attacker":      "bool",
    "cli2srv_pkts":         "int",
    "output_snmp":          "object",
    "cli_network":          "object",
    "score":                "int",
    "cli_name":             "string",
    "srv2cli_bytes":        "int",
    "cli_port":             "int",
    "alert_id":             "int",
    "l7_proto":             "int",
    "cli_country":          "object",
    "srv_country":          "object",
    "user_label_tstamp":    "datetime64[ns]",
    "first_seen":           "object",
    "alert_status":         "object"
}
try:

    print("\tSending request")
    my_historical = Historical(my_ntopng)
    last15minutes = (datetime.datetime.now() -
                     datetime.timedelta(minutes=10)).strftime('%s')
    raw_alerts = my_historical.get_flow_alerts(iface_id, last15minutes, datetime.datetime.now().strftime(
        '%s'), "*", "severity = 5", 10, "", "")
    # f = open("response.json", "w")
    # f.write(str(raw_alerts))
    # f.close()
    # TODO remove response writing
    # TODO change maxhits
except ValueError as e:
    print(e)
    os._exit(-1)


# from analyzer.alertdb import *
from analyzer.handler import *
for a in raw_alerts:
    alert_handler(a)

print(df)
