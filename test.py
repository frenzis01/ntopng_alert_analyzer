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

# Defaults
username = myenv.myusr
password = myenv.mykey
ntopng_url = myenv.myurl
iface_id = 12  # all
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
    "srv_blacklisted":      "bool",
    "interface_id":         "int",
    "cli_blacklisted":      "bool",
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

    my_historical = Historical(my_ntopng)
    last15minutes = (datetime.datetime.now() -
                     datetime.timedelta(minutes=15)).strftime('%s')
    raw_alerts = my_historical.get_flow_alerts(iface_id, last15minutes, datetime.datetime.now().strftime(
        '%s'), "*", "severity = 5", 10000, "", "")
    # TODO change maxhits
except ValueError as e:
    print(e)
    os._exit(-1)

# print(json.dumps(raw_alerts, indent=2))
df = pd.DataFrame(raw_alerts)
# print(df.dtypes)

# convert dtypes
df[["tstamp", "tstamp_end", "user_label_tstamp"]] = df[[
    "tstamp", "tstamp_end", "user_label_tstamp"]].apply(pd.to_datetime)
df[["probe_ip", "cli_ip", "srv_name", "srv_ip", "cli_name"]] = df[[
    "probe_ip", "cli_ip", "srv_name", "srv_ip", "cli_name"]].astype("string")

df[["srv_port", "severity", "cli2srv_bytes", "vlan_id", "cli_host_pool_id", "srv_host_pool_id", "rowid", "community_id",
    "ip_version", "srv2cli_pkts", "interface_id", "cli2srv_pkts", "score", "srv2cli_bytes", "cli_port", "alert_id", "l7_proto"]] = df[[
        "srv_port", "severity", "cli2srv_bytes", "vlan_id", "cli_host_pool_id", "srv_host_pool_id", "rowid", "community_id", "ip_version", "srv2cli_pkts", "interface_id", "cli2srv_pkts", "score", "srv2cli_bytes", "cli_port", "alert_id", "l7_proto"]].apply(pd.to_numeric)

df[["is_srv_victim", "srv_blacklisted", "cli_blacklisted", "is_srv_attacker", "is_cli_victim", "is_cli_attacker"]] = df[[
    "is_srv_victim", "srv_blacklisted", "cli_blacklisted", "is_srv_attacker", "is_cli_victim", "is_cli_attacker"]].astype("bool")

# sort on tstamp
df = df.sort_values(by=["tstamp"])


flag = False


def isUAmissing(x):
    if x.find("Empty or missing User-Agent") != -1:
        return 1
    return 0


def statsFromSeries(s):
    s_size = len(s)
    d = {}
    d["srv_port_CV"] = s["srv_port"].std()/s_size
    d["cli_port_CV"] = s["cli_port"].std()/s_size
    d["cli_ip_CV"] = s["cli_ip"].map(lambda x: struct.unpack("!I", socket.inet_aton(x))[0]).std()/s_size
    d["cli_ip_blk"] = s["cli_blacklisted"].sum()
    d["srv_ip_blk"] = s["srv_blacklisted"].max()
    tdiff_avg_unrounded = s["tstamp"].diff().mean()
    d["tdiff_avg"] = tdiff_avg_unrounded.round("s")
    if d["tdiff_avg"] != 0: 
        d["tdiff_CV"] = s["tstamp"].std()/tdiff_avg_unrounded    
    else:
        -1
    d["score_avg"] = s["score"].mean()
    d["NoUA"] = s["json"].apply(isUAmissing).sum()
    d["size"] = s_size
    # d["noUA_perc"] = s["json"]
    return pd.Series(d, index=["srv_port_CV","cli_ip_CV","cli_port_CV", "cli_ip_blk", "srv_ip_blk","tdiff_avg", "tdiff_CV", "score_avg", "NoUA", "size"])


pd.set_option("display.precision", 3)  # TODO change this?

# TODO make the grouping parametric
# the return obj of .filter() is DataFrame, not DataFrameGroupBy, so we need to group again
# btw, this is odd, there should be a less "dumb" way of keeping the data grouped
#
MIN_RELEVANT_GRP_SIZE = 3
by_srv_ip = df.groupby(["alert_id", "srv_ip", "vlan_id"]).filter(
    lambda g: len(g) > MIN_RELEVANT_GRP_SIZE).groupby(["alert_id", "srv_ip", "vlan_id"])
print(by_srv_ip.apply(statsFromSeries))
# with pd.option_context('display.max_rows', None, 'display.max_columns', None):  # more options can be specified also
#     print(by_srv_ip["json"].apply(lambda x: foo(x)))


# os._exit(0)
