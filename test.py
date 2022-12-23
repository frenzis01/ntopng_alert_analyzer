#!/usr/bin/env python3

# ntopng related imports
import os
import sys
import getopt
import time


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

try:

    my_historical = Historical(my_ntopng)
    last15minutes = (datetime.datetime.now() -
                     datetime.timedelta(minutes=5)).strftime('%s')
    raw_alerts = my_historical.get_flow_alerts(iface_id, last15minutes, datetime.datetime.now().strftime(
        '%s'), "*", "severity = 5", 20, "", "")
    # TODO change maxhits
except ValueError as e:
    print(e)
    os._exit(-1)

dtypes = {
    "srv_port":             "int",
    "tstamp_end":           "datetime64[ns]",
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

df[["is_srv_victim","srv_blacklisted","cli_blacklisted","is_srv_attacker","is_cli_victim","is_cli_attacker"]] = df[["is_srv_victim","srv_blacklisted","cli_blacklisted","is_srv_attacker","is_cli_victim","is_cli_attacker"]].astype("bool")

# sort on tstamp
df = df.sort_values(by=["tstamp"])

def statsFromSeries(s):
    d = {}
    d["srv_port_entropy"] = s["srv_port"].max()
    d["cli_port_entropy"] = s["cli_port"].max()
    d["cli_ip_entropy"] = s["cli_ip"].max()
    d["cli_ip_blk"] = s["cli_blacklisted"].sum()
    d["srv_ip_blk"] = s["srv_blacklisted"].max()
    d["tdiff_avg"] = s["tstamp"].diff().mean()
    d["tdiff_CV"] = s["tstamp"].std()/d["tdiff_avg"]
    d["size"] = len(s)
    return pd.Series(d, index=["srv_port_entropy", "cli_port_entropy", "cli_ip_entropy", "cli_ip_blk","tdiff_avg","tdiff_CV","size"])

# print(type(df))
# print(df.index[:5])
# print(df[["alert_id","srv_ip","vlan_id"]])
# TODO make the grouping parametric
groups = df.groupby(["alert_id","srv_ip","vlan_id"])
print(groups.filter(lambda g: len(g) > 2))
# print(groups.filter(lambda g: len(g) > 2))
print(groups.apply(statsFromSeries))

print(groups.filter(lambda g: len(g) > 2).groupby(["alert_id","srv_ip","vlan_id"]).apply(statsFromSeries))


# print(type(dfg))
# print(type(groups))
# print(dfg.index[:5])
# print(groups.index[:5])
# print(dfg)
# print(groups)
# print(df.apply(statsFromSeries)) #.size().sort_values(ascending=False)



# os._exit(0)
