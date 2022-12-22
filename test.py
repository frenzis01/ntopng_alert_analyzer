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
host_ip = "192.168.1.1" # useful only for -H option

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
        '%s'), "*", "severity = 5", 10000, "", "")
    # TODO change maxhits
except ValueError as e:
    print(e)
    os._exit(-1)

# print(json.dumps(raw_alerts, indent=2))
df = pd.DataFrame(raw_alerts)
# print(df.dtypes)
# TODO make the grouping parametric

def statsFromSeries(s):
    d = {}
    d["srv_port_entropy"] = s["srv_port"].max()
    d["cli_port_entropy"] = s["cli_port"].max()
    d["cli_ip_entropy"] = s["cli_ip"].max()
    d["cli_ip_blk"] = s["cli_blacklisted"].sum()
    return pd.Series(d, index=["srv_port_entropy","cli_port_entropy","cli_ip_entropy","cli_ip_blk"])
print(df.groupby(["alert_id","srv_ip"]).apply(statsFromSeries)) #.size().sort_values(ascending=False)



# os._exit(0)
