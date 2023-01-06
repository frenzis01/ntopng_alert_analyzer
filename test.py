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
                     datetime.timedelta(minutes=30)).strftime('%s')
    raw_alerts = my_historical.get_flow_alerts(iface_id, last15minutes, datetime.datetime.now().strftime(
        '%s'), "*", "severity = 5", 50000, "", "")
    # f = open("response.json", "w")
    # f.write(str(raw_alerts))
    # f.close()
    # TODO remove response writing
    # TODO change maxhits
except ValueError as e:
    print(e)
    os._exit(-1)

print("\tParsing response")
df = pd.DataFrame(raw_alerts)
print("\tParsed response")

# convert dtypes
df[["tstamp", "tstamp_end", "user_label_tstamp"]] = df[[
    "tstamp", "tstamp_end", "user_label_tstamp"]].apply(pd.to_datetime)
df[["probe_ip", "cli_ip", "srv_name", "srv_ip", "cli_name"]] = df[[
    "probe_ip", "cli_ip", "srv_name", "srv_ip", "cli_name"]].astype("string")

df[["srv_port", "severity", "cli2srv_bytes", "vlan_id", "cli_host_pool_id", "srv_host_pool_id", "rowid", "community_id",
    "ip_version", "srv2cli_pkts", "interface_id", "cli2srv_pkts", "score", "srv2cli_bytes", "cli_port", "alert_id", "l7_proto"]] = df[[
        "srv_port", "severity", "cli2srv_bytes", "vlan_id", "cli_host_pool_id", "srv_host_pool_id", "rowid", "community_id", "ip_version", "srv2cli_pkts", "interface_id", "cli2srv_pkts", "score", "srv2cli_bytes", "cli_port", "alert_id", "l7_proto"]].apply(pd.to_numeric)

# TODO astype(bool) evaluates 0 to True
df[["is_srv_victim", "srv_blacklisted", "cli_blacklisted", "is_srv_attacker", "is_cli_victim", "is_cli_attacker"]] = df[[
    "is_srv_victim", "srv_blacklisted", "cli_blacklisted", "is_srv_attacker", "is_cli_victim", "is_cli_attacker"]].astype("int")

# sort on tstamp
df = df.sort_values(by=["tstamp"])
print("\tSorted alerts")


def isUAmissing(x):
    y = json.loads(x)
    try:
        o = y["alert_generation"]["flow_risk_info"]
        o = json.loads(o)
        o = o["11"]  # useless assignment, needed to trigger KeyError if "11" missing
        return 1
    except KeyError:
        return 0
    # TODO remove
    if x.find("Empty or missing User-Agent") != -1:
        return 1
    return 0


def getAlertName(x):
    o = json.loads(x)
    try:
        return o["alert_generation"]["script_key"]
    except KeyError:
        return "no_name"

def getBFTfilename(x):
    o = json.loads(x)
    try :
        return o["last_url"]
    except KeyError:
        return math.nan

def shannon_entropy(data):
    # Calculate the frequency of each element in the list
    frequency_dict = Counter(data)
    S_entropy = 0
    probabilities = [] # 
    # Calculate the entropy
    for key in frequency_dict:
        # Calculate the relative frequency of each element
        # and the related probability
        probabilities.append(frequency_dict[key] / len(data))

    # Use l as the log base, to normalize the result and
    # get a value between 0 and 1
    l = len(frequency_dict)
    S_entropy = 0 if l == 1 else entropy(probabilities,base=l)
    return S_entropy

def ip2int(x):
    return struct.unpack("!I", socket.inet_aton(x))[0]


GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)
def statsFromSeries(s: pd.Series,GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    s_size = len(s)
    d = {}
    d["alert_name"] = s["json"].head(1).apply(getAlertName).iat[0]
    # Convert IP to int first, then compute entropy
    srv_ip_toN = s["srv_ip"].map(lambda x: struct.unpack("!I", socket.inet_aton(x))[0])
    cli_ip_toN = s["cli_ip"].map(lambda x: struct.unpack("!I", socket.inet_aton(x))[0])
    # Entropy (S)
    # Note that entropy is normalized and ranges from 0 to 1
    d["srv_ip_S"] = shannon_entropy(srv_ip_toN) 
    d["cli_ip_S"] = shannon_entropy(cli_ip_toN) 
    d["srv_port_S"] = shannon_entropy(s["srv_port"])
    d["cli_port_S"] = shannon_entropy(s["cli_port"])
    # Get blacklisted IPs and count how many they are
    d["srv_ip_blk"] = 0
    d["cli_ip_blk"] = 0
    # TODO validate this
    if (GRP_CRIT == GRP_SRV):
        cli_ip_blk_df = s[["cli_ip", "cli_blacklisted"]].loc[s["cli_blacklisted"] == 1, "cli_ip"]
        d["cli_ip_blk"] = (cli_ip_blk_df.nunique()/len(s) if len(s) else 0)
        d["srv_ip_blk"] = s["srv_blacklisted"].iat[0]
    elif (GRP_CRIT == GRP_CLI):
        srv_ip_blk_df = s[["srv_ip", "srv_blacklisted"]].loc[s["srv_blacklisted"] == 1, "srv_ip"]
        d["srv_ip_blk"] = (srv_ip_blk_df.nunique()/len(s) if len(s) else 0)
        d["cli_ip_blk"] = s["cli_blacklisted"].iat[0]
    # Periodicity - AKA Time interval Coefficient of Variation (CV)
    # TODO histogram rita-like
    tdiff_avg_unrounded = s["tstamp"].diff().mean()
    d["tdiff_avg"] = tdiff_avg_unrounded.round("s")
    # If the avg period is close to 0... 
    if d["tdiff_avg"].total_seconds() == 0: # cannot divide by 0
        tdiff_avg_unrounded = pd.Timedelta(1,"s") #1.0 #... consider '1' as reference to compute CV
    # Compute CV as stddev/avg
    d["tdiff_CV"] = s["tstamp"].std()/tdiff_avg_unrounded
    # NTOPNG score average
    d["score_avg"] = s["score"].mean()
    # Missing User-Agent percentage (0<p<1 format)
    d["noUA_perc"] = s["json"].apply(isUAmissing).sum() / s_size
    d["size"] = s_size
    # BinaryFileTransfer -> Check if same file
    #  Note: nunique() doesn't count NaN values
    d["bft_same_file"] = ""
    if (s["alert_id"].iat[0] == 29):
        filenames = s["json"].apply(getBFTfilename)
        # print(filenames)
        # print(filenames.nunique())
        d["bft_same_file"] = filenames.iat[0] if (filenames.nunique() == 1) else ""
        # if d["bft_same_file"] != "":
        #     print(d["bft_same_file"])
        #     print(s["json"].iat[0])

    # X-SCORE CALCULATION
    # TODO change (ip/port) weights depending on alert_id
    # TODO cli2srv and srv2cli bytes
    # TODO hostpool?
    # TODO other json fields i.e. file name 
    d["X-Score"] = (
        math.log(s_size) +  # Higher size => higher score
        # multi-target groups, i.e. high IP entropy => Higher score
        ((d["srv_ip_S"])* 10) +
        ((d["cli_ip_S"])*10) +
        # Inverse of common srv/cli behavior, i.e. HIGH srv_port_S || LOW cli_port_S
        #   => Higher score 
        (d["srv_port_S"])*10 +
        (1 - d["cli_port_S"])*10 +
        # Extra points if communicating with blacklisted IPs
        d["srv_ip_blk"]* (20 if s["alert_id"].iat[0] != 1 else 5) + # if alert isn't of type "blacklisted"
        d["cli_ip_blk"]* (20 if s["alert_id"].iat[0] != 1 else 5) + # if alert isn't of type "blacklisted"
        # Periodicity score = e^(-CV)
         # lower tdiff_CV => High time periodicity 
        pow(math.e, (-1.0)*d["tdiff_CV"]) +
        # ntopng avg score
        math.log2(d["score_avg"]) * 2 + # 70 -> ~12.4  | 300 -> ~16.5
        # percentage of missing user agent
        d["noUA_perc"]*20 +# relevant only when BFT or HTTPsusUA
        # Is the transferred file always the same?
        (1 if (d["bft_same_file"] != "") else 0) * 15
        )
    return pd.Series(d, index=["alert_name", "X-Score", "srv_ip_S", "cli_ip_S", "srv_port_S", "cli_port_S", "cli_ip_blk", "srv_ip_blk", "tdiff_avg", "tdiff_CV", "score_avg", "noUA_perc", "size","bft_same_file"])


#TODO validate
def summarize(d,GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    # print("lambda obj: " + str(d))
    i = ""
    # "Are the alerts periodic?"
    TDIFF_CV_TH = 2 # Threshold
    if d["tdiff_CV"] <= TDIFF_CV_TH:
        i += "Periodic "+ str(round(d["tdiff_CV"],2)) + " -> "+ str(d["tdiff_avg"]) + "\n"
    # In the client-server paradigm, the common behavior is that
    # srv uses always the same known port, while clients use ephimeral ones
    # We can set an entropy threshold to determine when srv and clients are
    # behaving oddly

    # not client-server paradigm associated alerts
    excludes = ["blacklisted"]
    PORT_S_TH = 0.25
    if GRP_CRIT != GRP_CLI and d["alert_name"] not in excludes and d["srv_port_S"] >= PORT_S_TH:
        i += "Odd Server behavior -> Using too many ports\n"
    if GRP_CRIT != GRP_SRV and d["alert_name"] not in excludes and d["cli_port_S"] <= PORT_S_TH:
        i += "Odd Client behavior -> Using very few ports\n"
    
    # Percentage of blacklisted hosts
    BLK_PERC_TH = 0.25
    if d["alert_name"] != "blacklisted":
        if d["srv_ip_blk"] >= BLK_PERC_TH:
            i += "Blacklisted servers found\n"
        if d["cli_ip_blk"] >= BLK_PERC_TH:
            i += "Blacklisted clients found\n"
    

    # Percentage of missing User-Agent in BFT alerts
    NO_UA_PERC_TH = 0.75
    if d["alert_name"] == "binary_file_transfer":
        if d["noUA_perc"] > NO_UA_PERC_TH:
            i += "BFT -> Many User-Agent are missing\n"
        if d["bft_same_file"] != "":
            i += "BFT -> Transferring always: \""+d["bft_same_file"]+"\"\n"

    # Prepend group size if critical
    if i != "":
        i = "SIZE: " + str(d["size"]) + " |     " + i
    return i[:-1]

pd.set_option("display.precision", 3)
pd.set_option("display.max_rows",None)
pd.set_option('display.max_colwidth', None)


# TODO make the grouping parametric

# the return obj of .filter() is DataFrame, not DataFrameGroupBy, so we need to group again
# btw, this is odd, there should be a less "dumb" way of keeping the data grouped
MIN_RELEVANT_GRP_SIZE = 5
by_srvcli_ip = df.groupby(["alert_id", "srv_ip","cli_ip", "vlan_id"]).filter(
    lambda g: len(g) > MIN_RELEVANT_GRP_SIZE).groupby(["alert_id", "srv_ip","cli_ip", "vlan_id"])
by_srvcli_ip = by_srvcli_ip.apply(lambda x: statsFromSeries(x,GRP_CLI))

# Remove srvcli alerts from df, in this way:
# SRV:CLI   The grouping on this set will result in
# A:B       SRVCLI  =   [A:B A:B A:B]
# A:B       SRV     =   [A:C A:D] instead of [A:B A:B A:B A:C A:D]
# A:B
# A:C
# A:D
df = df.merge(by_srvcli_ip, on=["alert_id", "srv_ip",
         "cli_ip", "vlan_id"], how='outer', indicator=True)\
    .query('_merge=="left_only"')\
    .drop('_merge', axis=1)



print("\nSERVER-CLIENT IP GROUPING\n-------------------------------------\n")
print("----TOP X-SCORE")
print(by_srvcli_ip.sort_values("X-Score",ascending=False).head(10))



by_srv_ip = df.groupby(["alert_id", "srv_ip", "vlan_id"]).filter(
    lambda g: len(g) > MIN_RELEVANT_GRP_SIZE).groupby(["alert_id", "srv_ip", "vlan_id"])
by_srv_ip = by_srv_ip.apply(lambda x: statsFromSeries(x,GRP_SRV))
print("\nSERVER IP GROUPING\n-------------------------------------\n")
print("----TOP X-SCORE")
# print(by_srv_ip.sort_values("srv_port_S",ascending=False).loc[by_srv_ip["alert_name"] != "blacklisted"].head(10))
print(by_srv_ip.sort_values("cli_ip_blk",ascending=False).head(10))


tmp = by_cli_ip = df.groupby(["alert_id", "cli_ip", "vlan_id"]).filter(
    lambda g: len(g) > MIN_RELEVANT_GRP_SIZE).groupby(["alert_id", "cli_ip", "vlan_id"])
by_cli_ip = by_cli_ip.apply(lambda x: statsFromSeries(x,GRP_CLI))
print("\nCLIENT IP GROUPING\n-------------------------------------\n")
print("----TOP X-SCORE")
# print(by_cli_ip.sort_values("cli_port_S",ascending=True).query("alert_id not in [1,38]").head(10))
print(by_cli_ip.sort_values("srv_ip_blk",ascending=True).head(10))
# print(tmp.get_group((38,"172.28.5.38",2))[["srv_ip","cli_ip"]])

# TODO Get IPs that generate many alert types
by_srv_count_alert = by_srv_ip.index.to_frame(index=False).groupby(["vlan_id","srv_ip"]).apply(lambda x: len(x)).to_frame("n_alert_types")
by_cli_count_alert = by_cli_ip.index.to_frame(index=False).groupby(["vlan_id","cli_ip"]).apply(lambda x: len(x)).to_frame("n_alert_types")
by_srvcli_count_alert = by_srvcli_ip.index.to_frame(index=False).groupby(["vlan_id","srv_ip","cli_ip"]).apply(lambda x: len(x)).to_frame("n_alert_types")

by_srv_count_alert_mean = by_srv_count_alert["n_alert_types"].mean()
by_cli_count_alert_mean = by_cli_count_alert["n_alert_types"].mean()
by_srvcli_count_alert_mean = by_srvcli_count_alert["n_alert_types"].mean()

print("\n#ALERT_TYPES GENERATED\n-------------------------------------\n")
print("\nThese srv hosts are associated with more alert types than others")
print(by_srv_count_alert.loc[by_srv_count_alert["n_alert_types"] > by_srv_count_alert_mean])

print("\nThese cli hosts are associated with more alert types than others")
print(by_cli_count_alert.loc[by_cli_count_alert["n_alert_types"] > by_cli_count_alert_mean])

print("\nThese <srv,cli> tuples are associated with more alert types than others")
print(by_srvcli_count_alert.loc[by_srvcli_count_alert["n_alert_types"] > by_srvcli_count_alert_mean])


print("\nCRITICAL INFO\n-------------------------------------\n")
print("----SERVER")
tmp = by_srv_ip.apply(lambda x: summarize(x,GRP_SRV),axis=1).to_frame("critical_info")
tmp = tmp["critical_info"].loc[tmp["critical_info"] != ""]
print(tmp.str.split("\n", expand=True).stack())

print("----CLIENT")
tmp = by_cli_ip.apply(lambda x: summarize(x,GRP_CLI),axis=1).to_frame("critical_info")
tmp = tmp["critical_info"].loc[tmp["critical_info"] != ""]
print(tmp.str.split("\n", expand=True).stack())

print("----SERVER-CLIENT")
tmp = by_srvcli_ip.apply(lambda x: summarize(x,GRP_SRVCLI),axis=1).to_frame("critical_info")
tmp = tmp["critical_info"].loc[tmp["critical_info"] != ""]
print(tmp.str.split("\n", expand=True).stack())
