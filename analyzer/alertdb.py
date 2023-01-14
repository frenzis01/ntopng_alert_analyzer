import json

import math
from scipy.stats import entropy
from collections import Counter
import struct
import socket
import numpy as np
import datetime as dt

bkt_srv = {}
bkt_cli = {}
bkt_srvcli = {}

GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)

def new_alert(a):
    # fix dtypes and remove unnecessary fields to improve performance
    remove_unwanted_fields(a)
    a_convert_dtypes(a)

    # add to buckets (i.e. groups)
    global bkt_srv,bkt_cli,bkt_srvcli # use global reference
    bkt_srv = add_to_bucket(a,bkt_srv,(a["srv_ip"], a["vlan_id"], a["alert_id"]))
    bkt_cli = add_to_bucket(a,bkt_cli,(a["cli_ip"], a["vlan_id"], a["alert_id"]))
    bkt_srvcli = add_to_bucket(a,bkt_srvcli,(a["srv_ip"],a["cli_ip"], a["vlan_id"], a["alert_id"]))


def add_to_bucket(alert, bkt, key):
    try:
        x = bkt[key] # throws KeyError if not existing
        bkt[key].append(alert)
        bkt[key].sort(key=lambda x : x["tstamp"])
    except KeyError:
        bkt[key] = [alert]
    return bkt


def get_bkt(BKT: int) -> dict:
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (BKT == GRP_SRV):
        return bkt_srv
    if (BKT == GRP_CLI):
        return bkt_cli
    if (BKT == GRP_SRVCLI):
        return bkt_srvcli


# UTILITIES
def a_convert_dtypes(a):

    # format 2023-01-13 17:37:31
    a["tstamp"] = dt.datetime.strptime(a["tstamp"], "%Y-%m-%d %H:%M:%S")
    a["tstamp_end"] = dt.datetime.strptime(a["tstamp_end"], "%Y-%m-%d %H:%M:%S")

    a["srv_port"] = int(a["srv_port"])
    a["severity"] = int(a["severity"])
    a["cli2srv_bytes"] = int(a["cli2srv_bytes"])
    a["vlan_id"] = int(a["vlan_id"])
    a["rowid"] = int(a["rowid"])
    a["ip_version"] = int(a["ip_version"])
    a["srv2cli_pkts"] = int(a["srv2cli_pkts"])
    a["interface_id"] = int(a["interface_id"])
    a["cli2srv_pkts"] = int(a["cli2srv_pkts"])
    a["score"] = int(a["score"])
    a["srv2cli_bytes"] = int(a["srv2cli_bytes"])
    a["cli_port"] = int(a["cli_port"])
    a["alert_id"] = int(a["alert_id"])
    a["l7_proto"] = int(a["l7_proto"])

    a["srv_blacklisted"] = int(a["srv_blacklisted"])
    a["cli_blacklisted"] = int(a["cli_blacklisted"])

def remove_unwanted_fields(a):
    a.pop("info", None)
    a.pop("l7_cat", None)
    a.pop("input_snmp", None)
    a.pop("l7_master_proto", None)
    a.pop("srv_network", None)
    a.pop("flow_risk_bitmap", None)
    a.pop("user_label", None)
    a.pop("proto", None)
    a.pop("alerts_map", None)
    a.pop("srv_location", None)
    a.pop("cli_location", None)
    a.pop("output_snmp", None)
    a.pop("cli_network", None)
    a.pop("cli_country", None)
    a.pop("srv_country", None)
    a.pop("first_seen", None)
    a.pop("alert_status", None)

    a.pop("community_id", None)
    a.pop("user_label_tstamp", None)
    a.pop("cli_host_pool_id", None)
    a.pop("srv_host_pool_id", None)
    a.pop("is_srv_victim", None)
    a.pop("is_srv_attacker", None)
    a.pop("is_cli_victim", None)
    a.pop("is_cli_attacker", None)


# Stats calculation

GRP_SRV, GRP_CLI, GRP_SRVCLI = range(3)
MIN_BKT_RELEVANT_SIZE = 3

def bkt_stats(s: list, GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    if len(s) < MIN_BKT_RELEVANT_SIZE:
        return None

    # Functions
    def get_alert_name(x):
        o = json.loads(x)
        try:
            return o["alert_generation"]["script_key"]
        except KeyError:
            return "no_name"

    # print(s)
    s_size = len(s)
    d = {}
    d["alert_name"] = get_alert_name(s[0]["json"])


    # ENTROPY (S)
    # Convert IP to int first, then compute entropy
    def ip_to_numeric(x):
        return struct.unpack("!I", socket.inet_aton(x))[0]
    srv_ip_toN = list(map(ip_to_numeric,map(lambda x: x["srv_ip"],s)))
    cli_ip_toN = list(map(ip_to_numeric,map(lambda x: x["cli_ip"],s)))
    
    # Note that entropy is normalized and ranges from 0 to 1
    def shannon_entropy(data):
        # Calculate the frequency of each element in the list
        frequency_dict = Counter(data)
        S_entropy = 0
        probabilities = []
        # Calculate the entropy
        for key in frequency_dict:
            # Calculate the relative frequency of each element
            # and the related probability
            probabilities.append(frequency_dict[key] / len(data))

        # Use l as the log base, to normalize the result and
        # get a value between 0 and 1
        l = len(frequency_dict)
        S_entropy = 0 if l == 1 else entropy(probabilities, base=l)
        return S_entropy
    d["srv_ip_S"] = shannon_entropy(srv_ip_toN)
    d["cli_ip_S"] = shannon_entropy(cli_ip_toN)
    d["srv_port_S"] = shannon_entropy(list(map(lambda x: x["srv_port"],s)))
    d["cli_port_S"] = shannon_entropy(list(map(lambda x: x["cli_port"],s)))


    # Get blacklisted IPs and count how many they are
    d["srv_ip_blk"] = 0
    d["cli_ip_blk"] = 0
    if (GRP_CRIT == GRP_SRV):
        cli_ip_set = set(map(lambda x: (x["cli_ip"],x["cli_blacklisted"]), s))
        cli_ip_blk = set(filter(lambda x: x[1] == 1, cli_ip_set))
        d["cli_ip_blk"] = (len(cli_ip_blk)/len(cli_ip_set) if len(cli_ip_set) else 0)
        d["srv_ip_blk"] = s[0]["srv_blacklisted"]
    elif (GRP_CRIT == GRP_CLI):
        srv_ip_set = set(map(lambda x: (x["srv_ip"],x["srv_blacklisted"]), s))
        srv_ip_blk = set(filter(lambda x: x[1] == 1, srv_ip_set))
        d["srv_ip_blk"] = (len(srv_ip_blk)/len(srv_ip_set) if len(srv_ip_set) else 0)
        d["cli_ip_blk"] = s[0]["cli_blacklisted"]

    # PERIODICITY - AKA Time interval Coefficient of Variation (CV)
    # assert that 's' is sorted on tstamp
    # TODO histogram rita-like
    # TODO optimize update on new alert
    def avg_delta(l):
        delta_sum = dt.timedelta(seconds=0)
        for i in range(1,len(l)):
            delta_sum += l[i] - l[i-1]
        return delta_sum / (len(l) - 1)
    tstamp_list = list(map(lambda x: x["tstamp"],s))
    tdiff_avg_unrounded = avg_delta(tstamp_list)
    d["tdiff_avg"] = dt.timedelta(seconds=round(tdiff_avg_unrounded.total_seconds()))
    # If the avg period is close to 0...
    if d["tdiff_avg"].total_seconds() == 0:  # cannot divide by 0
        # 1.0 #... consider '1' as reference to compute CV
        tdiff_avg_unrounded = dt.timedelta(seconds=1)
    # Compute CV as stddev/avg
    d["tdiff_CV"] = np.std(list(map(lambda x: (x - dt.datetime(1970, 1, 1)).total_seconds(),tstamp_list))) / tdiff_avg_unrounded.total_seconds()
    
    # NTOPNG score average
    d["score_avg"] = np.mean(list(map(lambda x: x["score"],s)))
    
    # MISSING USER-AGENT percentage (0<p<1 format)
    # TODO optimize update on new alert
    def is_UA_missing(x):
        y = json.loads(x)
        try:
            o = y["alert_generation"]["flow_risk_info"]
            o = json.loads(o)
            o = o["11"]  # useless assignment, needed to trigger KeyError if "11" missing
            return 1
        except KeyError:
            return 0
    d["noUA_perc"] = sum(map(is_UA_missing,map(lambda x: x["json"],s))) / s_size
    
    # BAT Binary Application Transfer -> Check if same file
    # TODO optimize update on new alert
    d["bft_same_file"] = ""
    def get_BAT_path(x):
        o = json.loads(x)
        try:
            return o["last_url"]
        except KeyError:
            return ""

    if (s[0]["alert_id"] == 29):
        # get the first path
        first_path = get_BAT_path(s[0]["json"])
        if first_path != "":
            for p in map(get_BAT_path,map(lambda x: x["json"],s)):
                if p != first_path:
                    first_path = ""
                    break
            

        d["bft_same_file"] = first_path

    d["size"] = s_size
    
    # X-SCORE CALCULATION
    # TODO change (ip/port) weights depending on alert_id
    # TODO cli2srv and srv2cli bytes
    # TODO hostpool?
    # TODO other json fields i.e. file name
    d["X-Score"] = (
        math.log(s_size) +  # Higher size => higher score
        # multi-target groups, i.e. high IP entropy => Higher score
        ((d["srv_ip_S"]) * 10) +
        ((d["cli_ip_S"])*10) +
        # Inverse of common srv/cli behavior, i.e. HIGH srv_port_S || LOW cli_port_S
        #   => Higher score
        (d["srv_port_S"])*10 +
        (1 - d["cli_port_S"])*10 +
        # Extra points if communicating with blacklisted IPs
        # if alert isn't of type "blacklisted"
        d["srv_ip_blk"] * (20 if s[0]["alert_id"] != 1 else 5) +
        # if alert isn't of type "blacklisted"
        d["cli_ip_blk"] * (20 if s[0]["alert_id"] != 1 else 5) +
        # Periodicity score = e^(-CV)
        # lower tdiff_CV => High time periodicity
        pow(math.e, (-1.0)*d["tdiff_CV"]) +
        # ntopng avg score
        math.log2(d["score_avg"]) * 2 +  # 70 -> ~12.4  | 300 -> ~16.5
        # percentage of missing user agent
        d["noUA_perc"]*20 +  # relevant only when BFT or HTTPsusUA
        # Is the transferred file always the same?
        (1 if (d["bft_same_file"] != "") else 0) * 15
    )
    return d
