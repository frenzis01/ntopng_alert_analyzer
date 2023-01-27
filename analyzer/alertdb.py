import json

import math
from scipy.stats import entropy
from collections import Counter
import struct
import socket
import numpy as np
import datetime as dt
import itertools
import re

STREAMING_MODE = False

bkt_srv = {}
bkt_cli = {}
bkt_srvcli = {}

bkt_srv_stats = {}
bkt_cli_stats = {}
bkt_srvcli_stats = {}

GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)

def to_be_ignored(a):
    EXCLUDED_VLAN = ["9","24","53","57","58","203"]
    if a["vlan_id"] in EXCLUDED_VLAN:
        return True
    return False

def new_alert(a):
    # check if has to be ignored
    if to_be_ignored(a):
        return

    # fix dtypes and remove unnecessary fields to improve performance
    remove_unwanted_fields(a)
    a_convert_dtypes(a)

    # add to buckets (i.e. groups)
    global bkt_srv,bkt_cli,bkt_srvcli # use global reference
    bkt_srv = add_to_bucket(a,bkt_srv,(a["srv_ip"], a["vlan_id"], a["alert_id"]))
    bkt_cli = add_to_bucket(a,bkt_cli,(a["cli_ip"], a["vlan_id"], a["alert_id"]))
    bkt_srvcli = add_to_bucket(a,bkt_srvcli,(a["srv_ip"],a["cli_ip"], a["vlan_id"], a["alert_id"]))

    if STREAMING_MODE:
        # TODO harvesting()
        update_bkts_stats()

def update_bkts_stats() :
    global bkt_srv_stats,bkt_cli_stats,bkt_srvcli_stats
    # the if statement filters groups with a too small size
    bkt_srv_stats = {k : stats for (k,v) in bkt_srv.items() if (stats := compute_bkt_stats(v,GRP_SRV))}
    bkt_cli_stats = {k : stats for (k,v) in bkt_cli.items() if (stats := compute_bkt_stats(v,GRP_CLI))}
    bkt_srvcli_stats = {k : stats for (k,v) in bkt_srvcli.items() if (stats := compute_bkt_stats(v,GRP_SRVCLI))}

def add_to_bucket(alert, bkt, key):
    try:
        x = bkt[key] # throws KeyError if not existing
        bkt[key].append(alert)
        bkt[key].sort(key=lambda x : x["tstamp"])
    except KeyError:
        bkt[key] = [alert]
    return bkt

# GETTERS
def get_bkt(BKT: int) -> dict:
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (BKT == GRP_SRV):
        return bkt_srv
    if (BKT == GRP_CLI):
        return bkt_cli
    if (BKT == GRP_SRVCLI):
        return bkt_srvcli


def get_bkt_stats(BKT: int) -> dict:
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (BKT == GRP_SRV):
        return bkt_srv_stats
    if (BKT == GRP_CLI):
        return bkt_cli_stats
    if (BKT == GRP_SRVCLI):
        return bkt_srvcli_stats

def map_id_to_name(GRP_CRIT:int):
    if (GRP_CRIT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (GRP_CRIT == GRP_SRV):
        return "SRV"
    if (GRP_CRIT == GRP_CLI):
        return "CLI"
    if (GRP_CRIT == GRP_SRVCLI):
        return "SRVCLI"


def get_sup_level_alerts() -> dict:
    # Needed because json.dumps doesn't accept tuples as keys
    def str_key(d:dict):
        return {str(k): v for (k,v) in d.items()}
    
    sup_level_alerts = {}
    for grp_crit in [GRP_SRV,GRP_CLI,GRP_SRVCLI]:
        sup_level_alerts[map_id_to_name(grp_crit)] = {
            "higher_alert_types" : str_key(get_higher_alert_types(grp_crit)),
            "tls_critical" : str_key(get_tls_critical(grp_crit)),
            "cs_paradigm_odd" : str_key(get_cs_paradigm_odd(grp_crit)),
            "blk_peer" : str_key(get_blk_peer(grp_crit)),
            "simultaneous" : str_key(get_simultaneous(grp_crit)),
            "periodic" : str_key(get_periodic(grp_crit)),
            "similar_periodicity" : get_similar_periodicity(grp_crit),
            "bat_samefile" : str_key(get_bat_samefile(grp_crit)),
            "missingUA" : str_key(get_missingUA(grp_crit)),
        }
    return sup_level_alerts

# New alert handling UTILITIES 
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

    a["is_srv_victim"] = int(a["is_srv_victim"])
    a["is_srv_attacker"] = int(a["is_srv_attacker"])
    a["is_cli_victim"] = int(a["is_cli_victim"])
    a["is_cli_attacker"] = int(a["is_cli_attacker"])


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


# Stats calculation
GRP_SRV, GRP_CLI, GRP_SRVCLI = range(3)
MIN_BKT_RELEVANT_SIZE = 3

def compute_bkt_stats(s: list, GRP_CRIT: int):
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

    d["srv_attacker"] = sum(map(lambda x: x["is_srv_attacker"],s))/s_size
    d["cli_attacker"] = sum(map(lambda x: x["is_cli_attacker"],s))/s_size

    # Get blacklisted IPs and count how many they are
    # Initially assume they are equal to the first ip in the series
    d["srv_ip_blk"] = s[0]["srv_blacklisted"]
    d["cli_ip_blk"] = s[0]["cli_blacklisted"]
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
    d["tdiff_avg"] = str(d["tdiff_avg"])
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

# Superior level alert generation Getters

# @returns groups which generated a higher number 
# of different alert types than others
def get_higher_alert_types(GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")

    bkt = get_bkt(GRP_CRIT)
    bkt_stats = get_bkt_stats(GRP_CRIT)

    # keys are tuples -> ("ip","vlan_id","alert_id")
    # To obtain #{distinct alert_id} for each ("ip","vlan_id") we can map
    # the keys to discard "alert_id" and then use Counter to get the number
    # of alert_id generated by each ("ip","vlan_id")
    
    # Firstly get groups which contain more than 1 alert and where key is attacker
    def is_relevant(key):
        IS_ATTACKER_TH = 0.75
        # is_attacker if considering the tuple (srv,cli) as key
        is_attacker = True if (GRP_CRIT == GRP_SRVCLI) else False
        if not is_attacker:
            try:
                field_name = "srv_attacker" if (GRP_CRIT == GRP_SRV) else "cli_attacker"
                is_attacker = bkt_stats[key][field_name] > IS_ATTACKER_TH
            except KeyError:
                # if the group is too small and the stats haven't been computed
                is_attacker = sum(map(lambda x: x["is_srv_attacker"],bkt[key]))/len(bkt[key]) > IS_ATTACKER_TH
        return is_attacker
    
    #   Note: x should never be None, but it's safer to check regardless
    relevant_keys = filter(lambda x: x and len(x) > 1 and is_relevant(x),bkt.keys())
    
    # Count the number of alert_types for each group ("ip","vlan_id") or ("srv","cli","vlan_id")
    nat = Counter(map(lambda x: ((x[0],x[1]) if len(x) == 3 else (x[0],x[1],x[2])), relevant_keys))
    # Consider only groups which generated at least 2 different alert types
    n_alert_types_per_key = {x: count for x, count in nat.items() if count >= 2}

    # if no relevant groups, avoid calculate mean
    if len(n_alert_types_per_key) == 0:
        return {}
    
    n_alert_types_mean = math.ceil(np.mean(list(n_alert_types_per_key.values())))

    # return only keys s.t. n_alerts > mean
    return {x: count for x, count in n_alert_types_per_key.items() if count >= n_alert_types_mean}

tls_alerts = ["tls_certificate_expired","tls_certificate_mismatch","tls_old_protocol_version","tls_unsafe_ciphers","tls_certificate_selfsigned"]

def get_tls_critical(GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")

    # TODO optimize use alert_id instead of alert_name.find(tls)
    bkts_tls_alerts = filter(lambda x: not (x[1]["alert_name"].find("tls") == -1), get_bkt_stats(GRP_CRIT).items())
    
    # Count the number of alert_types for each group ("ip","vlan_id") or ("srv","cli","vlan_id")
    critical_tls_hosts = Counter(map(lambda x: ((x[0][0],x[0][1]) if len(x[0]) == 3 else (x[0][0],x[0][1],x[0][2])), bkts_tls_alerts))
    # Consider only groups which generated at least 2 different alert types
    return {x: count for x, count in critical_tls_hosts.items() if count >= 2}


# returns hosts which do not behave according to
# the client-server paradigm
def get_cs_paradigm_odd(GRP_CRIT:int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    
    bkt_s = get_bkt_stats(GRP_CRIT)
    
    # In the client-server paradigm, the common behavior is that
    # srv uses always the same known port, while clients use ephimeral ones
    # We can set an entropy threshold to determine when srv and clients are
    # behaving oddly

    def is_odd(x):
        # Note: exclude not client-server paradigm associated alerts
        excludes = ["blacklisted"]
        PORT_S_TH   = 0.1
        IP_S_TH     = 0.5
        if (GRP_CRIT != GRP_CLI and x["alert_name"] not in excludes and x["srv_port_S"] >= PORT_S_TH):
            return "odd_server"
        # A client is odd if uses the SAME port with MANY servers
        if (GRP_CRIT != GRP_SRV 
            and x["alert_name"] not in excludes
            and x["cli_port_S"] <= PORT_S_TH
            and x["srv_ip_S"] >= IP_S_TH):
            return "odd_client"
        return None
    
    # k = ("ip","vlan","alert_id") we must exclude "alert_id" 
    tmp= {k: oddity for (k,v) in bkt_s.items() if (oddity := is_odd(v))}
    # hosts = {}
    # for k,v in tmp.items():
    #     hosts[(k[0],k[1])] = v
    return get_hosts_noalertid(tmp)

MIN_PERIODIC_SIZE = 3
# @returns groups which are strongly periodic (i.e. tdiff_CV < 0.85)
def get_simultaneous(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)
    return {k: v["tdiff_avg"] + " " + v["alert_name"] for (k,v) in bkt_s.items() 
            if ((v["tdiff_CV"] == 0
                 or v["tdiff_avg"] == "0:00:00")
            and v["size"] > MIN_PERIODIC_SIZE)}


def get_periodic(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)

    # Note: exclude not periodic relevant alerts
    excludes = tls_alerts + ["remote_to_local_insecure_proto","ndpi_http_suspicious_user_agent"]

    THRESHOLD = 0.85
    # TODO return also CV?  i.e. (v["tdiff_avg"],v["tdiff_CV"],v["size"]))
    return {k: v["tdiff_avg"] + " " + v["alert_name"] for (k, v) in bkt_s.items()
            if v["tdiff_CV"] < THRESHOLD
            and v["tdiff_CV"] > 0.0
            and v["tdiff_avg"] != "0:00:00"
            and v["size"] >= MIN_PERIODIC_SIZE
            and v["alert_name"] not in excludes}

def get_similar_periodicity(GRP_CRIT:int):
    # TODO consider also the alert type
    bkt_s = get_bkt_stats(GRP_CRIT)

    # filter only periodic groups, i.e. tdiff_CV < 1.25
    # Sort on tdiff_CV, positioning in the list head the "most periodic", 
    # or "most accurate" alert groups
    # periods = { K : (period, CV) }    with K = (IP,VLAN,ALERT_ID)

    # Note: exclude not periodic relevant alerts
    excludes = tls_alerts + ["remote_to_local_insecure_proto","ndpi_http_suspicious_user_agent"]

    periods = sorted({k: (v["tdiff_avg"], v["tdiff_CV"],v["alert_name"]) for (k, v) in bkt_s.items()
                      if (v["tdiff_CV"] < 1.25 
                      and v["tdiff_CV"] > 0.0
                      and v["size"] > MIN_PERIODIC_SIZE
                      and v["alert_name"] not in excludes)}.items(),
                     key=lambda x: x[1][1])
    
    bins = {}   # bins will hold the result
    # bins = { "P" : [ K1,K2,...,KN ]}    
    # with P = period string %H:%M:%S && Ki | Ki["tdiff_avg"] 'is similar to' P
    
    # Basic criteria to cluster the data
    def are_similar(a,b):
        return abs(a - b) <= 60

    # Tries to add x to the FIRST similar bin found
    def add_to_bin(x):
        curr_tdiff_avg = str_to_timedelta(x[1][0]).total_seconds()
        # Iterate on the period keys
        for str_bin_key in bins.keys():
            bin_key = str_to_timedelta(str_bin_key).total_seconds()
            if are_similar(curr_tdiff_avg,bin_key):
                bins[str_bin_key].append(x)
                return 1
        # No bin with similar period found
        return None
            
    for p in periods:
        if not add_to_bin(p):
            # If there is no similar bin key to p, create one
            bin_key = p[1][0] # = p["tdiff_avg"]
            bins[bin_key] = [p]

    def groupby_alertid(bin:list):
        d = {}
        for entry in bin:
            # entry[0] = (IP,VLAN,ALERT_ID)
            # entry[1] = (tdiff_avg,tdiff_CV,alert_name)
            alert_name = entry[1][-1]
            if alert_name not in d:
                d[alert_name] = [entry[0][0:-1]]
            else:
                d[alert_name].append(entry[0][0:-1])
        return {k : v for k,v in d.items() if len(v) >= 2}

    def get_avg_tdiff(v: list):
        return str(dt.timedelta(seconds=int(np.mean(list(map(lambda x: str_to_timedelta(x[1][0]).total_seconds(), v))))))
    return { get_avg_tdiff(v) : alert_grouped_bin for (k,v) in bins.items() if (alert_grouped_bin := groupby_alertid(v))}
    


# @returns groups associated with BAT alerts transferring always the same file
def get_bat_samefile(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)
    return {k: v["bft_same_file"] for (k,v) in bkt_s.items() if v["bft_same_file"] != ""}

# @returns groups associated with BAT alerts with high percentage of missing User-Agent
def get_missingUA(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)

    # exclude not interesting alerts
    excludes = ["ndpi_http_suspicious_user_agent"]

    # Percentage of missing User-Agent in BFT alerts
    NO_UA_PERC_TH = 0.9
    tmp = {k: "missingUA" for (k,v) in bkt_s.items() if (
        v["noUA_perc"] > NO_UA_PERC_TH
        and v["alert_name"] not in excludes)}

    return get_hosts_noalertid(tmp)



# @returns (srv XOR cli) groups with a high percentage of blacklisted hosts
def get_blk_peer(GRP_CRIT:int):
    if GRP_CRIT == GRP_SRVCLI:
        return {}
    if GRP_CRIT not in range(2):
        raise Exception("Invalid grouping criteria, only GRP_SRV and GRP_CLI available")
    
    bkt_s = get_bkt_stats(GRP_CRIT)
    
    # Blacklisted hosts percentage threshold
    BLK_PERC_TH = 0.25

    
    excludes = ["blacklisted"]
    if (GRP_CRIT == GRP_SRV):
        peers = {k: "blk_cli_peer" for (k, v) in bkt_s.items()
                 if (v["cli_ip_blk"] > BLK_PERC_TH and v["alert_name"] not in excludes)}
    if (GRP_CRIT == GRP_CLI):
        peers = {k: "blk_cli_peer" for (k, v) in bkt_s.items()
                 if (v["cli_ip_blk"] > BLK_PERC_TH and v["alert_name"] not in excludes)}

    # print(json.dumps({str(k):v for k,v in peers.items()},indent=2))
    
    # k = ("ip","vlan","alert_id") we must exclude "alert_id" 
    
    # This returns all specific hosts
    # for k,v in peers.items():
    #     hosts[(k[0],k[1])] = v
    
    # In the following way, we produce group similar IPs
    return get_hosts_noalertid(peers)

def get_hosts_noalertid(hosts: dict):
    tmp = {}
    for k,v in hosts.items():
        key = None
        try:
            if(len(k) == 4):    # (srv,cli,vlan,alert_id)
                key = (k[0],k[1],k[2])
                if (tmp[key] != v):
                    tmp[key] += v  
            else: # len(k) == 3
                key = (k[0],k[1])
                if (tmp[key] != v):
                    tmp[key] += v
        except KeyError:
            tmp[key] = v
    return tmp

def group_hosts_first2IPblocks(hosts: dict):
    tmp = {}
    for k,v in hosts.items():
        # determine whether it is IPv4 or IPv6 addr
        sep = "." if (k[0].find(".") != -1) else ":"
        # get the first 2 blocks of IP addr; i.e. 192.168.1.1 -> 192.168
        ip1 = sep.join(re.split('\.|:',k[0],2)[:2])
        if(len(k) == 4):    # (srv,cli,vlan,alert_id)
            # parse second IP
            ip2 = sep.join(re.split('\.|:',k[1],2)[:2])
            tmp[(ip1,ip2,k[2])] = v
        else: # len(k) == 3
            tmp[(ip1,k[1])] = v
    
    return tmp

def str_to_timedelta(s: str) -> dt.timedelta:
    d = dt.datetime.strptime(s, "%H:%M:%S")
    total_sec = d.hour*3600 + d.minute*60 + d.second  # total seconds calculation
    return dt.timedelta(seconds=total_sec)