import pandas as pd
import json

import pandas as pd
import math
from scipy.stats import entropy
from collections import Counter
import struct
import socket

bkt_srv = None
bkt_cli = None
bkt_srvcli = None

GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)


def new_alert(a):
    # fix dtypes and remove unnecessary fields to improve performance
    remove_unwanted_fields(a)
    a_convert_dtypes(a)

    # add to buckets (i.e. groups)
    global bkt_srv,bkt_cli,bkt_srvcli # use global reference
    bkt_srv = add_to_bucket(a,bkt_srv,[(a["srv_ip"], a["alert_id"])],("srv_ip", "alert_id"))
    bkt_cli = add_to_bucket(a,bkt_cli,[(a["cli_ip"], a["alert_id"])],("cli_ip", "alert_id"))
    bkt_srvcli = add_to_bucket(a,bkt_srvcli,[(a["srv_ip"],a["cli_ip"], a["alert_id"])],("srv_ip","cli_ip", "alert_id"))


def add_to_bucket(alert, bkt, index_tuple, index_name):
    tmp = pd.DataFrame(alert, index=pd.MultiIndex.from_tuples(index_tuple, names=index_name))
    if bkt is None:    # first alert
        bkt = tmp
    else:
        bkt = pd.concat([bkt, tmp], axis=0, copy=False, join="inner")
    return bkt


def get_bkt(BKT: int):
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (BKT == GRP_SRV):
        return bkt_srv
    if (BKT == GRP_CLI):
        return bkt_cli
    if (BKT == GRP_SRVCLI):
        return bkt_srvcli


def a_convert_dtypes(a):
    # convert dtypes
    # tmp = a["tstamp"]
    a["tstamp"] = pd.to_datetime(a["tstamp"])
    a["tstamp_end"] = pd.to_datetime(a["tstamp_end"])
    # print(str(tmp) + str(type(tmp)) + ' --> ' +
    #   str(a["tstamp"]) + str(type(a["tstamp"])))

    a["srv_port"] = pd.to_numeric(a["srv_port"])
    a["severity"] = pd.to_numeric(a["severity"])
    a["cli2srv_bytes"] = pd.to_numeric(a["cli2srv_bytes"])
    a["vlan_id"] = pd.to_numeric(a["vlan_id"])
    a["rowid"] = pd.to_numeric(a["rowid"])
    a["community_id"] = pd.to_numeric(a["community_id"])
    a["ip_version"] = pd.to_numeric(a["ip_version"])
    a["srv2cli_pkts"] = pd.to_numeric(a["srv2cli_pkts"])
    a["interface_id"] = pd.to_numeric(a["interface_id"])
    a["cli2srv_pkts"] = pd.to_numeric(a["cli2srv_pkts"])
    a["score"] = pd.to_numeric(a["score"])
    a["srv2cli_bytes"] = pd.to_numeric(a["srv2cli_bytes"])
    a["cli_port"] = pd.to_numeric(a["cli_port"])
    a["alert_id"] = pd.to_numeric(a["alert_id"])
    a["l7_proto"] = pd.to_numeric(a["l7_proto"])

    a["srv_blacklisted"] = pd.to_numeric(a["srv_blacklisted"])
    a["cli_blacklisted"] = pd.to_numeric(a["cli_blacklisted"])

    # TODO strings are still recognised as 'object'
    # a["probe_ip"] = str(a["probe_ip"])
    # a["cli_ip"] = str(a["cli_ip"])
    # a["srv_name"] = str(a["srv_name"])
    # a["srv_ip"] = str(a["srv_ip"])
    # a["cli_name"] = str(a["cli_name"])


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

    a.pop("user_label_tstamp", None)
    a.pop("cli_host_pool_id", None)
    a.pop("srv_host_pool_id", None)
    a.pop("is_srv_victim", None)
    a.pop("is_srv_attacker", None)
    a.pop("is_cli_victim", None)
    a.pop("is_cli_attacker", None)


# Stats calculation

# sort on tstamp
# srv = srv.sort_values(by=["tstamp"])
# print("\tSorted alerts")


def is_UA_missing(x):
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


def get_alert_name(x):
    o = json.loads(x)
    try:
        return o["alert_generation"]["script_key"]
    except KeyError:
        return "no_name"


def getBFTfilename(x):
    o = json.loads(x)
    try:
        return o["last_url"]
    except KeyError:
        return math.nan


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


def ip2int(x):
    return struct.unpack("!I", socket.inet_aton(x))[0]


GRP_SRV, GRP_CLI, GRP_SRVCLI = range(3)


def stats_from_series(s: pd.Series, GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    s_size = len(s)
    d = {}
    d["alert_name"] = s["json"].head(1).apply(get_alert_name).iat[0]
    # Convert IP to int first, then compute entropy
    srv_ip_toN = s["srv_ip"].map(
        lambda x: struct.unpack("!I", socket.inet_aton(x))[0])
    cli_ip_toN = s["cli_ip"].map(
        lambda x: struct.unpack("!I", socket.inet_aton(x))[0])
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
        cli_ip_blk_df = s[["cli_ip", "cli_blacklisted"]
                          ].loc[s["cli_blacklisted"] == 1, "cli_ip"]
        d["cli_ip_blk"] = (cli_ip_blk_df.nunique()/len(s) if len(s) else 0)
        d["srv_ip_blk"] = s["srv_blacklisted"].iat[0]
    elif (GRP_CRIT == GRP_CLI):
        srv_ip_blk_df = s[["srv_ip", "srv_blacklisted"]
                          ].loc[s["srv_blacklisted"] == 1, "srv_ip"]
        d["srv_ip_blk"] = (srv_ip_blk_df.nunique()/len(s) if len(s) else 0)
        d["cli_ip_blk"] = s["cli_blacklisted"].iat[0]
    # Periodicity - AKA Time interval Coefficient of Variation (CV)
    # TODO histogram rita-like
    tdiff_avg_unrounded = s["tstamp"].diff().mean()
    d["tdiff_avg"] = tdiff_avg_unrounded.round("s")
    # If the avg period is close to 0...
    if d["tdiff_avg"].total_seconds() == 0:  # cannot divide by 0
        # 1.0 #... consider '1' as reference to compute CV
        tdiff_avg_unrounded = pd.Timedelta(1, "s")
    # Compute CV as stddev/avg
    d["tdiff_CV"] = s["tstamp"].std()/tdiff_avg_unrounded
    # NTOPNG score average
    d["score_avg"] = s["score"].mean()
    # Missing User-Agent percentage (0<p<1 format)
    d["noUA_perc"] = s["json"].apply(is_UA_missing).sum() / s_size
    d["size"] = s_size
    # BinaryFileTransfer -> Check if same file
    #  Note: nunique() doesn't count NaN values
    d["bft_same_file"] = ""
    if (s["alert_id"].iat[0] == 29):
        filenames = s["json"].apply(getBFTfilename)
        # print(filenames)
        # print(filenames.nunique())
        d["bft_same_file"] = filenames.iat[0] if (
            filenames.nunique() == 1) else ""
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
        ((d["srv_ip_S"]) * 10) +
        ((d["cli_ip_S"])*10) +
        # Inverse of common srv/cli behavior, i.e. HIGH srv_port_S || LOW cli_port_S
        #   => Higher score
        (d["srv_port_S"])*10 +
        (1 - d["cli_port_S"])*10 +
        # Extra points if communicating with blacklisted IPs
        # if alert isn't of type "blacklisted"
        d["srv_ip_blk"] * (20 if s["alert_id"].iat[0] != 1 else 5) +
        # if alert isn't of type "blacklisted"
        d["cli_ip_blk"] * (20 if s["alert_id"].iat[0] != 1 else 5) +
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
    return pd.Series(d, index=["alert_name", "X-Score", "srv_ip_S", "cli_ip_S", "srv_port_S", "cli_port_S", "cli_ip_blk", "srv_ip_blk", "tdiff_avg", "tdiff_CV", "score_avg", "noUA_perc", "size", "bft_same_file"])
