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
import utils as u

STREAMING_MODE = False
LEARNING_PHASE = True

bkt_srv = {}
bkt_cli = {}
bkt_srvcli = {}

singleton = {}
sav = {}        # Singleton Alert View
snd_grp = {}    # Secondary groupings
unidir = {}     # Unidirectional traffic notice


bat_paths = {}
bat_server = {}

bkt_srv_stats = {}
bkt_cli_stats = {}
bkt_srvcli_stats = {}

GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)

def to_be_ignored(a):
    EXCLUDED_VLAN = ["9","24","53","57","58","203"]
    EXCLUDED_ALERTIDS = ["91",  # vlan_bidirectional_traffic
                         "75"]  # connection_failed : Warning TCP Connection failed
    if (a["vlan_id"] in EXCLUDED_VLAN or
        a["alert_id"] in EXCLUDED_ALERTIDS):
            return True
    return False

def new_alert(a):
    # check if has to be ignored
    if to_be_ignored(a):
        return


    # fix dtypes and remove unnecessary fields to improve performance
    remove_unwanted_fields(a)
    a_convert_dtypes(a)

    if unidirectional_handler(a) == True:
        return

    # if unidirectional traffic but low severity discard
    if (a["alert_id"] == 26 and a["severity"] <=4):
        return


    # add to buckets (i.e. groups)
    global bkt_srv,bkt_cli,bkt_srvcli # use global reference
    SRV_ID = a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"]
    CLI_ID = a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"]
    bkt_srv = add_to_bucket(a,bkt_srv,(SRV_ID, a["vlan_id"], a["alert_id"]))
    bkt_cli = add_to_bucket(a,bkt_cli,(CLI_ID, a["vlan_id"], a["alert_id"]))
    bkt_srvcli = add_to_bucket(a,bkt_srvcli,(SRV_ID,CLI_ID, a["vlan_id"], a["alert_id"]))

    # add to singleton groups
    global singleton
    singleton = add_to_singleton(singleton,a)

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
    # DEBUG print
    # if (alert["alert_id"] == 28 and alert["score"] > 150):
    #     print(json.dumps(json.loads(alert["json"]),indent=2))
    try:
        x = bkt[key] # throws KeyError if not existing
        bkt[key].append(alert)
        bkt[key].sort(key=lambda x : x["tstamp"])
    except KeyError:
        bkt[key] = [alert]
    return bkt

def add_to_singleton(bkt,alert):
    alert_name = get_alert_name(alert["json"])
    key = is_relevant_singleton(alert)
    try:
        x = bkt[key] # throws KeyError if not existing
        bkt.pop(key, None)
    except KeyError:
        if key:
            bkt[key] = (alert_name)
    return bkt

def add_bat_path(path):
    if path in bat_paths:
        return bat_paths
    else:
        bat_paths[path] = 1

def harvesting(bound: dt.datetime):
    def to_harvest(alert):
        return alert["tstamp"] < bound
    
    global bkt_srv,bkt_cli,bkt_srvcli
    bkt_srv = {k:harvested_v for (k,v) in bkt_srv.items() if len(harvested_v := list(filter(to_harvest,v)))}
    bkt_cli = {k:harvested_v for (k,v) in bkt_cli.items() if len(harvested_v := list(filter(to_harvest,v)))}
    bkt_srvcli = {k:harvested_v for (k,v) in bkt_srvcli.items() if len(harvested_v := list(filter(to_harvest,v)))}
    

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


TLS_ALERTS = ["tls_certificate_expired","tls_certificate_mismatch","tls_old_protocol_version","tls_unsafe_ciphers"]
# "tls_certificate_selfsigned"

RELEVANT_SINGLETON_ALERTS = [
    # "binary_application_transfer",
    # "remote_to_local_insecure_proto",
    # "ndpi_ssh_obsolete_client",
    # "ndpi_clear_text_credentials",
    "ndpi_smb_insecure_version",
    "data_exfiltration",
    # "ndpi_suspicious_dga_domain",
    # "tls_certificate_selfsigned"
    ]

IGNORE_SINGLETON_ALERTS = [
    # These are not interesting alerts by theirselves
    "blacklisted",
    "ndpi_dns_suspicious_traffic",
    "ndpi_http_suspicious_user_agent",

    # These are exported only when matching
    # more specific criterias
    "ndpi_http_suspicious_content",
    "ndpi_suspicious_dga_domain",
    "ndpi_ssh_obsolete_client",
    "binary_application_transfer",
    "ndpi_clear_text_credentials",
    "remote_to_local_insecure_proto",
    "tls_certificate_selfsigned"

] + TLS_ALERTS

clear_text_usernames = {}
dga_suspicious_domains = {}
tls_self_ja3_tuples = {}

def dict_init_alertnames():
    sav["ndpi_ssh_obsolete_client"] = {}
    sav["ndpi_http_suspicious_content"] = {}
    sav["remote_to_local_insecure_proto"] = {}
    sav["binary_application_transfer"] = {}
    snd_grp["ndpi_clear_text_credentials"] = {}
    snd_grp["ndpi_suspicious_dga_domain"] = {}
    snd_grp["tls_certificate_selfsigned"] = {}
    

def is_relevant_singleton(a):
    global sav,snd_grp
    alert_name = get_alert_name(a["json"])
    
    CLI_ID = (a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"],
              a["vlan_id"])
    SRV_ID = (a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"],
              a["vlan_id"])
    SRVCLI_ID = (a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"],
                 a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"],
                 a["vlan_id"])

    def get_atk_key():
        k = SRVCLI_ID
        if (a["is_srv_attacker"] == 1):
            k = SRV_ID
        if (a["is_cli_attacker"] == 1):
            k = CLI_ID
        # TODO can this happen?
        # Note: case not included in k init
        if (a["is_srv_attacker"] == 1 and a["is_cli_attacker"] == 1):
            k = SRVCLI_ID
        return k
    
    # We only care about the client in this case
    if (alert_name == "ndpi_ssh_obsolete_client"):
        # sav[alert_name].append(CLI_ID)
        u.addremove_to_singleton(sav[alert_name],CLI_ID)
        return CLI_ID
    
    # BAT is relevant if it concerns a previously unseen file
    # The learning phase must be over, otherwise every new transfer
    # get marked as relevant 
    if (alert_name == "binary_application_transfer"
        and (path := (u.get_BAT_path_server(a["json"]))[0])
        and path not in bat_paths
        and LEARNING_PHASE == False):
        sav[alert_name][path] = SRVCLI_ID
        return SRVCLI_ID
    
    # "ndpi_http_suspicious_content" leads to a +100 score
    # In case of other simultaneous issues like non-std ports,
    # or missing user agent, the score gets higher.
    # We want to seize these scenarios
    if (alert_name == "ndpi_http_suspicious_content" and a["score"] > 150):
        u.addremove_to_singleton(sav[alert_name],SRVCLI_ID)
        return SRVCLI_ID

    key = get_atk_key()
    a_json = json.loads(a["json"])

    # Interested in remote_to_local only when regarding remote access (score = 100),
    # i.e. Telnet
    # But there should be some other issues related, so the score should be higher
    if (alert_name == "remote_to_local_insecure_proto" 
        and a_json["ndpi_category_name"] == "RemoteAccess"
        and a["score"] >= 180):
        u.addremove_to_singleton(sav[alert_name],key)
        return key
    
    # When sending clear-text credentials
    # Consider only hosts which are using previously unseen usernames
    def get_username():
        flow_risk_info = json.loads(a_json["alert_generation"]["flow_risk_info"])
        if ("36" in flow_risk_info
            and "username" in flow_risk_info["36"]):
            # Parse 'Found FTP username (USERNAME)'
            i = flow_risk_info["36"].find('(')
            return (flow_risk_info["36"][i+1:]
                    .removesuffix(")"))
        '''
        TODO
        Find a way to retrieve info when
        "flow_risk_info": "{\"36\":\"Found credentials in HTTP Auth Line\"}"
        '''
        return None
    global clear_text_usernames
    if (alert_name == "ndpi_clear_text_credentials"
    and (username := get_username()) ):
    # and username not in clear_text_usernames):
        if (username not in snd_grp[alert_name]):
            snd_grp[alert_name][username] = {}
        snd_grp[alert_name][username][key] = 1
        # snd_grp[alert_name][username] = (snd_grp[alert_name][username][key] if (username in snd_grp[alert_name]) else [key])
        # add to "known" usernames
        clear_text_usernames[username] = key
        # add username to key tuple
        return key + (username,)

    def get_domain_name():
        flow_risk_info = json.loads(a_json["alert_generation"]["flow_risk_info"])
        if ("16" in flow_risk_info):
            # Parse "flow_risk_info": "{\"16\":\"domain.com\"}"
            return (flow_risk_info["16"])
        return None
    if (alert_name == "ndpi_suspicious_dga_domain"
        and (domain_name := get_domain_name()) ):
        # # and domain_name not in dga_suspicious_domains):
        # if (domain_name not in snd_grp[alert_name]):
        #     snd_grp[alert_name][domain_name] = {}
        # snd_grp[alert_name][domain_name][key] = 1
        # # snd_grp[alert_name][domain_name] = (snd_grp[alert_name][domain_name][key] if (domain_name in snd_grp[alert_name]) else [key])
        # # add to "known" domains
        # dga_suspicious_domains[domain_name] = key
        # # add domains to key tuple
        # return key + (domain_name,)
        key = SRVCLI_ID
        partial_name = u.add_to_domain_dict(dga_suspicious_domains,domain_name,key)
        dga_suspicious_domains[partial_name][key] += 1
        return key + (partial_name,)

    # Cert self signed distinct on JA3 hash


    def get_ja3_hash():
        if ("tls" not in a_json["proto"]):
            return None
        tls_info = a_json["proto"]["tls"]
        if ("ja3.server_hash" in tls_info and
            "ja3.client_hash" in tls_info):
            # Parse "tls_info": "{\"16\":\"domain.com\"}"
            return (tls_info["ja3.server_hash"],tls_info["ja3.client_hash"])
        return None
    if (alert_name == "tls_certificate_selfsigned"
        and (ja3_hash := get_ja3_hash()) ):
        # and ja3_hash not in tls_self_ja3_tuples):
        key = SRV_ID
        if (ja3_hash not in snd_grp[alert_name]):
            snd_grp[alert_name][ja3_hash] = {}
        snd_grp[alert_name][ja3_hash][key] = 1
        # snd_grp[alert_name][ja3_hash] = (snd_grp[alert_name][ja3_hash][key] if (ja3_hash in snd_grp[alert_name]) else [key])
        # add to "known" ja3 hashes
        tls_self_ja3_tuples[ja3_hash] = key
        # add domains to key tuple
        return key + (ja3_hash,)


    # if (alert_name in RELEVANT_SINGLETON_ALERTS):
    if (alert_name not in IGNORE_SINGLETON_ALERTS):
        if (alert_name not in sav):
            sav[alert_name] = {}
        # check if the key was already present
        # if yes, it is not a singleton
        u.addremove_to_singleton(sav[alert_name],key)

    
    return None



# GETTERS
def get_singleton() -> dict:
    # return {k: v for k,v in singleton.items() if v[0] in RELEVANT_SINGLETON_ALERTS}
    return singleton

def get_singleton_alertview() -> dict:
    return {k: (u.str_key(v) if (type(v) is dict)
                else (u.str_val(v) if (type(v) is list)
                else v))
                
                for k, v in sav.items()}

def get_secondary_groupings() -> dict:
    return {k: (u.str_key(v) if (type(v) is dict)
                else (u.str_val(v) if (type(v) is list)
                else v))
                
                for k, v in snd_grp.items()}

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
    
    sup_level_alerts = {"FLAT_GROUPINGS": {},
                        "BAT_SERVER_NAMES": {},
                        "DGA_DOMAINS": {},
                        "PROBING_VICTIMS": {}}
    for grp_crit in [GRP_SRV, GRP_CLI, GRP_SRVCLI]:
        sup_level_alerts["FLAT_GROUPINGS"][map_id_to_name(grp_crit)] = {
            "higher_alert_types" : u.str_key(get_higher_alert_types(grp_crit)),
            # "tls_critical" : u.str_key(get_tls_critical(grp_crit)),
            # "cs_paradigm_odd" : u.str_key(get_cs_paradigm_odd(grp_crit)),
            # "blk_peer" : u.str_key(get_blk_peer(grp_crit)),
            "simultaneous" : u.str_key(get_simultaneous(grp_crit)),
            "periodic" : u.str_key(get_periodic(grp_crit)),
            "similar_periodicity" : get_similar_periodicity(grp_crit),
            "bat_samefile" : u.str_key(get_bat_samefile(grp_crit)),
            # "missingUA" : u.str_key(get_missingUA(grp_crit)),
        }
    sup_level_alerts["BAT_SERVER_NAMES"] = bat_server
    sup_level_alerts["DGA_DOMAINS"] = get_dga_sus_domains()
    sup_level_alerts["PROBING_VICTIMS"] = get_unidir_probed()
    return u.str_key(sup_level_alerts)

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


def unidirectional_handler(a):
    if (a["alert_id"] != 26): # 26 : Unidirectional traffic
        return False
    
    o = json.loads(a["json"])
    try:
        # print(o)
        # o = json.loads(a["json"])
        o = o["alert_generation"]["flow_risk_info"]
        o = json.loads(o)
        if (o["46"] != "No server to client traffic"):
            return False
    except KeyError as e:
        # print(repr(e))
        return False
    
    # We are sure the alert indicates
    # Unidir traffic from client to server
    k = u.get_id_vlan(a,GRP_SRV)
    cli_id = u.get_id(a,GRP_CLI)
    srv_port = a["srv_port"]
    unidir[k] = [(cli_id,srv_port)] if (k not in unidir) else unidir[k] + [(cli_id,srv_port)]

    return True

def get_unidir_probed():
    probed = {}
    MIN_PROBING_RELEVANT_SIZE = 4
    PROBING_ENTROPY_THRESH = 0.5
    for srv,t in unidir.items():
        # If a server is a victim of probing, one or more client will be trying to 
        # unidirectionally communicate with it on many different ports
        if (len(unidir[srv]) > MIN_PROBING_RELEVANT_SIZE and
            u.is_server(srv[1]) and
            (s := u.shannon_entropy(list(map(lambda x: x[1],unidir[srv])))) > PROBING_ENTROPY_THRESH):
            probed[srv] = set(map(lambda x: x[0],unidir[srv]))
        # else:
        #     probed[srv] = (s,len(unidir[srv]))
    return probed

def get_dga_sus_domains():
    return {k:v for k,v in dga_suspicious_domains.items() if len(v) > 1}

# Stats calculation
GRP_SRV, GRP_CLI, GRP_SRVCLI = range(3)
MIN_BKT_RELEVANT_SIZE = 3

def get_alert_name(x):
    o = json.loads(x)
    try:
        return o["alert_generation"]["script_key"]
    except KeyError:
        return "no_name"

def compute_bkt_stats(s: list, GRP_CRIT: int):
    if GRP_CRIT not in range(3):
        raise Exception("Invalid grouping criteria")
    if len(s) < MIN_BKT_RELEVANT_SIZE:
        return None


    # print(s)
    s_size = len(s)
    d = {}
    d["alert_name"] = get_alert_name(s[0]["json"])


    # ENTROPY (S)
    # Convert IP to int first, then compute entropy
    def ip_to_numeric(x):
        try:
            return struct.unpack("!I", socket.inet_aton(x))[0]
        except:
            print(x)
            return 0
    srv_ip_toN = list(map(ip_to_numeric,map(lambda x: x["srv_ip"],s)))
    cli_ip_toN = list(map(ip_to_numeric,map(lambda x: x["cli_ip"],s)))
    
    
    d["srv_ip_S"] = u.shannon_entropy(srv_ip_toN)
    d["cli_ip_S"] = u.shannon_entropy(cli_ip_toN)
    d["srv_port_S"] = u.shannon_entropy(list(map(lambda x: x["srv_port"],s)))
    d["cli_port_S"] = u.shannon_entropy(list(map(lambda x: x["cli_port"],s)))

    # In case of SRV | CLI
    # If the other peer is always the same, this grouping will be found in SRVCLI
    # Thus, there is no reason to duplicate the info here
    if ((GRP_CRIT == GRP_SRV and d["cli_ip_S"] == 0.0)
        or (GRP_CRIT == GRP_CLI and d["srv_ip_S"] == 0.0)):
        return None

    d["srv_attacker"] = sum(map(lambda x: x["is_srv_attacker"],s))/s_size
    d["cli_attacker"] = sum(map(lambda x: x["is_cli_attacker"],s))/s_size
    d["srv_victim"] = sum(map(lambda x: x["is_srv_victim"],s))/s_size
    d["cli_victim"] = sum(map(lambda x: x["is_cli_victim"],s))/s_size


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

    if (s[0]["alert_id"] == 29):
        # get the first path
        first_path = (u.get_BAT_path_server(s[0]["json"]))[0]
        
        paths_servers_keys = map(lambda x: u.get_BAT_path_server(x["json"]) + (u.get_id_vlan(x,GRP_SRVCLI),),s)
        if first_path != "":
            bat_paths[first_path] = 1
            for p,srv_name,k in paths_servers_keys:
                if p != first_path:
                    first_path = ""
                    break
        # get all servers
        for p,server_name,key in paths_servers_keys:
            server_name = server_name if (server_name != "") else "-missing server name-"
            u.add_to_dict_dict_counter(bat_server,server_name,str(key))

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
    
    # Firstly get groups which contain more than 1 alert and where key is not victim
    def is_relevant(key):
        IS_VICTIM_TH = 0.75
        # not is_victim if considering the tuple (srv,cli) as key
        is_victim = False if (GRP_CRIT == GRP_SRVCLI) else True
        if (GRP_CRIT != GRP_SRVCLI):
            try:
                field_name = "srv_victim" if (GRP_CRIT == GRP_SRV) else "cli_victim"
                is_victim = bkt_stats[key][field_name] > IS_VICTIM_TH
            except KeyError:
                # if the group is too small and the stats haven't been computed
                is_victim = sum(map(lambda x: x["is_" + field_name],bkt[key]))/len(bkt[key]) > IS_VICTIM_TH
        return not is_victim
    
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
    return {x: count for x, count in n_alert_types_per_key.items() if count > n_alert_types_mean}

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

    def is_odd(x,vlan_id):
        # Note: exclude not client-server paradigm associated alerts
        excludes = ["blacklisted"]
        PORT_S_TH   = 0.1
        IP_S_TH     = 0.5
        if (GRP_CRIT != GRP_CLI 
            and x["alert_name"] not in excludes
            and x["srv_port_S"] >= PORT_S_TH
            and u.is_server(vlan_id)):
            return "odd_server"
        # A client is odd if uses the SAME port with MANY servers
        if (GRP_CRIT != GRP_SRV 
            and x["alert_name"] not in excludes
            and x["cli_port_S"] <= PORT_S_TH
            and x["srv_ip_S"] >= IP_S_TH
            and u.is_client(vlan_id)):
            return "odd_client"
        return None
    
    # k = ("ip","vlan","alert_id") we must exclude "alert_id" 
    tmp= {k: oddity for (k,v) in bkt_s.items() if (oddity := is_odd(v,k[-1:]))}
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
                 or (v["tdiff_avg"] == "0:00:00" and v["tdiff_CV"] <= 0.5))
            and v["size"] > MIN_PERIODIC_SIZE)}


def get_periodic(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)

    # Note: exclude not periodic relevant alerts
    excludes = TLS_ALERTS + ["remote_to_local_insecure_proto","ndpi_http_suspicious_user_agent"]

    THRESHOLD = 0.8
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
    excludes = TLS_ALERTS + ["remote_to_local_insecure_proto","ndpi_http_suspicious_user_agent"]

    periods = sorted({k: (v["tdiff_avg"], v["tdiff_CV"],v["alert_name"]) for (k, v) in bkt_s.items()
                      if (v["tdiff_CV"] < 1
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
        curr_tdiff_avg = u.str_to_timedelta(x[1][0]).total_seconds()
        # Iterate on the period keys
        for str_bin_key in bins.keys():
            bin_key = u.str_to_timedelta(str_bin_key).total_seconds()
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
        return str(dt.timedelta(seconds=int(np.mean(list(map(lambda x: u.str_to_timedelta(x[1][0]).total_seconds(), v))))))
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

dict_init_alertnames()