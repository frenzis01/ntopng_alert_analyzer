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
from .utils import u
from .utils.c import *
from .utils import ctx_ as ctx
from ipaddress import ip_address

import matplotlib.pyplot as plt

STREAMING_MODE = False
LEARNING_PHASE = False
CONTEXT_INFO = True

bat_paths = set()
alerts_per_host = {}

def init():
    global bkt_srv,bkt_cli,bkt_srvcli
    bkt_srv = {}
    bkt_cli = {}
    bkt_srvcli = {}

    global singleton,sav,snd_grp,unidir,longlived,lowgoodput
    singleton = {}
    sav = {}        # Singleton Alert View
    snd_grp = {}    # Secondary groupings
    unidir = {}     # Unidirectional traffic notice
    longlived = {}  # Long-lived flows notice
    lowgoodput = {} # Low goodput ratio notice

    global bat_paths,bat_server,bkt_srv_stats,bkt_cli_stats,bkt_srvcli_stats,sup_level_alerts
    # TODO path
    # bat_paths = set()
    bat_server = {}
    bkt_srv_stats = {}
    bkt_cli_stats = {}
    bkt_srvcli_stats = {}
    sup_level_alerts = {}


    global clear_text_usernames,dga_suspicious_domains,tls_self_ja3_tuples
    clear_text_usernames = {}
    dga_suspicious_domains = {}
    tls_self_ja3_tuples = {}

    global alerts_per_host
    for k in alerts_per_host.keys():
        alerts_per_host[k] += [0]

    dict_init_alertnames()


def dict_init_alertnames():
    sav["ndpi_ssh_obsolete_client"] = {}
    sav["ndpi_http_suspicious_content"] = {}
    sav["remote_to_local_insecure_proto"] = {}
    sav["binary_application_transfer"] = {}
    snd_grp["ndpi_clear_text_credentials"] = {}
    snd_grp["ndpi_suspicious_dga_domain"] = {}
    snd_grp["tls_certificate_selfsigned"] = {}
    
def set_bkt_stats(bkt_stats_update:list):
    global bkt_srv_stats,bkt_cli_stats,bkt_srvcli_stats
    bkt_srv_stats = bkt_stats_update[0]
    bkt_cli_stats = bkt_stats_update[1]
    bkt_srvcli_stats = bkt_stats_update[2]

def set_alerts_per_host(ah:dict,n_time_windows:int):
    global alerts_per_host
    alerts_per_host = {k:v[:n_time_windows] for k,v in ah.items()}

init()

def to_be_ignored(a):
    try:
        if (CONTEXT_INFO and (
            a["vlan_id"] in ctx.EXCLUDED_VLAN or
            a["alert_id"] in ctx.EXCLUDED_ALERTIDS) or
            any(s in ctx.EXCLUDED_HOSTS for s in [a["srv_ip"],a["srv_name"],a["cli_ip"],a["cli_name"]])):
                return True
    except:
        return True
    return False

def new_alert(a):
    a["alert_id"] = int(a["alert_id"])
    a["vlan_id"] = int(a["vlan_id"]) if (a["vlan_id"] != "") else -1
    
    # check if has to be ignored
    if to_be_ignored(a):
        return

    if (low_goodput_handler(a) or
        long_lived_flow_handler(a)):
        return

    # fix dtypes and remove unnecessary fields to improve performance
    u.remove_unwanted_fields(a)
    u.a_convert_dtypes(a)

    if unidirectional_handler(a):
        return

    # if unidirectional_handler(a) returned None but
    # unidirectional traffic (and low severity) discard
    if (a["alert_id"] == 26 and a["severity"] <=4):
        return


    # add to buckets (i.e. groups)
    global bkt_srv,bkt_cli,bkt_srvcli # use global reference
    SRV_ID = a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"]
    CLI_ID = a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"]
    bkt_srv = add_to_bucket(a,bkt_srv,(SRV_ID, a["vlan_id"], a["alert_id"]))
    bkt_cli = add_to_bucket(a,bkt_cli,(CLI_ID, a["vlan_id"], a["alert_id"]))
    bkt_srvcli = add_to_bucket(a,bkt_srvcli,(SRV_ID,CLI_ID, a["vlan_id"], a["alert_id"]))

    u.n_alerts_incr(alerts_per_host,(SRV_ID,a["vlan_id"]))
    u.n_alerts_incr(alerts_per_host,(CLI_ID,a["vlan_id"]))
    # # add to singleton groups
    # global singleton
    # singleton = add_to_singleton(singleton,a)
    is_relevant_singleton(a)

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

def add_to_singleton(bkt,alert):
    alert_name = get_alert_name(alert["json"])
    key = is_relevant_singleton(alert)
    # AVOID updating singleton alerts
    # try:
    #     x = bkt[key] # throws KeyError if not existing
    #     bkt.pop(key, None)
    # except KeyError:
    #     if key:
            # bkt[key] = (alert_name)
    return bkt

def harvesting(bound: dt.datetime):
    def to_harvest(alert):
        return alert["tstamp"] < bound
    
    # TODO perform also on other groupings
    global bkt_srv,bkt_cli,bkt_srvcli
    bkt_srv = {k:harvested_v for (k,v) in bkt_srv.items() if len(harvested_v := list(filter(to_harvest,v)))}
    bkt_cli = {k:harvested_v for (k,v) in bkt_cli.items() if len(harvested_v := list(filter(to_harvest,v)))}
    bkt_srvcli = {k:harvested_v for (k,v) in bkt_srvcli.items() if len(harvested_v := list(filter(to_harvest,v)))}


# GETTERS
def get_bkt(BKT: int) -> dict:
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    global bkt_srv_stats,bkt_cli_stats,bkt_srvcli_stats
    if (BKT == GRP_SRV):
        return bkt_srv
    if (BKT == GRP_CLI):
        return bkt_cli
    if (BKT == GRP_SRVCLI):
        return bkt_srvcli

def is_relevant_singleton(a):
    global sav,snd_grp
    alert_name = get_alert_name(a["json"])
    
    CLI_ID = u.get_id_vlan(a,GRP_CLI)
    SRV_ID = u.get_id_vlan(a,GRP_SRV)
    SRVCLI_ID = u.get_id_vlan(a,GRP_SRVCLI)

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
    
    
    # BAT is relevant if it concerns a previously unseen file
    # The learning phase must be over, otherwise every new transfer
    # get marked as relevant
    global bat_paths
    if (alert_name == "binary_application_transfer"
        and (path_srvname := ((u.get_BAT_path_server(a["json"])))) != ("","")
        # following line is only to assign path and srvname; walrus (:=) dsnt allow unpacking
        #   i.e. `path, srvname := foo()` isn't allowed
        and (path := path_srvname[0]) and (srvname := path_srvname[1])
        and (not CONTEXT_INFO or not any(path.find(x) != -1 for x in ctx.BAT_PATH_WHITELIST))
        and (not CONTEXT_INFO or not srvname in ctx.BAT_SERVER_WHITELIST)):
        # add to srvname grouping
        srvname = srvname if (srvname != "") else "-missing server name-"
        u.add_to_dict_dict_counter(bat_server,srvname,str(SRVCLI_ID))

        # if not learning and previously unseen path
        if (LEARNING_PHASE == False and path not in bat_paths):
            # add path and srvcli to singleton alerts
            sav[alert_name][path] = SRVCLI_ID + ()
            # add to known paths
            bat_paths.add(path)
            return SRVCLI_ID
        # if not learning and path already seen
        elif (LEARNING_PHASE == False and path in bat_paths):
            # remove entry from singleton alerts, if present
            sav[alert_name].pop(path,None)
        # add to known paths regardless
        bat_paths.add(path)

    key = get_atk_key()
    a_json = json.loads(a["json"])

    def get_domain_name():
        flow_risk_info = json.loads(a_json["alert_generation"]["flow_risk_info"])
        if ("16" in flow_risk_info):
            # Parse "flow_risk_info": "{\"16\":\"domain.com\"}"
            return (flow_risk_info["16"])
        return None
    if (alert_name == "ndpi_suspicious_dga_domain"
        and (domain_name := get_domain_name()) 
        and (not CONTEXT_INFO or not any(x in domain_name.split(".") for x in ctx.WHITELIST_DOMAIN_TOKEN))):
        # We need both requestor and server in this case
        key = SRVCLI_ID
        # Find the most similar domain if existent and remove the unmatching portion
        # This results in the portion of the name used, e.g.
        #       '1564903955.dgadom.com'
        #       '6759204650.dgadom.com'
        #    Will collapse under 'dgadom.com'
        partial_name = u.add_to_domain_dict(dga_suspicious_domains,domain_name,key)
        dga_suspicious_domains[partial_name][key] += 1
        return key + (partial_name,)

    # Cert self signed grouped on JA3 hash
    def get_ja3_hash():
        if ("tls" not in a_json["proto"]):
            return None
        tls_info = a_json["proto"]["tls"]
        
        ja3_srv = tls_info["ja3.server_hash"] if ("ja3.server_hash" in tls_info) else JA3_MISSING_SRV_HASH
        ja3_cli = tls_info["ja3.client_hash"] if ("ja3.client_hash" in tls_info) else JA3_MISSING_CLI_HASH
        
        if("ja3.client_hash" in tls_info):
            # Parse "tls_info": "{\"16\":\"domain.com\"}"
            return (ja3_srv,ja3_cli)
        return None
    # Consider only non-private servers
    if (alert_name == "tls_certificate_selfsigned"
        and (ja3_hash := get_ja3_hash()) 
        and not (ip_address(a["srv_ip"]).is_private)):
        key = SRV_ID
        u.add_to_dict_dict_counter(snd_grp[alert_name],ja3_hash,key)
        # add ja3 to key tuple
        return key + (ja3_hash,)
    


    # The following are less relevant alerts

    # We only care about the client in this case
    if (alert_name == "ndpi_ssh_obsolete_client"):
        # sav[alert_name].append(CLI_ID)
        u.addremove_to_singleton(sav[alert_name],CLI_ID,1)
        return CLI_ID

    # Interested in remote_to_local only when regarding remote access (score = 100),
    # i.e. Telnet
    # But there should be some other issues related, so the score should be higher
    if (alert_name == "remote_to_local_insecure_proto" 
        and a_json["ndpi_category_name"] == "RemoteAccess"
        and a["score"] >= 180):
        u.addremove_to_singleton(sav[alert_name],key,1)
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


    # "ndpi_http_suspicious_content" leads to a +100 score
    # In case of other simultaneous issues like non-std ports,
    # or missing user agent, the score gets higher.
    # We want to seize these scenarios
    if (alert_name == "ndpi_http_suspicious_content" and a["score"] > 150):
        u.addremove_to_singleton(sav[alert_name],SRVCLI_ID,1)
        return SRVCLI_ID



    # Avoid considering other alert types

    # # if (alert_name in RELEVANT_SINGLETON_ALERTS):
    # if (alert_name not in IGNORE_SINGLETON_ALERTS):
    #     if (alert_name not in sav):
    #         sav[alert_name] = {}
    #     # check if the key was already present
    #     # if yes, it is not a singleton
    #     u.addremove_to_singleton(sav[alert_name],key,1)

    
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

def get_bkt_stats(BKT: int) -> dict:
    if (BKT not in range(3)):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    # global bkt_srv_stats,bkt_cli_stats,bkt_srvcli_stats
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

def map_name_to_id(GRP_CRIT:str):
    if (GRP_CRIT not in ["SRV","CLI","SRVCLI"]):
        raise Exception("Invalid bucket id: 0,1,2 (srv,cli,srvcli) available only")
    if (GRP_CRIT == "SRV"):
        return GRP_SRV
    if (GRP_CRIT == "CLI"):
        return GRP_CLI
    if (GRP_CRIT == "SRVCLI"):
        return GRP_SRVCLI



def get_host_ratings(sup_alerts: dict):
    hostsR = {}
    
    BAT_ONE_TIME_srv = 25
    BAT_ONE_TIME_cli = 25
    for key in sup_alerts["BAT_ONE_TIME"].values():
        u.dict_incr(hostsR,(key[0],key[2]),BAT_ONE_TIME_srv,"BAT_ONE_TIME")
        u.dict_incr(hostsR,(key[1],key[2]),BAT_ONE_TIME_cli,"BAT_ONE_TIME")
    
    DGA_DOMAINS_srv = 0
    DGA_DOMAINS_cli = 20
    for keys in sup_alerts["DGA_DOMAINS"].values():
        for key in keys:
            # u.dict_incr(hostsR,(key[0],key[2]),DGA_DOMAINS_srv)
            u.dict_incr(hostsR,(key[1],key[2]),DGA_DOMAINS_cli,"DGA_DOMAINS")
    
    # PROBING_VICTIMS_srv = 0
    PROBING_VICTIMS_cli = 15
    for attackers in sup_alerts["PROBING_VICTIMS"].values():
        # u.dict_incr(hostsR,(key[0],key[2]),PROBING_VICTIMS_srv)
        for key in attackers:
            u.dict_incr(hostsR,(key[1],key[2]),PROBING_VICTIMS_cli,"PROBING_VICTIMS")
    
    for grp_crit in sup_alerts["FLAT_GROUPINGS"]:
        HIGHER_ALERT_TYPES_rate = 20
        def get_rate(key,crit,rate):
            crit = map_name_to_id(crit)
            size = (stats := get_bkt_stats(crit))[key]["size"]
            bonus = (rate*0.10) * math.log(size)
            return rate + bonus


        def get_hat_rate(key,crit,rate):
            crit = map_name_to_id(crit)
            count = sup_alerts["FLAT_GROUPINGS"][grp_crit]["higher_alert_types"][key]
            bonus = (rate*0.10) * math.log(count)
            return rate + bonus

            
        for key in sup_alerts["FLAT_GROUPINGS"][grp_crit]["higher_alert_types"]:
            if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                u.dict_incr(hostsR,(key[0],key[2]),get_hat_rate(key,grp_crit,HIGHER_ALERT_TYPES_rate),"higher_alert_types")
                u.dict_incr(hostsR,(key[1],key[2]),get_hat_rate(key,grp_crit,HIGHER_ALERT_TYPES_rate),"higher_alert_types")
            else: # SRV or CLI tuple 
                u.dict_incr(hostsR,(key[0],key[1]),get_hat_rate(key,grp_crit,HIGHER_ALERT_TYPES_rate),"higher_alert_types")

        CS_PARADIGM_ODD_rate = 10
        for key in sup_alerts["FLAT_GROUPINGS"][grp_crit]["cs_paradigm_odd"]:
            if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                u.dict_incr(hostsR,(key[0],key[2]),get_rate(key,grp_crit,CS_PARADIGM_ODD_rate),"cs_paradigm_odd")
                u.dict_incr(hostsR,(key[1],key[2]),get_rate(key,grp_crit,CS_PARADIGM_ODD_rate),"cs_paradigm_odd")
            else: # SRV or CLI tuple 
                u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,CS_PARADIGM_ODD_rate),"cs_paradigm_odd")

        SIMULTANEOUS_rate = 40
        for key in sup_alerts["FLAT_GROUPINGS"][grp_crit]["simultaneous"]:
            if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                u.dict_incr(hostsR,(key[0],key[2]),get_rate(key,grp_crit,SIMULTANEOUS_rate),"simultaneous")
                u.dict_incr(hostsR,(key[1],key[2]),get_rate(key,grp_crit,SIMULTANEOUS_rate),"simultaneous")
            else: # SRV or CLI tuple 
                u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,SIMULTANEOUS_rate),"simultaneous")

        PERIODIC_rate = 20
        PERIODIC_bonus = 15
        def compute_periodic_rate (key, crit:str) -> float:
            stats = get_bkt_stats(map_name_to_id(crit))
            percentage = 1 - (stats[key]["tdiff_CV"]/PERIODIC_CV_THRESHOLD)
            bonus = PERIODIC_bonus * percentage
            return PERIODIC_rate + bonus

        for key in sup_alerts["FLAT_GROUPINGS"][grp_crit]["periodic"]:
            if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                u.dict_incr(hostsR,(key[0],key[2]),get_rate(key,grp_crit,compute_periodic_rate(key,grp_crit)),"periodic")
                u.dict_incr(hostsR,(key[1],key[2]),get_rate(key,grp_crit,compute_periodic_rate(key,grp_crit)),"periodic")
            else: # SRV or CLI tuple 
                u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,compute_periodic_rate(key,grp_crit)),"periodic")

        SIMILAR_PERIODICITY_rate = 10
        for key_list in sup_alerts["FLAT_GROUPINGS"][grp_crit]["similar_periodicity"].values():
            for key in key_list: 
                if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                    u.dict_incr(hostsR,(key[0],key[2]),get_rate(key,grp_crit,SIMILAR_PERIODICITY_rate),"similar_periodicity")
                    u.dict_incr(hostsR,(key[1],key[2]),get_rate(key,grp_crit,SIMILAR_PERIODICITY_rate),"similar_periodicity")
                else: # SRV or CLI tuple 
                    u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,SIMILAR_PERIODICITY_rate),"similar_periodicity")

        BAT_SAMEFILE_srv = 20
        BAT_SAMEFILE_cli = 20
        for key in sup_alerts["FLAT_GROUPINGS"][grp_crit]["bat_samefile"]:
            if (grp_crit == "SRVCLI"): # (srv,cli,vlan) tuple
                u.dict_incr(hostsR,(key[0],key[2]),get_rate(key,grp_crit,BAT_SAMEFILE_srv),"bat_samefile")
                u.dict_incr(hostsR,(key[1],key[2]),get_rate(key,grp_crit,BAT_SAMEFILE_cli),"bat_samefile")
            elif(grp_crit == "SRV"): # SRV 
                u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,BAT_SAMEFILE_srv),"bat_samefile")
            elif(grp_crit == "CLI"): # CLI 
                u.dict_incr(hostsR,(key[0],key[1]),get_rate(key,grp_crit,BAT_SAMEFILE_cli),"bat_samefile")

    
    SIZE_MAX_RATE = 60
    def get_size_rate(host):
        n = alerts_per_host[host][-1]
        return math.log(n,10) * (SIZE_MAX_RATE / math.log(max_n_alerts, 10))
    # size_outliers = get_hosts_size_outliers(u.detect_outliers_iqr_nonzero)
    # size_outliers = get_hosts_size_outliers(u.detect_outliers_exp_smooth)
    size_outliers = get_hosts_size_outliers(u.detect_outliers_holt_winters)
    # max_n_alerts is the maximum number of alerts per host in the size_outlier hosts
    max_n_alerts = max([0] + [alerts_per_host[k][-1] for k in size_outliers])
    for k in size_outliers:
        u.dict_incr(hostsR,k,get_size_rate(k),"N_alerts")
        # print(hostsR[k])

    SIZE_MAX_BONUS_RATE = 15
    def get_size_bonus_rate(host):
        if host in size_outliers:
            return 0
        n = alerts_per_host[host][-1]
        return math.log(n,10) * (SIZE_MAX_BONUS_RATE / math.log(max_n_alerts, 10))
    # max_n_alerts is the maximum number of alerts per host in the hosts which have computed a rating
    # in this time windows
    max_n_alerts = max([0] + [alerts_per_host[k][-1] for k in hostsR.keys()])
    for k in hostsR.keys():
        u.dict_incr(hostsR,k,get_size_bonus_rate(k),"N_alerts")

    return dict(sorted(hostsR.items(),key=lambda x: x[1]["total"],reverse=True))

def get_hosts_size_outliers(detect_outliers:callable):
    outliers = []
    # check number of observations in each time series
    n_time_windows = len(next(iter(alerts_per_host.values()))) if (len(alerts_per_host.values()) != 0) else 1
    # if the time series isn't long enough
    if (n_time_windows < 5):
        return []
    print("TIME_WINDOWS " + str(n_time_windows))
    for k in filter(lambda x: 
                    (v := alerts_per_host[x])[-1] != 0 and
                    len([i for i in v if i != 0]) > 3,
                    alerts_per_host.keys()):
        indexes = detect_outliers(alerts_per_host[k],5,threshold=3.5)
        # since this is called inside get_host_ratings and it
        # refers only to the last time window
        # return only if the outlier is the last index  
        if any(i+1 == n_time_windows for i in indexes):
            outliers.append(k)
            print(str(k) + " : " + str(alerts_per_host[k]))
    
    return outliers

def get_hosts_outliers(hostsR:dict):
    ratings = list(hostsR.values())
    q1 = np.quantile(ratings, .25)
    q3 = np.quantile(ratings, .75)
    iqr = q3-q1 # interquartile range
    ub = q3 + 1 * iqr # upper bound

    outliers = u.str_key({k:round(v,2) for k,v in hostsR.items() if v >= ub})
    hosts = list(outliers.keys())
    # plt.figure(figsize=(15,5))
    # plt.bar(range(len(hosts)),outliers.values(),0.7, color = 'g')
    # plt.xticks(range(len(hosts)), hosts, rotation=90)
    # plt.subplots_adjust(bottom=0.45)
    # plt.show()
    return outliers

def get_sup_level_alerts() -> dict:
    update_bkts_stats()
    global sup_level_alerts
    sup_level_alerts = {"FLAT_GROUPINGS": {},
                        "BAT_ONE_TIME" : {},
                        "BAT_SERVER_NAMES": {},
                        "DGA_DOMAINS": {},
                        "PROBING_VICTIMS": {},
                        "TLS_SELFSIGNERS_JA3" : {}}
    for grp_crit in [GRP_SRV, GRP_CLI, GRP_SRVCLI]:
        sup_level_alerts["FLAT_GROUPINGS"][map_id_to_name(grp_crit)] = {
            "higher_alert_types" : get_higher_alert_types(grp_crit),
            # "tls_critical" : get_tls_critical(grp_crit),
            "cs_paradigm_odd" : get_cs_paradigm_odd(grp_crit),
            # "blk_peer" : get_blk_peer(grp_crit),
            "simultaneous" : get_simultaneous(grp_crit),
            "periodic" : get_periodic(grp_crit),
            "similar_periodicity" : get_similar_periodicity(grp_crit),
            "bat_samefile" : get_bat_samefile(grp_crit),
        }
    sup_level_alerts["BAT_ONE_TIME"] = sav["binary_application_transfer"]
    sup_level_alerts["BAT_SERVER_NAMES"] = bat_server
    sup_level_alerts["DGA_DOMAINS"] = get_dga_sus_domains()
    sup_level_alerts["PROBING_VICTIMS"] = get_unidir_probed()
    sup_level_alerts["TLS_SELFSIGNERS_JA3"] = snd_grp["tls_certificate_selfsigned"]
    return sup_level_alerts


def unidirectional_handler(a):
    if (a["alert_id"] != 26): # 26 : Unidirectional traffic
        return False
    
    # Consider only when the traffic goes from client to server
    o = json.loads(a["json"])
    try:
        flow_risk = o["alert_generation"]["flow_risk_info"]
        flow_risk = json.loads(flow_risk)
        if (flow_risk["46"] != "No server to client traffic"):
            return False
    except KeyError as e:
        return False
    
    # Consider only when proto is TCP or is UDP the application
    # Requires at least one response from the server
    if not (a["proto"] == 6 or (a["proto"] == 17
                                and any("".join(o["proto"].keys()).find(app) != -1 for app in BIDIR_APP))):
        return False

    # Consider only when the server possible victim is a private host
    # if not ip_address(a["srv_ip"]).is_private:
    #     return False

    # We are sure the alert indicates
    # Unidir traffic from client to server
    k = u.get_id_vlan(a,GRP_SRV)
    cli_id = u.get_id(a,GRP_CLI)
    srv_port = a["srv_port"]
    unidir[k] = [(cli_id,srv_port)] if (k not in unidir) else unidir[k] + [(cli_id,srv_port)]

    return True

# These get useful when detecting "true" DGAs
def long_lived_flow_handler(a):
    if (a["alert_id"] != 11): # 11 : Long-lived Flow
        return False
    
    k = u.get_id_vlan(a,GRP_CLI)

    # longlived[k] = a["tstamp"]
    # "tstamp" is not included in this case, since, for some odd reason,
    # it cannot be put in the select statement of the query performed for
    # this type of alert
    longlived[k] = u.time_lower.strftime("%d-%m-%Y %H:%M:%S")
    return True

def low_goodput_handler(a):
    if (a["alert_id"] != 12): # 12 : Low Goodput Ratio
        return False
    
    k = u.get_id_vlan(a,GRP_CLI)

    # lowgoodput[k] = a["tstamp"]
    # "tstamp" is not included in this case, since, for some odd reason,
    # it cannot be put in the select statement of the query performed for
    # this type of alert
    lowgoodput[k] = u.time_lower.strftime("%d-%m-%Y %H:%M:%S")
    return True

def get_unidir_probed():
    probed = {}
    for srv,t in unidir.items():
        # If a server is a victim of probing, one or more client will be trying to 
        # unidirectionally communicate with it on many different ports
        if (len(unidir[srv]) > MIN_PROBING_RELEVANT_SIZE and
            is_server(srv[1]) and
            (s := u.shannon_entropy(list(map(lambda x: x[1],unidir[srv])))) > PROBING_ENTROPY_THRESH):
            probed[srv] = set(map(lambda x: x[0],unidir[srv]))
    return probed

def get_dga_sus_domains():
    # Each v is a tuple (srv,cli,vlan)
    # But we want to detect only the clients' behavior,
    # to check whether they are associated with
    # longlived flows or lowgoodput ratio alerts,
    # Which might mean they are actual DGAs

    # Create a list using only keys, and get only (cli,vlan) discarding srv
    toret = {k: list(set(map(lambda x: x[1:],v.keys())))
             for k, v in dga_suspicious_domains.items()}
    # For each client (potential attacker) perform a request 
    # to get its associated longlived or lowgoodput alerts
    for k, v in toret.items():
        req_str_hosts = u.request_builder_srvcli(v)
        # 11 -> Longlived flows | 12 -> Lowgoodput
        # Request first only Longlived flows
        req_str = "(alert_id=11) AND (" + req_str_hosts + ")"
        # 5 hit per key are sufficient for our purposes
        # Note that if there are, for example, four keys, thus maxhits = 4*5 = 20
        # We might get 20 hits related to the same key.
        # Not a big deal.
        new_alerts = u.make_request(req_str,5 * len(v))
        
        # Now request lowgoodput flows
        req_str = "(alert_id=12) AND (" + req_str_hosts + ")"
        new_alerts += u.make_request(req_str, 5 * len(v))
        for a in new_alerts:
            # since 'alert_id = 11 OR alert_id = 12'
            # each alert will be handled properly and put in longlived or lowgoodput
            new_alert(a)
        
    return {k: x for k, v in dga_suspicious_domains.items()
            # We want to consider only DGAs in which the attacker is associated with long-lived low-goodput flows
            if len((x := list(filter(lambda x: (x[1],x[2]) in longlived and (x[1],x[2]) in lowgoodput, v.keys())))) >= 1}

# Stats calculation
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
            # TODO ipv6
            # print(x)
            return 0
    srv_ip_toN = list(map(ip_to_numeric,map(lambda x: x["srv_ip"],s)))
    cli_ip_toN = list(map(ip_to_numeric,map(lambda x: x["cli_ip"],s)))
    
    
    d["srv_ip_S"] = u.shannon_entropy(srv_ip_toN)
    d["cli_ip_S"] = u.shannon_entropy(cli_ip_toN)
    d["srv_port_S"] = u.shannon_entropy(list(map(lambda x: x["srv_port"],s)))
    d["cli_port_S"] = u.shannon_entropy(list(map(lambda x: x["cli_port"],s)))
    
    d["srv_port_count"] = len(set(map(lambda x: x["srv_port"],s)))
    d["cli_port_count"] = len(set(map(lambda x: x["cli_port"],s)))


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
    d["bat_same_file"] = ""

    if (s[0]["alert_id"] == 29):
        # get the first path
        first_path = (u.get_BAT_path_server(s[0]["json"]))[0]
        
        paths = map(lambda x: u.get_BAT_path_server(x["json"])[0],s)
        if first_path != "":
            # Check if the file transferred is always the same
            for p in paths:
                if p != first_path:
                    # If not, exit
                    first_path = ""
                    break
        d["bat_same_file"] = first_path

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
        (1 if (d["bat_same_file"] != "") else 0) * 15
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
    relevant_keys = filter(lambda x: x and len(x) >= 1 and is_relevant(x),bkt.keys())
    
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
        if (GRP_CRIT != GRP_CLI 
            and x["alert_name"] not in excludes
            and x["srv_port_S"] >= SRV_ODD_PORT_S_TH
            and x["srv_port_count"] >= SRV_ODD_PORT_COUNT_TH
            and is_server(vlan_id)):
            return "odd_server"
        # A client is odd if uses the SAME port with MANY servers
        if (GRP_CRIT != GRP_SRV 
            and x["alert_name"] not in excludes
            and x["cli_port_S"] <= CLI_ODD_PORT_S_TH
            # and x["cli_port_count"] <= CSODD_PORT_COUNT_TH
            and x["srv_ip_S"] >= CSODD_IP_S_TH
            and is_client(vlan_id)):
            return "odd_client"
        return None
    
    # k = ("ip","vlan","alert_id") we must exclude "alert_id" 
    tmp= {k: oddity for (k,v) in bkt_s.items() if (oddity := is_odd(v,k[-1:]))}
    # hosts = {}
    # for k,v in tmp.items():
    #     hosts[(k[0],k[1])] = v
    return get_hosts_noalertid(tmp)

# @returns groups which are strongly periodic (i.e. tdiff_CV < 0.85)
def get_simultaneous(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)
    return {k: v["tdiff_avg"] + " " + v["alert_name"] for (k,v) in bkt_s.items()
            # TODO v["tdiff_CV"] == 0 ok?
            if ((
                # v["tdiff_CV"] == 0 or
                (v["tdiff_avg"] == "0:00:00" and v["tdiff_CV"] <= 0.5))
                and v["size"] >= MIN_PERIODIC_SIZE)}


def get_periodic(GRP_CRIT:int):
    bkt_s = get_bkt_stats(GRP_CRIT)

    # Note: exclude not periodic relevant alerts
    excludes = TLS_ALERTS + ["remote_to_local_insecure_proto","ndpi_http_suspicious_user_agent"]

    # TODO return also CV?  i.e. (v["tdiff_avg"],v["tdiff_CV"],v["size"]))
    return {k: v["tdiff_avg"] + " " + v["alert_name"] for (k, v) in bkt_s.items()
            if v["tdiff_CV"] < PERIODIC_CV_THRESHOLD
            # and v["tdiff_CV"] > 0.0
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
                      if (v["tdiff_CV"] < PERIODIC_SIMILAR_CV_THRESHOLD
                      and v["tdiff_CV"] > 0.0
                      and v["tdiff_avg"] != "0:00:00"
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
    return {k: v["bat_same_file"] for (k,v) in bkt_s.items() if v["bat_same_file"] != ""}

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

def is_server(vlan_id:int):
    return not CONTEXT_INFO or vlan_id in ctx.VLAN_SERVER
def is_client(vlan_id:int):
    return not CONTEXT_INFO or vlan_id in ctx.VLAN_CLIENT

# dict_init_alertnames()