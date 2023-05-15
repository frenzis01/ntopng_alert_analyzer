#!/usr/bin/env python3

# ntopng related imports
import os
import sys
import getopt

from ntopng.ntopng import Ntopng
from ntopng.historical import Historical

# My imports
import datetime
import json
import myenv_ as myenv
import pickle

from analyzer.utils.u import *
from analyzer.utils.c import FEATURES
from analyzer.alertdb import *
from analyzer.utils.u import set_historical

FILE_INPUT = False
FILE_INPUT = True

ALERTS_INPUT = False
ALERTS_INPUT = True

ITERATIONS = 24

# Defaults
username = myenv.myusr
password = myenv.mykey
ntopng_url = myenv.myurl
iface_id = myenv.myiface_id
auth_token = None
enable_debug = False
host_ip = "192.168.1.1"  # useful only for -H option

def usage():
    print("test.py [-h] [-d] [-u <username>] [-p <passwrd>] [-n <ntopng_url>]")
    print("         [-i <iface id>] [-t <auth token>]")
    print("")
    print("Example: ./test.py -t ce0e284c774fac5a3e981152d325cfae -i 4")
    print("         ./test.py -u ntop -p mypassword -i 4")
    sys.exit(0)

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

if not FILE_INPUT:
    try:
        my_ntopng = Ntopng(username, password, auth_token, ntopng_url)

        if (enable_debug):
            my_ntopng.enable_debug()
    except ValueError as e:
        print(e)
        os._exit(-1)

hosts_ts = {}
hosts_ratings = []
all_raw_alerts = []
all_time_dict = []


t_zero_end = datetime.datetime.now() - datetime.timedelta(minutes=0*myenv.WINDOW_SIZE_MINUTES)
t_zero_start = t_zero_end - datetime.timedelta(minutes=ITERATIONS*myenv.WINDOW_SIZE_MINUTES)

if not FILE_INPUT and not ALERTS_INPUT:

    try:
        my_historical = Historical(my_ntopng,iface_id)
        set_historical(my_historical,iface_id,t_zero_start,t_zero_end)
        t_start = t_zero_start
        for i in range(ITERATIONS):
            t_end = t_start + datetime.timedelta(minutes=myenv.WINDOW_SIZE_MINUTES)
            time_dict = {
                "start" : t_start.strftime("%Y/%d/%m %H:%M:%S"),
                "end" : t_end.strftime("%Y/%d/%m %H:%M:%S")
            }
            print(json.dumps(time_dict,indent=2))

            all_time_dict += [time_dict]
            raw_alerts = my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
                '%s'), "*", "severity >= 5", 200000, "", "tstamp")

            raw_alerts += my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
                '%s'), "*", "alert_id = 26", 2000000, "", "")

            for a in raw_alerts:
                remove_unwanted_fields(a)
            all_raw_alerts += [raw_alerts]

            t_start = t_end

    except ValueError as e:
        print(e)
        os._exit(-1)

    f = open("mock_time","wb")
    pickle.dump(all_time_dict,f)
    f.close()

all_sup_level_alerts = []

all_bkt_stats = []

if not FILE_INPUT:

    if not ALERTS_INPUT:
        with open("all_alerts","wb") as f:
            pickle.dump(all_raw_alerts,f)


    if ALERTS_INPUT:
        with open("all_alerts","rb") as f:
            all_raw_alerts = pickle.load(f)
        print("-----------Using Alerts from File-----------")
        my_historical = Historical(my_ntopng,iface_id)
        with open("mock_time","rb") as f:
            all_time_dict = pickle.load(f)

    def to_dt(s:str):
        return datetime.datetime.strptime(s,"%Y/%d/%m %H:%M:%S")
    t_zero_end = to_dt(all_time_dict[ITERATIONS-1]["end"])
    t_zero_start = to_dt(all_time_dict[0]["start"])
    set_historical(my_historical,iface_id,t_zero_start,t_zero_end)

    for i,raw_alerts in enumerate(all_raw_alerts):
        t_start = to_dt(all_time_dict[i]["start"])
        print(json.dumps(all_time_dict[i]["start"],indent=1))
        

        init()
        for a in raw_alerts:
            new_alert(a)

        update_bkts_stats()
        tmp_bkt_stats = (get_bkt_stats(GRP_SRV),get_bkt_stats(GRP_CLI),get_bkt_stats(GRP_SRVCLI))
        all_bkt_stats += [tmp_bkt_stats]

        sup_level_alerts = get_sup_level_alerts(all_time_dict[i])
        sla = copy.deepcopy(sup_level_alerts)
        hostsR = get_host_ratings(sup_level_alerts)
        
        if ONLY_MATCHING_HOSTS:
            hostsR = {k:v for k,v in hostsR.items() if subnet_check(k[0],ctx.SUBNETS_REGEX)}

        all_sup_level_alerts += [sla]
        
        hosts_ratings += [hostsR]
        new_hostsR_handler(hosts_ts,hostsR)
    

    with open("mock_alerts_per_host","wb") as f:
        pickle.dump(alerts_per_host,f)
    
    with open("mock_stats","wb") as f:
        pickle.dump(all_bkt_stats,f)

    f = open("mock_hostsR", "wb")
    pickle.dump(hosts_ratings,f)
    f.close()

    f = open("mock_sup_level_alerts", "wb")
    pickle.dump(all_sup_level_alerts,f)
    f.close()

    with open("mock_tmp.json","w") as f:
        f.write(json.dumps(list(map(str_key,all_sup_level_alerts)),indent=2))


if FILE_INPUT:

    with open("mock_alerts_per_host","rb") as f:
        alerts_per_host = (pickle.load(f))

    with open("mock_time","rb") as f:
        all_time_dict = pickle.load(f)

    f = open("mock_sup_level_alerts", "rb")
    all_sup_level_alerts = pickle.load(f)
    f.close()

    f = open("mock_stats","rb")
    all_bkt_stats = pickle.load(f)
    f.close()
    for i,sup_level_alerts in enumerate(all_sup_level_alerts):
        set_bkt_stats(all_bkt_stats[i])
        # TODO
        set_alerts_per_host(alerts_per_host,i+1)
        set_blk_peers(sup_level_alerts["BLK_PEER"])
        set_remote_access(sup_level_alerts["REMOTE_ACCESS"])

        hostsR = {k:v for k,v in get_host_ratings(sup_level_alerts).items()}

        if ONLY_MATCHING_HOSTS:
            hostsR = {k:v for k,v in get_host_ratings(sup_level_alerts).items() if subnet_check(k[0],ctx.SUBNETS_REGEX)}

        hosts_ratings += [hostsR]
        new_hostsR_handler(hosts_ts,hostsR)

    with open("mock_tmp.json","w") as f:
        f.write(json.dumps(list(map(str_key,all_sup_level_alerts)),indent=2))
    

hosts_sizes = alerts_per_host


if ONLY_MATCHING_HOSTS:
    hosts_ts = {k:v for k,v in hosts_ts.items() if subnet_check(k[0],ctx.SUBNETS_REGEX)}

with open("mock_hosts_ts.json", "w") as f:
    f.write(json.dumps(str_key(hosts_ts),indent=2))

print("Outliers: " + json.dumps(str_key(outliers := hostsR_outlier(hosts_ts,detect_outliers_wma)),indent=2))
plot_outliers(map_index_to_time(get_outliers_features(outliers,hosts_ratings),all_time_dict),FEATURES,ITERATIONS,hosts_ratings,hosts_sizes, all_time_dict, "H - Weighted Moving Average")

print("Outliers: " + json.dumps(str_key(outliers := hostsR_outlier(hosts_ts,detect_outliers_exp_smooth)),indent=2))
plot_outliers(map_index_to_time(get_outliers_features(outliers,hosts_ratings),all_time_dict),FEATURES,ITERATIONS,hosts_ratings,hosts_sizes, all_time_dict, "H - Single Exp Smoothing")

print("Outliers: " + json.dumps(str_key(outliers := hostsR_outlier(hosts_ts,detect_outliers_holt_winters)),indent=2))
plot_outliers(map_index_to_time(get_outliers_features(outliers,hosts_ratings),all_time_dict),FEATURES,ITERATIONS,hosts_ratings,hosts_sizes, all_time_dict, "H - Holt Winters")


# TODO Doesn't change anything from 'nonzero' or not, because hosts_ratings items are sorted on the score,
# so 0 ratings are at the begininning 
print("Outliers: " + json.dumps(str_key(outliers := window_rating_outlier(hosts_ratings,detect_outliers_iqr_nonzero)),indent=2))
plot_outliers(map_index_to_time(get_outliers_features(outliers,hosts_ratings),all_time_dict),FEATURES,ITERATIONS,hosts_ratings,hosts_sizes, all_time_dict, "Time Windows - IQR")

plt.show()