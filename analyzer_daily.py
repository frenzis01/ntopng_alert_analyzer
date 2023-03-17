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


from analyzer.utils.u import new_hostsR_handler
from analyzer.utils.u import hostsR_outlier
from analyzer.utils.u import str_key

FILE_INPUT = True

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
if not FILE_INPUT:
    try:
        my_historical = Historical(my_ntopng,iface_id)
        t_end = datetime.datetime.now() - datetime.timedelta(minutes=0*myenv.WINDOW_SIZE_MINUTES)
        for i in range(6):
            t_start = t_end - datetime.timedelta(minutes=(i+1) * myenv.WINDOW_SIZE_MINUTES)
            time_dict = {
                "start" : t_start.strftime("%d/%m/%Y %H:%M:%S"),
                "end" : t_end.strftime("%d/%m/%Y %H:%M:%S")
            }
            from analyzer.utils.u import set_historical
            set_historical(my_historical,iface_id,t_start,t_end)
            raw_alerts = my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
                '%s'), "*", "severity >= 5 AND NOT alert_id = 91", 200000, "", "tstamp")

            raw_alerts += my_historical.get_flow_alerts(t_start.strftime('%s'), t_end.strftime(
                '%s'), "*", "alert_id = 26", 2000000, "", "")

            all_raw_alerts += [raw_alerts]

            # from analyzer.alertdb import *
            # for a in raw_alerts:
            #     new_alert(a)



            # sup_level_alerts = get_sup_level_alerts()
            # hostsR = get_host_ratings(sup_level_alerts)

            # hosts_ratings += [hostsR]

            # new_hostsR_handler(hosts_ts,hostsR)
            # print("HOSTS_TS: " + str(str_key(hosts_ts)))


            # print(json.dumps({"time" : time_dict} | str_key(get_hosts_outliers(hostsR)),indent=2))
            t_end = t_start

    except ValueError as e:
        print(e)
        os._exit(-1)

    f = open("alerts.json","w")
    f.write(str(all_raw_alerts))
    f.close()

    from analyzer.alertdb import *
    for raw_alerts in all_raw_alerts:
        init()
        for a in raw_alerts:
            new_alert(a)

        sup_level_alerts = get_sup_level_alerts()
        hostsR = get_host_ratings(sup_level_alerts)
        # print(hostsR)

        hosts_ratings += [hostsR]
        new_hostsR_handler(hosts_ts,hostsR)

    f = open("hostsR.json", "w")
    f.write(str(hosts_ratings))
    f.close()

if FILE_INPUT:
    f = open("hostsR.json", "r")
    hosts_ratings = json.loads(f.read())
    for hostsR in hosts_ratings:
        new_hostsR_handler(hosts_ts,hostsR)

# print(hosts_ts)
print(json.dumps("Outliers: " + str(str_key(hostsR_outlier(hosts_ts))),indent=2))
