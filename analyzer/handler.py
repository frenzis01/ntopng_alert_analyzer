import json
import pandas as pd
from analyzer.alertdb import *

bkt_srv = []
bkt_cli = []
bkt_srvcli = []

def alert_handler(a):
   srv_ip = a["srv_ip"]
   # print(a["srv_ip"])
   # print(a["cli_ip"])
   # if srv_ip not in bkt_srv:
   # bkt_srv[srv_ip] += a

   new_alert(a)
