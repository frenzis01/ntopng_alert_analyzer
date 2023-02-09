import json 
import datetime as dt
def parse_keys_from_path(p):
   # This is a path example
   # "root['sup_level_alerts']['SRV']['periodic']['('255.255.255.255', 1, 1)']"
   p = p.removeprefix("root")
   # The first token is empty, so we remove it using [1:]
   return (list(map(lambda x: x.removesuffix("]").removeprefix("'").removesuffix("'"), p.split("["))))[1:]

def get_value_from_keys(d, keys: list):
   if type(d) is not dict:
      return d
   if (len(keys) == 0):
      return d
   key = keys.pop(0)
   return get_value_from_keys(d[key],keys)


def is_server(vlan_id:int):
   return vlan_id in [2,14]

def is_client(vlan_id:int):
   return vlan_id in [46,3]


def low_level_info(alert):
   is_server(alert) and alert["alert_name"] in ["tls_certificate_selfsigned",
                           "ndpi_suspicious_dga_domain",
                           "ndpi_ssh_obsolete_client",
                           "ndpi_smb_insecure_version",
                           "data_exfiltration"]
                           
# Other utilities
def get_BAT_path_server(x):
    o = json.loads(x)
    try:
        # add bat_paths
        path = o["last_url"]
        server = o["last_server"]
        return (path,server)
    except KeyError:
        return ("","")

# Needed because json.dumps doesn't accept tuples as keys

def str_key(d: dict):
    return {str(k): (str_val(v) if (type(v) is list)
                     else (
                        str_key(v) if (type(v) is dict) else
                        (str(v) if (type(v) is tuple)
                           else v)))
            for (k, v) in d.items()}

def str_val(d:list):
    return list(map(str,d))

def addremove_to_singleton(a: dict, v):
    if (v in a):
        a.pop(v,None)
        return
    # else
    a[v] = 1

def add_to_dict_dict_counter(s:dict,k,v):
   if (k not in s):
      s[k] = {v : 1}
   else:
      if (v not in s[k]):
         s[k][v] = 1
      else:
         s[k][v] += 1

def str_to_timedelta(s: str) -> dt.timedelta:
    d = dt.datetime.strptime(s, "%H:%M:%S")
    total_sec = d.hour*3600 + d.minute*60 + d.second  # total seconds calculation
    return dt.timedelta(seconds=total_sec)

