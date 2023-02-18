import json 
import datetime as dt

from scipy.stats import entropy
from collections import Counter

from ipaddress import ip_address,IPv4Address

my_historical = iface_id = time_lower = time_upper = None

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
    return {str(k): (str_val(v) if (type(v) is list) else
                        (str_key(v) if (type(v) is dict) else
                        (list(v) if (type(v) is set) else
                        (str(v) if (type(v) is tuple)
                           else v))))
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


def request_builder_srvcli(keys: list):
   if (len(keys) == 0):
      return ""

   # Each k is a client name or IP
   k = keys[0]
   cli_condition = str(k[0])
   try:
      a = ip_address(k[0]) # if valid IP address, then use 'cli_ip' prefix
      # if (type(a) is IPv4Address):
      #    cli_condition = "IPV4_SRC_ADDR=(\"" + cli_condition + "\")"
      # else:
      #    cli_condition = "IPV6_SRC_ADDR=(\"" + cli_condition + "\")"
      cli_condition = "cli_ip='" + cli_condition + "'"

   except ValueError:      # if not, use 'cli_name' prefix
      cli_condition = "cli_name='" + cli_condition + "'"

   return ("(" + cli_condition + " AND vlan_id=" + str(k[1]) + ")"
           + (" OR " + request_builder_srvcli(keys[1:]) if len(keys[1:]) else ""))

def set_historical(h, iface, t_lower, t_upper):
   global my_historical,iface_id, time_lower, time_upper
   my_historical = h
   iface_id = iface
   time_lower = t_lower
   time_upper = t_upper

def make_request(r: str, maxhits: int):
   if my_historical:
      return my_historical.get_flow_alerts(time_lower.strftime('%s'), time_upper.strftime(
        '%s'), "distinct alert_id, vlan_id, cli_name, cli_ip", r, maxhits,"", "")
   return None


def get_id(a,k:int):
   if(k not in range(3)):
      raise Exception("Invalid id: 0,1,2 (srv,cli,srvcli) available only")
   srv_id = a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"]
   cli_id = a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"]
      
   if (k == 0):
      return srv_id
   if (k == 1):
      return cli_id
   if (k == 2):
      return (srv_id,cli_id)

def get_id_vlan(a,k:int) -> tuple:
   if(k not in range(3)):
      raise Exception("Invalid id: 0,1,2 (srv,cli,srvcli) available only")
   
   # srv or cli might be missing depending on 'a' value,
   # (e.g. alert_id=11|12 => no srv fields) 
   # so we must assign srv_id|cli_id only when strictly 
   # necessary, to avoid KeyError  
   if (k == 0):
      srv_id = a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"]
      return (srv_id,a["vlan_id"])
   if (k == 1):
      cli_id = a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"]
      return (cli_id,a["vlan_id"])
   if (k == 2):
      srv_id = a["srv_name"] if (a["srv_name"] != "") else a["srv_ip"]
      cli_id = a["cli_name"] if (a["cli_name"] != "") else a["cli_ip"]
      return (srv_id,cli_id,a["vlan_id"])

# @returns the longest sequence of subsequent common substrings
# between l1 and l2
def find_longest_common_subsequent_substrs(l1:list,l2:list):
   # @returns the first sequence of subsequent common substrings
   # and the index of the last matching substring of the longer list
   def find_first_common_subsequent_substrs(l1:list,l2:list):
      # a is the shortest list, b the longest
      a = l1 if (len(l1) <= len(l2)) else l2
      b = l2 if (len(l1) <= len(l2)) else l1

      # res holds the FIRST sequence of substrings 
      res = []
      for i in range(len(a)):
         for j in range(len(b)):
            # found some matches, but no more
            # NB 'j-1'
            if(len(res) and (a[i] != b[j])):
               return res,j-1


            # found another subsequent match
            if (a[i] == b[j]):
               # add to resulting list
               res.append(b[j])

               # if there are no more elements in the shortest
               # list then exit
               if i + 1 == len(a):
                   return res,j
               # else move onto the next element 
               i += 1
      return res,j
   
   # a is the shortest list, b the longest
   a = l1 if (len(l1) <= len(l2)) else l2
   b = l2 if (len(l1) <= len(l2)) else l1

   res = []
   for i in range(len(b)):
      tmp,index = find_first_common_subsequent_substrs(a,b[i:])
      # if res is longer than half of b
      # we are sure there ain't longer sequences
      if (len(tmp) > len(b)/2):
         return tmp
      
      # update res
      res = tmp if (len(tmp) > len(res)) else res

      index += 1 # consider element after the last matching
      # if there isn't a chance to find a longer matching sequence
      # exit 
      if (len(b) - index < len(res)):
         return res
      # else try to find a longer matching sequence
      i = index
   return res


def add_to_domain_dict(d:dict,name:str,key):
   best_match = [name]
   best_match_name = name
   name_tokens = name.split(".")
   for dga_name in (d.keys()):
      tmp = find_longest_common_subsequent_substrs(name_tokens,dga_name.split("."))
      best_match = tmp if (len(tmp) > len(best_match)) else best_match
      best_match_name = dga_name if (len(tmp) > len(best_match)) else best_match_name
   
   new_name = ".".join(best_match)
   d[new_name] = d.pop(best_match_name,{})
   d[new_name][key] = 0
   return new_name

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