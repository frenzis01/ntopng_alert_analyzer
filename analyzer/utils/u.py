import json 
import datetime as dt

from scipy.stats import entropy
from collections import Counter

import numpy as np
import statistics

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
   except KeyError:
      return ("","")
   try:
      server = o["last_server"]
   except KeyError:
      server = ""
   return (path,server)

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

def addremove_to_singleton(a: dict, v, value):
   if (v in a.keys()):
      a.pop(v,None)
   else:
      a[v] = value

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

def dict_incr(d:dict,key:str,value:int,feature:str):
   if key not in d:
      d[key] = {"total" : 0}
   if feature not in d[key]:
      d[key][feature] = 0
   
   d[key][feature] += value
   d[key]["total"] += value

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

# @param hosts_ts is a dict made as {host1 : [rating0, rating30min, rating60min, ...], ...}
# @param hosts_r is a dict containting the update, { host1: current_rating, ...}
def new_hostsR_handler(hosts_ts:dict,host_r:dict):
   # how many iterations have we already performed?
   len_TimeWindow = len(list(hosts_ts.values())[0]) if (len(hosts_ts)) else 0
   for k,v in host_r.items():
      # if host was not previously observed
      if k not in hosts_ts:
         # fill with zeros
         # hosts_ts[k] = [0] * len_TimeWindow
         # fill with the first value known
         hosts_ts[k] = [0] * (len_TimeWindow-1)
      hosts_ts[k] += [v["total"]]
   
   # if no update in host_r for some keys,
   # then add zero
   for k in hosts_ts.keys():
      if k not in host_r:
         # no update in host_r
         # add zero
         hosts_ts[k] += [0]

def hostsR_outlier_wma(hosts_ts:dict):
   outlier_hosts = {}
   for host,ratings in hosts_ts.items():
      # print("host and rating" + str((host,ratings) ))
      # hoti = host_outlier_time_indices
      hoti = detect_outliers_wma(ratings,lower_bound=40)
      if hoti:
         outlier_hosts[host] = [hoti, list(map(lambda x: round(x,2),ratings))]   
   return outlier_hosts

def hostsR_outlier_mad(hosts_ts:dict):
   outlier_hosts = {}
   for host,ratings in hosts_ts.items():
      # print("host and rating" + str((host,ratings) ))
      # hoti = host_outlier_time_indices
      hoti = detect_outliers_mad_modified(ratings)
      if hoti:
         outlier_hosts[host] = [hoti, list(map(lambda x: round(x,2),ratings))]   
      
   return outlier_hosts


def detect_outliers_iqr(data, threshold=1.5):
    """
    This function detects outliers in a list of numbers using the interquartile range (IQR).
   
    data: list of numbers
    threshold: number of IQRs from the median to use as a threshold for outlier detection
   
    returns: list of outlier indices
    """
    
    # Convert the data to a numpy array
    data = np.array(data)
    
    # Calculate the quartiles
    q1, q3 = np.percentile(data, [25, 75])
    
    # Calculate the IQR
    iqr = q3 - q1
    
    # Calculate the lower and upper bounds
    lower_bound = q1 - threshold * iqr
    upper_bound = q3 + threshold * iqr
    
    # Find the outliers
    outliers = np.where((data < lower_bound) | (data > upper_bound))[0]
    
    return outliers.tolist()

def detect_outliers_wma(values:list, lower_bound:int, window_size=5, sigma=3):
   """
   This function detects outliers in a list of numbers using the weighted moving average WMA.
   
   data: list of numbers
   window_size: size of the window used for the moving average
   sigma: number of standard deviations from the moving average to use as a threshold for outlier detection
   lower_bound: values below this threshold will be excluded from outlier detection
   
   returns: list of outlier indices
   """
   data = list(values)

   leading_zeros = 0
   while len(data) > 0 and data[0] == 0:
      data.pop(0)
      leading_zeros += 1
   
   
   # If data has less than window_size elements, return an empty list
   if len(data) < window_size:
       return []
   
   # Check if the first n elements of data are equal and the remaining elements are all 0
   n = window_size - 1
   if len(data) > n and all(x == data[0] for x in data[:n]) and all(x == 0 for x in data[n:]):
       return []
   
   # Calculate the weighted moving average
   weights = np.arange(1, window_size+1)
   wma = np.convolve(data, weights, mode='valid') / weights.sum()
   
   # Calculate the deviation from the weighted moving average
   deviation = np.abs(data[window_size-1:] - wma)
   
   # Calculate the standard deviation of the deviation
   std_dev = np.std(deviation)
   
   # Check that the standard deviation is not zero
   if std_dev == 0:
       return []
   
   # Calculate the threshold for outlier detection
   threshold = sigma * std_dev
   
   # Find the outliers
   outliers = np.where(deviation > threshold)[0] + window_size-1
   # outliers.tolist()
   
   # If threshold is None
   # Exclude values below threshold from data
   if lower_bound is not None:
      outliers = [x for x in outliers if data[x] >= lower_bound]

   # Check if last element is an actual outlier or not   
   if len(outliers) and (data[-1] < threshold or abs(data[-1] - wma[-1]) <= threshold):
      outliers.pop()


   return list(map(lambda x: x + leading_zeros,outliers))


def detect_outliers_mad_modified(data, threshold=3.5):
    """
    This function detects outliers in a list of numbers using the modified z-score method with MAD.
    It excludes the first elements of data that are equal to 0 and does not consider the last element as an outlier.

    data: list of numbers
    threshold: modified z-score threshold for outlier detection

    returns: list of outlier indices
    """
    # Exclude first elements equal to 0
    first_non_zero_idx = next((i for i, x in enumerate(data) if x != 0), len(data))
    data = data[first_non_zero_idx:]

    # Calculate median and MAD
    median = statistics.median(data)
    deviations = [abs(x - median) for x in data]
    MAD = statistics.median(deviations)

    # Calculate modified z-score
    if MAD == 0:
        modified_z_scores = [0] * len(data)
    else:
        modified_z_scores = [0.6745 * (x - median) / MAD for x in data]

    # Find outliers
    outliers = [i + first_non_zero_idx for i, x in enumerate(modified_z_scores) if abs(x) > threshold and i != len(modified_z_scores)-1]

    return outliers

# New alert handling UTILITIES 
def a_convert_dtypes(a):

    # format 2023-01-13 17:37:31
    a["tstamp"] = dt.datetime.strptime(a["tstamp"], "%Y-%m-%d %H:%M:%S")
    a["tstamp_end"] = dt.datetime.strptime(a["tstamp_end"], "%Y-%m-%d %H:%M:%S")

    a["srv_port"] = int(a["srv_port"])
    a["severity"] = int(a["severity"])
    a["cli2srv_bytes"] = int(a["cli2srv_bytes"])
    a["rowid"] = int(a["rowid"])
    a["ip_version"] = int(a["ip_version"])
    a["srv2cli_pkts"] = int(a["srv2cli_pkts"])
    a["interface_id"] = int(a["interface_id"])
    a["cli2srv_pkts"] = int(a["cli2srv_pkts"])
    a["score"] = int(a["score"])
    a["srv2cli_bytes"] = int(a["srv2cli_bytes"])
    a["cli_port"] = int(a["cli_port"])
    a["l7_proto"] = int(a["l7_proto"])
    a["proto"] = int(a["proto"])

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
