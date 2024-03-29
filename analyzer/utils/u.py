import json 
import datetime as dt

from scipy.stats import entropy
from collections import Counter

import numpy as np
import statistics
import re
from ast import literal_eval as make_tuple
from statsmodels.tsa.holtwinters import ExponentialSmoothing

from warnings import filterwarnings,catch_warnings


import copy

import matplotlib.pyplot as plt
from matplotlib.container import BarContainer
from matplotlib import cm

import tkinter as tk

from ipaddress import ip_address,IPv4Address

import mplcursors
import random

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
      # a.pop(v,None)
      a[v] = -1
   else:
      a[v] = value
   return a[v]

def add_to_dict_dict_counter(s:dict,k,v):
   if (k not in s):
      s[k] = {v : 1}
   else:
      if (v not in s[k]):
         s[k][v] = 1
      else:
         s[k][v] += 1

def add_to_blk_peers(blk_peers:dict,peer,role,peer2):
    if (key := (peer,role)) not in blk_peers:
        blk_peers[key] = set()
    blk_peers[key].add(peer2)

def n_alerts_incr(dct:dict,k):
   """
   Increases by 1 dct[k][-1]
   Puts k in dct if absent
   """
   if k not in dct:
      n = len(next(iter(dct.values()))) if len(dct.values()) else 1
      dct[k] = [0] * n
   dct[k][-1] += 1
   return dct[k][-1]

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

HOSTNAMES = False
def get_id(a,k:int):
   if(k not in range(3)):
      raise Exception("Invalid id: 0,1,2 (srv,cli,srvcli) available only")
   srv_id = a["srv_name"] if (HOSTNAMES and a["srv_name"] != "") else a["srv_ip"]
   cli_id = a["cli_name"] if (HOSTNAMES and a["cli_name"] != "") else a["cli_ip"]
   
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
      srv_id = a["srv_name"] if (HOSTNAMES and a["srv_name"] != "") else a["srv_ip"]
      return (srv_id,a["vlan_id"])
   if (k == 1):
      cli_id = a["cli_name"] if (HOSTNAMES and a["cli_name"] != "") else a["cli_ip"]
      return (cli_id,a["vlan_id"])
   if (k == 2):
      srv_id = a["srv_name"] if (HOSTNAMES and a["srv_name"] != "") else a["srv_ip"]
      cli_id = a["cli_name"] if (HOSTNAMES and a["cli_name"] != "") else a["cli_ip"]
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
   # len_TimeWindow = len(list(hosts_ts.values())[0]) if (len(hosts_ts)) else 0
   len_TimeWindow = max(len(v) for v in hosts_ts.values()) if (len(hosts_ts)) else 0
   # print(len_TimeWindow)
   for k,v in host_r.items():
      # if host was not previously observed
      if k not in hosts_ts:
         # fill with zeros
         # hosts_ts[k] = [0] * len_TimeWindow
         # fill with the first value known
         hosts_ts[k] = [0] * (len_TimeWindow)
      hosts_ts[k] += [v["total"]] 
   
   # if no update in host_r for some keys,
   # then add zero
   for k in hosts_ts.keys():
      if k not in host_r:
         # no update in host_r
         # add zero
         hosts_ts[k] += [0]

def contains_two_nonzero_values(v:list):
   """
   This function checks whether v contains at least two different values != 0
   """
   nonzero_values = set(filter(lambda x: x != 0, v))
   return len(nonzero_values) >= 2

OUTLIER_LOWER_BOUND = 45

def hostsR_outlier(hosts_ts:dict, outlier_detector: callable):
   outlier_hosts = {}
   for host,ratings in hosts_ts.items():
      # print("host and rating" + str((host,ratings) ))
      # hoti = host_outlier_time_indices

      hoti = outlier_detector(values=ratings,lower_bound=OUTLIER_LOWER_BOUND) if contains_two_nonzero_values(ratings) else []
      if hoti:
         outlier_hosts[host] = [hoti, list(map(lambda x: round(x,2),ratings))]   
   return outlier_hosts

def window_rating_outlier(hosts_ratings:list, outlier_detector: callable):
   outlier_hosts = {}
   for time_window_index,d in enumerate(hosts_ratings):
      # print(d.values())
      # filter 0 values

      d = {h:r for h,r in d.items() if r["total"] > 0.}
      ratings = list(map(lambda x: x["total"],d.values()))
      hoti = outlier_detector(values=ratings,lower_bound=OUTLIER_LOWER_BOUND) if contains_two_nonzero_values(ratings) else []
      hosts_index = [(list(d.keys())[i],i) for i in hoti]
      for host,i in hosts_index:
         outlier_hosts[host] = [[time_window_index], [round(ratings[i],2)]]
      
   return outlier_hosts
         


def detect_outliers_iqr(values,lower_bound:int, threshold=3.5):
    """
    This function detects outliers in a list of numbers using the interquartile range (IQR).
    values: list of numbers
    threshold: number of IQRs from the median to use as a threshold for outlier detection

    returns: list of outlier indices
    """
    data = list(values)

    leading_zeros = 0
    while len(data) > 0 and data[0] == 0:
       data.pop(0)
       leading_zeros += 1

    # Convert the data to a numpy array
    data = np.array(data)

    # Calculate the quartiles
    q1, q3 = np.percentile(data, [25, 75])

    # Calculate the IQR
    iqr = q3 - q1

    # Calculate the lower and upper bounds
    lower_b = q1 - threshold * iqr
    upper_b = q3 + threshold * iqr

    # Find the outliers
    outliers = np.where((data < lower_b) | (data > upper_b))[0]

    # If threshold is None
    # Exclude values below threshold from data
    if lower_bound is not None:
       outliers = [x + leading_zeros for x in outliers if data[x] >= lower_bound]
 
   #  # Check if last element is an actual outlier or not   
   #  if len(outliers) and (data[-1] < threshold or abs(data[-1] - wma[-1]) <= threshold):
   #     outliers.pop()


    return list(outliers)

def detect_outliers_iqr_nonzero(values, lower_bound:int, threshold=4):
    """
    This function detects outliers in a list of numbers using the interquartile range (IQR).

    values: list of numbers
    threshold: number of IQRs from the median to use as a threshold for outlier detection

    returns: list of outlier indices
    """
    data = list(values)

    # Elimina i valori pari a 0 da data e ricava gli indici corrispondenti in values
    indices = [i for i, val in enumerate(values) if val != 0]
    data = [val for val in values if val != 0]

    # Convert the data to a numpy array
    data = np.array(data)

    # Calculate the quartiles
    q1, q3 = np.percentile(data, [25, 75])

    # Calculate the IQR
    iqr = q3 - q1

    # Calculate the lower and upper bounds
    lower_b = q1 - threshold * iqr
    upper_b = q3 + threshold * iqr

    # Find the outliers
    outliers = np.where((data < lower_b) | (data > upper_b))[0]

    # If lower_bound is not None, exclude values below lower_bound from data
    if lower_bound is not None:
        outliers = [x for x in outliers if data[x] >= lower_bound]

    # Map the outlier indices back to the indices of the original values list
    outliers = [indices[i] for i in outliers]

    return outliers


def detect_outliers_wma(values:list, lower_bound:int, window_size=5, threshold=2.5):
   """
   This function detects outliers in a list of numbers using the weighted moving average WMA.
   
   data: list of numbers
   window_size: size of the window used for the moving average
   threshold: aka sigma number of standard deviations from the moving average to use as a threshold for outlier detection
   lower_bound: values below this threshold will be excluded from outlier detection
   
   returns: list of outlier indices
   """

   sigma = threshold # renaming
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

def detect_outliers_mad(values, lower_bound:int,threshold=3.5):
   """
   This function detects outliers in a list of numbers using the modified z-score method with MAD.
   It excludes the first elements of data that are equal to 0 and does not consider the last element as an outlier.

   data: list of numbers
   threshold: modified z-score threshold for outlier detection

   returns: list of outlier indices
   """

   data = list(values)
 
   leading_zeros = 0
   while len(data) > 0 and data[0] == 0:
      data.pop(0)
      leading_zeros += 1
   

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
   # outliers = [i + leading_zeros for i, x in enumerate(modified_z_scores) if abs(x) > threshold and i != len(modified_z_scores)-1]
   # return outliers

   outliers = [i for i, x in enumerate(modified_z_scores) if (abs(x) > threshold and data[i] >= lower_bound and i != len(modified_z_scores)-1)]
   return list(map(lambda x: x + leading_zeros,outliers))

def detect_outliers_exp_smooth(values, lower_bound : int, alpha=0.8, threshold=3.0):
    """
    This function detects outliers in a list of numbers using exponential smoothing.
    
    values: list of numbers
    alpha: smoothing factor
    threshold: number of standard deviations from the smoothed values to use as a threshold for outlier detection
    
    returns: list of outlier indices
    """
    data = list(values)
    # Exclude leading zeros
    leading_zeros = 0
    while len(data) > 0 and data[0] == 0:
       data.pop(0)
       leading_zeros += 1
    if len(data) == 0:
        return []
    
    data = np.array(data)
    # Apply exponential smoothing
    smoothed = [data[0]]
    for i in range(1, len(data)):
        smoothed.append(alpha * data[i] + (1 - alpha) * smoothed[-1])
    
    # Calculate deviations from smoothed values
    deviation = np.abs(data - smoothed)
    
    # Calculate the standard deviation of the deviation
    std_dev = np.std(deviation)
    
    # Check that the standard deviation is not zero
    if std_dev == 0:
        return []
    
    # Calculate the threshold for outlier detection
    threshold = threshold * std_dev
    
    # Find the outliers
    outliers = np.where(deviation > threshold)[0]
    
    outliers = list(filter(lambda x: values[x] >= lower_bound,map(lambda x: x + leading_zeros,outliers)))
    
    return outliers

def detect_outliers_holt_winters(values, lower_bound, threshold=1.5, smoothing_level=0.2, smoothing_trend=0.1, smoothing_seasonal=0.3, seasonal_periods=None):
    """
    This function detects outliers in a list of numbers using the triple exponential smoothing (Holt-Winters) method.
    
    values: list of numbers
    threshold: number of standard deviations from the predicted value to use as a threshold for outlier detection
    smoothing_level: parameter of the Holt-Winters model controlling the smoothing of the level
    smoothing_trend: parameter of the Holt-Winters model controlling the smoothing of the trend
    smoothing_seasonal: parameter of the Holt-Winters model controlling the smoothing of the seasonal component
    seasonal_periods: number of periods in a complete seasonal cycle, used for the seasonal component of the Holt-Winters model
    
    returns: list of outlier indices
    """
    data = list(values)
    if len(set(values)) == 1:
       return []
    # Exclude leading zeros
    leading_zeros = 0
    while len(data) > 0 and data[0] == 0:
       data.pop(0)
       leading_zeros += 1
      
   #  # Exclude leading zeros if present
   #  while len(data) > 0 and data[0] == 0:
   #      data = data[1:]
    
    
    # If data has less than 2 elements, return an empty list
    if len(data) < 2 or len(list(filter(lambda x: x != 0,data))) < 4:
        return []
    
    data = np.array(data)

    # Create the Holt-Winters model
    with catch_warnings():
       filterwarnings("ignore", category=RuntimeWarning)
       model = ExponentialSmoothing(data, trend='add',seasonal=('add' if seasonal_periods else None), seasonal_periods=seasonal_periods,)
      #  filterwarnings('ignore', category=w[0].category, module=w[0].module, lineno=w[0].lineno)
       # Fit the model and predict the values
       fitted_model = model.fit(smoothing_level=smoothing_level, smoothing_trend=smoothing_trend, smoothing_seasonal=smoothing_seasonal)
       predicted_values = fitted_model.fittedvalues

    
    # Calculate the residuals (differences between the actual and predicted values)
    residuals = data - predicted_values
    
    # Calculate the standard deviation of the residuals
    std_dev = np.std(residuals)
    
    # Calculate the threshold for outlier detection
    threshold = threshold * std_dev
    
    # Find the outliers
    outliers = np.where(np.abs(residuals) > threshold)[0]

    # Check if last element is an actual outlier or not   
    if len(outliers) and np.abs(data[-1] - predicted_values[-1]) <= threshold:
        outliers = outliers[:-1]
    
    outliers = list(filter(lambda x: values[x] >= lower_bound,map(lambda x: x + leading_zeros,outliers)))
    return outliers

def get_outliers_features(outliers:dict, hosts_ratings:list) ->dict:
   """
   This function returns for each host which presents outliers in its ratings
   how such an outlier rating was computed, which is the score associated
   with each feature
   """

   """
   Each outliers item looks like this:
   "('host', vlan_id)": [
    "[7, 8]",
    "[0, 0, 0, 0, 0, 0, 31.86, 0, 0, 30.92, 31.42]"
   ]

   While hosts_ratings is a list of dictionaries whose items look like:
   {"('host', vlan_id)": {
    "total": 190.18823310062726,
    "BAT_ONE_TIME": 25,
    "higher_alert_types": 20,
    "periodic": 125.18823310062726,
    "bat_samefile": 20}
   """
   outliers_time_features = {}
   for key,v in outliers.items():
      ratings = None
      for time_index in v[0]:
         # Get the hosts ratings list corresponding to the time
         # window where the host k produced an outlier value in its rating
         ratings = hosts_ratings[time_index]

         # Add its features-specific rating to the returning dict
         # TODO k is a string if parsed from file
         # key = str(k) if (len(ks := ratings.keys()) and type(ks) is str) else k
         outliers_time_features[(time_index,key)] = ratings[key] if (key in ratings) else {"total" : .0}

         # We do not care about "total" score
         # outliers_time_features[(time_index,k)].pop("total",None)

   # deepcopy necessary because we are popping total from the dict
   # and it might be needed when sorting if an outlier is detected multiple times
   # by different function calls
   outliers_time_features = copy.deepcopy(dict(sorted(outliers_time_features.items(),key=lambda x:(x[0][0],x[1]["total"]))))
   for k in outliers_time_features.keys():
      outliers_time_features[k].pop("total",None)

   return outliers_time_features

def map_index_to_time(outliers_features:dict,time_lst:list):
   return {(time_lst[k[0]]["start"],k[1]):v for k,v in outliers_features.items()}


def plot_outliers(outliers_time_features,
                  features: list,
                  n_time_windows: int,
                  hosts_ratings: dict,
                  hosts_sizes: dict,
                  all_time_dict: list,
                  title: str):

   len_outlier_keys = len(outliers_time_features.items())
   if len_outlier_keys == 0:
      return
   # Fill outliers_time_features with zero values if a feature hasn't contributed
   for k,v in outliers_time_features.items():
      for feature in features:
         if feature not in outliers_time_features[k]:
            outliers_time_features[k][feature] = 0.

   # Calcola i punteggi intermedi per ogni record
   scores = []

   for k,v in outliers_time_features.items():
      sorted_values = [v[feature] for feature in sorted(v.keys(), key=lambda k: features.index(k))]
      scores.append(sorted_values)

   # Fix different lengths
   # max_len = len(max(scores,key=len))
   max_len = n_time_windows
   for l in scores:
      while len(l) < max_len:
         # l += [.0]
         l.append(.0)

   scores = np.array(scores)  # Converti scores in un array NumPy

   # Crea un grafico a barre impilate dei punteggi intermedi
   fig, ax = plt.subplots()
   categories = features
   colors = cm.tab20(np.linspace(0, 1, len(categories)))
   bars = []
   for i, cat in enumerate(categories):
       cat_scores = [score[i] for score in scores]
       new_bar = ax.bar(np.array(range(len_outlier_keys)), cat_scores, bottom=np.sum(scores[:, :i], axis=1),color=colors[i],label=cat)
       bars.append(new_bar)

   def show_annotation(sel):
    if type(sel.artist) == BarContainer:
        bar = sel.artist[sel.index]
        sel.annotation.set_text(f'{sel.artist.get_label()}: {bar.get_height():.1f}')
        sel.annotation.xy = (bar.get_x() + bar.get_width() / 2, bar.get_y() + bar.get_height() / 2)
        sel.annotation.get_bbox_patch().set_alpha(0.8)

   cursor = mplcursors.cursor(hover=2)

   cursor.connect("add", show_annotation)

   # Aggiungi le etichette degli assi e delle categorie
   ax.set_xticks(range(len_outlier_keys))
   ax.set_xticklabels(outliers_time_features.keys(), rotation=90)
   ax.set_xlabel('Host')
   ax.set_ylabel('Ratings')
   ax.legend(bars, categories)
   fig.canvas.manager.set_window_title(title)
   plt.subplots_adjust(bottom=0.45)

   def onclick(event):
      try:
         index = int(event.xdata)
      except TypeError as e:
         return # do nothing
      key = list(outliers_time_features.keys())[index]

      # copy to clipboard the host@vlan
      host_vlan = str(key[1][0]) + ("@" + str(key[1][1])) if (key[1][1] != -1) else ""
      copy_to_clipboard(host_vlan)

      tmp = {key[1] : [list(range(0,len(hosts_ratings))),[]]}
      feats = map_index_to_time(get_outliers_features(tmp,hosts_ratings),all_time_dict)

      feats_sizes = map_index_to_time({(i,key[1]) : {"N_alerts": hosts_sizes[key[1]][i]} for i in list(range(0,len(hosts_ratings)))}
                                      ,all_time_dict)
      try:
         plot_outliers(feats,features,n_time_windows,hosts_ratings,hosts_sizes,all_time_dict,str(key[1]) + " Ratings")
         plt.show()
         plot_outliers(feats_sizes,["N_alerts"],n_time_windows,hosts_ratings,hosts_sizes,all_time_dict,str(key[1]) + " Number of Alerts")
         plt.show()
      except TypeError as e:
         e # Do nothing

   cid = fig.canvas.mpl_connect('button_press_event', onclick)


def tuple_hook(obj):
   if (type(obj) is dict):
      return {deserialize_key(k):tuple_hook(v) for k,v in obj.items()}
   if (type(obj) is list):
      return list(map(deserialize_key,obj))
   return obj

def deserialize_key(s):
   if (type(s) is str and
      re.match("\(('.+?',\s){1,2}([0-9]+)(,\s[0-9]+)?\)",s)):
      return make_tuple(s)
   return s

def subnet_check(s:str,subnet_regex:list):
   if any(re.match(subnet_re,s) for subnet_re in subnet_regex):
      return True
   return False

def copy_to_clipboard(text: str):
    root = tk.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    root.destroy()

def is_private(host:str):
   return ip_address(host).is_private

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

def randomize_dict_keys(d):
    randomized_keys = {}
    for key in d:
        x, y = key
        while True:
            new_key = (tuple(random.randint(0, 255) for _ in range(4)), random.randint(2, 70))
            if new_key not in randomized_keys:
                randomized_keys[new_key] = d[key]
                break
    return randomized_keys

def randomize_dict(d):
    result = {}
    for key, value in d.items():
        z, (x, y) = key
        new_x = tuple(str(random.randint(0, 255)) for _ in range(4))
        new_y = random.randint(2, 70)
        new_key = (z, ('.'.join(new_x), new_y))
        while new_key in result:
            new_x = tuple(str(random.randint(0, 255)) for _ in range(4))
            new_y = random.randint(2, 70)
            new_key = (z, ('.'.join(new_x), new_y))
        result[new_key] = value
    return result
