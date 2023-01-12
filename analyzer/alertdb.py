import pandas as pd

df = pd.DataFrame({"tstamp": pd.Series(dtype='datetime64[ns]'),
                   "tstamp_end": pd.Series(dtype='datetime64[ns]'),

                   "srv_port": pd.Series(dtype='int'),
                   "severity": pd.Series(dtype='int'),
                   "cli2srv_bytes": pd.Series(dtype='int'),
                   "vlan_id": pd.Series(dtype='int'),
                   "rowid": pd.Series(dtype='int'),
                   "community_id": pd.Series(dtype='int'),
                   "ip_version": pd.Series(dtype='int'),
                   "srv2cli_pkts": pd.Series(dtype='int'),
                   "interface_id": pd.Series(dtype='int'),
                   "cli2srv_pkts": pd.Series(dtype='int'),
                   "score": pd.Series(dtype='int'),
                   "srv2cli_bytes": pd.Series(dtype='int'),
                   "cli_port": pd.Series(dtype='int'),
                   "alert_id": pd.Series(dtype='int'),
                   "l7_proto": pd.Series(dtype='int'),

                  # These are bool actually
                   "srv_blacklisted": pd.Series(dtype='int'),
                   "cli_blacklisted": pd.Series(dtype='int'),

                   "probe_ip": pd.Series(dtype='string'),
                   "cli_ip": pd.Series(dtype='string'),
                   "srv_name": pd.Series(dtype='string'),
                   "srv_ip": pd.Series(dtype='string'),
                   "cli_name": pd.Series(dtype='string'),

                   "json": pd.Series(dtype='object')
                   })



dtypes = [
    ("srv_port",             "int"),
    ("tstamp_end",           "datetime64[s]"),
    ("probe_ip",             "string"),
    ("severity",             "int"),
    ("cli2srv_bytes",        "int"),
    ("is_srv_victim",        "bool"),
    ("cli_ip",               "string"),
    ("vlan_id",              "int"),
    ("cli_host_pool_id",     "int"),
    ("srv_host_pool_id",     "int"),
    ("rowid",                "int"),
    ("tstamp",               "datetime64[ns]"),
    ("community_id",         "int"),
    ("ip_version",           "int"),
    ("srv2cli_pkts",         "int"),
    ("srv_name",             "string"),
    ("srv_blacklisted",      "int"),
    ("interface_id",         "int"),
    ("cli_blacklisted",      "int"),
    ("is_srv_attacker",      "bool"),
    ("is_cli_victim",        "bool"),
    ("srv_ip",               "string"),
    ("is_cli_attacker",      "bool"),
    ("cli2srv_pkts",         "int"),
    ("score",                "int"),
    ("cli_name",             "string"),
    ("srv2cli_bytes",        "int"),
    ("cli_port",             "int"),
    ("alert_id",             "int"),
    ("l7_proto",             "int"),
    ("user_label_tstamp",    "datetime64[ns]"),
]

df = pd.DataFrame(columns=["tstamp","tstamp_end","srv_port","severity","cli2srv_bytes","vlan_id","rowid","community_id","ip_version","srv2cli_pkts","interface_id","cli2srv_pkts","score","srv2cli_bytes","cli_port","alert_id","l7_proto","srv_blacklisted","cli_blacklisted","json","probe_ip","cli_ip","srv_name","srv_ip","cli_name"])

def new_alert(a):
    remove_unwanted_fields(a)
    a_convert_dtypes(a)
    # tmp = pd.DataFrame(a, index=[0])
    # append to dataframe
    df.loc[len(df)] = a

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
