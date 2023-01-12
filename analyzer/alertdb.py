import pandas as pd

df = pd.DataFrame(columns=["tstamp","tstamp_end","srv_port","severity","cli2srv_bytes","vlan_id","rowid","community_id","ip_version","srv2cli_pkts","interface_id","cli2srv_pkts","score","srv2cli_bytes","cli_port","alert_id","l7_proto","srv_blacklisted","cli_blacklisted","json","probe_ip","cli_ip","srv_name","srv_ip","cli_name"])

def new_alert(a):
    remove_unwanted_fields(a)
    a_convert_dtypes(a)
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
    
    # TODO strings are still recognised as 'object'
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
