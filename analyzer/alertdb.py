import pandas as pd

df = pd.DataFrame({"tstamp": pd.Series(dtype='datetime64[ns]'),
                   "tstamp_end": pd.Series(dtype='datetime64[ns]'),
                   "user_label_tstamp": pd.Series(dtype='datetime64[ns]'),

                   "srv_port": pd.Series(dtype='int'),
                   "severity": pd.Series(dtype='int'),
                   "cli2srv_bytes": pd.Series(dtype='int'),
                   "vlan_id": pd.Series(dtype='int'),
                   "cli_host_pool_id": pd.Series(dtype='int'),
                   "srv_host_pool_id": pd.Series(dtype='int'),
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
                   "is_srv_victim": pd.Series(dtype='int'),
                   "srv_blacklisted": pd.Series(dtype='int'),
                   "cli_blacklisted": pd.Series(dtype='int'),
                   "is_srv_attacker": pd.Series(dtype='int'),
                   "is_cli_victim": pd.Series(dtype='int'),
                   "is_cli_attacker": pd.Series(dtype='int'),

                   "probe_ip": pd.Series(dtype='string'),
                   "cli_ip": pd.Series(dtype='string'),
                   "srv_name": pd.Series(dtype='string'),
                   "srv_ip": pd.Series(dtype='string'),
                   "cli_name": pd.Series(dtype='string'),

                   "json": pd.Series(dtype='object')
                   })


def new_alert(a):
    #  a_convert_dtypes(a)
    remove_unwanted_fields(a)
    # tmp = pd.DataFrame(a, index=[0])
    #  df.append(a,ignore_index=True)
    #  pd.concat([tmp,df],ignore_index=True)
    df.loc[len(df)] = a
    #  print(df)


def a_convert_dtypes(a):
    # convert dtypes
    tmp = a["tstamp"]
    a["tstamp"] = pd.to_datetime(a["tstamp"])
    a["tstamp_end"] = pd.to_datetime(a["tstamp_end"])
    a["user_label_tstamp"] = pd.to_datetime(a["user_label_tstamp"])
    print(str(tmp) + str(type(tmp)) + ' --> ' +
          str(a["tstamp"]) + str(type(a["tstamp"])))

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
