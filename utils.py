import json 
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
                           
