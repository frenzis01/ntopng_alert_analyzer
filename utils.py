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