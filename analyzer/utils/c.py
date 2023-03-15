# Generic constants file


GRP_SRV,GRP_CLI,GRP_SRVCLI = range(3)

# Alert categories

TLS_ALERTS = ["tls_certificate_expired","tls_certificate_mismatch","ndpi_tls_old_protocol_version","tls_unsafe_ciphers"]

# Singleton alerts are alerts which are relevant if received only one time (per srv/cli)
RELEVANT_SINGLETON_ALERTS = [
    # "binary_application_transfer",
    # "remote_to_local_insecure_proto",
    # "ndpi_ssh_obsolete_client",
    # "ndpi_clear_text_credentials",
    "ndpi_smb_insecure_version",
    "data_exfiltration",
    # "ndpi_suspicious_dga_domain",
    # "tls_certificate_selfsigned"
    ]

IGNORE_SINGLETON_ALERTS = [
    # These are not interesting alerts by theirselves
    "blacklisted",
    "ndpi_dns_suspicious_traffic",
    "ndpi_http_suspicious_user_agent",

    # These are exported only when matching
    # more specific criterias
    "ndpi_http_suspicious_content",
    "ndpi_suspicious_dga_domain",
    "ndpi_ssh_obsolete_client",
    "binary_application_transfer",
    "ndpi_clear_text_credentials",
    "remote_to_local_insecure_proto",
    "tls_certificate_selfsigned"
] + TLS_ALERTS
# "tls_certificate_selfsigned"

# Alert flow stats constants

# Minimum size for an alert flow before computing stats on it
MIN_BKT_RELEVANT_SIZE = 3
# Minimum percentage of 'is_victim' before considering a host a victim
IS_VICTIM_TH = 0.75
# Minimum number of alerts in a flow to consider it periodic
MIN_PERIODIC_SIZE = 3
# Upper bound on the coefficient of variation (aka relative stddev) on tdiff
# to consider an alert flow periodic 
PERIODIC_CV_THRESHOLD = 0.9
# Entropy threshold on port and IPs to consider a host behavior odd
# with respect to the client-server paradigm
CLI_ODD_PORT_S_TH   = 0.1
SRV_ODD_PORT_S_TH   = 0.8
SRV_ODD_PORT_COUNT_TH   = 6
CSODD_IP_S_TH     = 0.5
# Upper bound on the coefficient of variation (aka relative stddev) on tdiff
# to consider an alert flow periodic when comparing it with others who have similar periodicity
PERIODIC_SIMILAR_CV_THRESHOLD = 1.0



# JA3 str to be used instead of srv|cli hash when it is missing
JA3_MISSING_SRV_HASH = "ja3_MISSING_SRV_hash"
JA3_MISSING_CLI_HASH = "ja3_MISSING_CLI_hash"

# For these applications it is expected a bidirectional communication
# Hence, no unidirectional traffic
BIDIR_APP = ["http", "tls", "dns"]


# Minimum number of unidirectional flows towards the same server
# to consider it a probing victim 
MIN_PROBING_RELEVANT_SIZE = 10
# Entropy threshold on the probed server PORTS the attackers (client) are
# trying to connect to 
PROBING_ENTROPY_THRESH = 0.8
