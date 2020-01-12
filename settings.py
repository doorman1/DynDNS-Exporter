#################
# Main Settings #
#################

# Login credentials for the account on Dyn.com
auth_cred = {
    'username' : 'Your username goes here',
    'password' : 'Your password goes here',
}

# Enter the zones your want exported and where each should be saved
# Files ending with .html are saved as HTML documents, the rest as TXT files
# In case of only one entry, leave the trailing comma in place
zones = (
    ('yourdomain.com', '/path/to/dns/index.html'),
)

# Which record types to export and whether to display the record type
# 'All' is a special value that includes all types
exported_types = ['A-record']
display_type = False

# Ports for which to add links next to each hostname
# In case of only one entry, leave the trailing comma in place
# Line format:
#    (port number, protocol)
ports = (
    (80, 'http'),
    (1800, 'http'),
    (7000, 'http'),
    (8080, 'http'),
    (41810, 'http'),
)

##################
# GeoIP Settings #
##################

# Whether or not to cache IP information
# If the cache is enabled but not writable, the script will refuse to continue
# and will raise a CacheNotWritable exception
cache_enable = True
# Absolute path to file used to store cached information
cache_file = '/path/to/cache/file'
# How long should information about an IP be retained in the cache (in days)
cache_lifetime = 32

# Maxmind's web service license key
license_key = 'YuUtl5pOBwmg'

# Private network names
# Higher entries override lower ones. That means that in case an IP belongs
# to more than one network, the first network's name will be picked
# Networks are specified in CIDR notation
# http://en.wikipedia.org/wiki/CIDR_notation
# http://ip2cidr.com/ can be used to generate CIDR notations
# Put one entry per line, end with commas
# Line format:
#    name : [cidr(,...)]
private_network_names = {
    'Pending Setup' : ['1.1.1.1/32'],
    'Skynap Private IP' : ['10.20.0.0/16'],
    'Private IP' : ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
}

# Alternate ISP names (case sensitive!)
# Put one entry per line, end with commas
# Line format:
#    name returned by maxmind : new name
isp_names_alt = {
    'BellSouth.net' : 'Bellsouth DSL',
}

#######################
# Port Check Settings #
#######################

# Ports to check
port_checks = [22, 80, 1800, 7000, 8080, 41810]

# Timeout for port checks (in seconds)
timeout = 20

# Maximum number of threads to use for making port checks
port_thread_pool_size = 300

# Maximum number of threads to use for making ping checks
ping_thread_pool_size = 10

# Whether offline hosts should be pinged to determine if they're online
ping_offline_hosts = True

# Command to use when pinging a host
#
# Example commands:
#
#         Linux: ['ping', '-c', '1', '-w', '10']
#       Windows: ['ping', '-n', '1', '-w', '10000']
#
# Note: Windows uses milliseconds for the -w option, while Linux uses seconds.
ping_cmd = ['ping', '-c', '1', '-w', '10']

# Private networks
#
# Networks are specified in CIDR notation
# http://en.wikipedia.org/wiki/CIDR_notation
# http://ip2cidr.com/ can be used to generate CIDR notations
# Put one entry per line, end with commas
private_networks = (
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
)

private_hostnames = (
    'arjona.ahtdns.com',
    'gainor.ahtdns.com',
    'hirtenstein.ahtdns.com',
    'lajos.ahtdns.com',
    'lgd.ahtdns.com',
    'nancy.ahtdns.com',
    'suridisoffice.ahtdns.com',
    'suridisloft.ahtdns.com',
)

###############################
# Email Notification Settings #
###############################

# Whether or not to send email notifications for status changes
email_enable = True

# Send notification for status changes listed below
# Line format:
#    (old status, new status, enable notification)
# Note: Do not add new lines, only change the third field of each existing line
#       to either True or False
email_status_changes = (
    ('online', 'offline', True),
    ('offline', 'online', True),

    ('online', 'private', False),
    ('private', 'online', False),

    ('offline', 'private', False),
    ('private', 'offline', False),
)

# Sender (From:) and recipient (To:) email addresses
email_sender = 'webmaster@localhost'
email_recipient = ''

# Subject and main body of the notification email
# Valid placeholders that will be replaced:
#    {new_status}, {old_status}, {hostname}, {timestamp}
email_subject = 'Status change: {hostname} is {new_status}'
email_message = """
Status of {hostname} changed from {old_status} to {new_status}.

This event occurred on {timestamp}.
"""

# Mail server settings:
#   email_host
#      the host to use for sending email
#   email_port
#      port to use for the SMTP server
#   email_host_user
#      username to use for the SMTP server
#   email_host_password
#      password to use for the SMTP server
#   email_use_tls
#      whether to use a TLS connection when connecting to the SMTP server;
#      usually mail servers listening on port 587 will require this option
#   email_use_ssl
#      whether to use an SSL connection when connecting to the SMTP server;
#      usually mail servers listening on port 465 will require this option
email_host = 'localhost'
email_port = 25
email_host_user = ''
email_host_password = ''
email_use_tls = False
email_use_ssl = False
