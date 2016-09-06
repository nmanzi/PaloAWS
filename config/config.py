# each FW IP corresponds to exactly one zone
FIREWALLS = {
    'a': {'hostname': '1.2.3.4', 'api_username': 'apiuser', 'api_password': 'apipwd'},
    'b': {'hostname': '2.3.4.5', 'api_username': 'apiuser', 'api_password': 'apipwd'}
}

# specify in CIDR format (e.g. 192.168.0.0/24)
AZ_PREFIX_MAP = {
    'a': '192.168.1.0/24',
    'b': '192.168.2.0/24'
}

# internal ELB(s) that NAT rule will point to
ELB_LIST = [
    "internal-lb-123456789.eu-central-1.elb.amazonaws.com",
    "internal-lb-987654321.eu-central-1.elb.amazonaws.com"
]

# S3 Bucket where the database is stored at
S3_BUCKET = 'paloaws'

# S3 credentials (only used for debug)
AWS_REGION = "eu-central-1"
AWS_ACCESS_KEY = ""
AWS_SECRET_KEY = ""

VERBOSE = True
DEBUG = False

DB_FILE = "elblist.json"
