




# Home directory -- where your network scanner dir is -- the scanner needs the full path.
# NOTE: CHANGE THIS
HOME = "/var/home/cshortt/Desktop/Network_Scanner"

# FULL path to your nmap binary -- MAY need to be changed. Check your install:> which nmap
# NOTE: MIGHT HAVE TO CHANGE THIS
NMAP_PATH = '/home/linuxbrew/.linuxbrew/bin/nmap'


# FULL oath to state file. This file stores the state and results in JSON format for the dashboard
STATE_FILE = HOME + '/state.json'

# Default directories and extensions for the network scanner -- shouldn't need to be changed
IPS_DIR = HOME + "/ips"
IP_F_EXT = "ips"
SCAN_DIR = HOME + "/scans"

# How often, in minutes, should you scan? -- NOT used currently
SCAN_CADENCE = 5











