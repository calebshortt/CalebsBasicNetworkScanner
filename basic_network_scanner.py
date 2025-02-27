import logging
import settings
logger = logging.getLogger(__name__)
logging.basicConfig(filename=settings.HOME + '/networkscanner.log', format='%(asctime)s - %(levelname)s: %(message)s', encoding='utf-8', level=logging.DEBUG)

import time
import glob
import os
import filecmp
import json
import re

from datetime import datetime
from subprocess import call




""""
        Caleb's Basic Network Scanner (CBNS)

        This is a simple network scanner. It uses nmap to find IPs on your network, then port scans them.
        It saves the results to a JSON file, and to individual files for analysis.
        The JSON file is used by the local server to power the dashboard (dashboard.html)

        GENERAL FLOW:
                1. Run scanner (or set up a daemon to run every few hours)
                2. Once at least one successful scan is complete, start the local server (servelocally/sh)
                3. Go to localhost:8080/dashboard.html

        USAGE:

            Run the scanner $> sudo python3 basic_network_scanner.py
                - This will take some time.
                - You can view the logs in the networkscanner.log file
                    - $> tail networkscanner.log -f -n100

            Run the dashboard
                1. $> ./servelocally.sh
                    - NOTE: This script will take the HOME directory from settings.py and host it.
                    - NOTE: This script assumes that /bin/python exists. Modify accordingly if required.

                2. Open browser and go to localhost:8080/dashboard.html
                    - NOTE: At least one run must have been completed and a state.json file created from it.


"""




"""
STATE Structure

STATE = {
    '<ip address>': {
        'raw_scan': <str: raw scan from nmap>
        'ports':
    },
    ...
}

"""
STATE = {}


def save_state():
    logger.debug('Saving scan state to {}'.format(settings.STATE_FILE))
    with open(settings.STATE_FILE, "w") as f:
        json.dump(STATE, f)

def load_state():
    if not os.path.isfile(settings.STATE_FILE):
        logger.debug('Initializing scan state. No file to load. New state generated.')
        STATE = {}

    else:
        logger.debug('Initializing scan state from {}'.format(settings.STATE_FILE))
        with open(settings.STATE_FILE, "r") as f:
            STATE = json.load(f)

"""
    Use nmap to scan the network and save any found IPs to a file.
    The file name is saved to {IPS_DIR}/ips-{time}E
    Returns: filepath to newly-generated IPs file
"""
def find_ips():
    f_name = '{}/ips-{}.{}'.format(settings.IPS_DIR, time.strftime("%Y%m%d-%H%M%S"), settings.IP_F_EXT)
    logger.debug('Finding IP addresses on network and storing results in {}'.format(f_name))

    cmd = settings.NMAP_PATH + ' -sn 192.168.1.1/24 | grep "scan report" | grep -oE "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b" > ' + f_name
    call(cmd, shell=True)
    return f_name


"""
    Get all the ip files from X number of days ago until now -- default is 7 days.
    NOTE: This goes by date modified.
    Returns a list of filepaths
"""
def _get_ip_files(days=7):
    files = glob.glob('{}/ips-*.{}'.format(settings.IPS_DIR, settings.IP_F_EXT))
    modified_files = list()
    current_time = time.time()

    for f in files:
        time_delta = current_time - os.path.getmtime(f)
        time_delta_days = time_delta / (60 * 60 * 24)
        if time_delta_days < days:
            modified_files.append(f)

    return modified_files


"""
    Just a helper function to make things readable
"""
def something_changed(file1, file2):
    return not filecmp.cmp(file1, file2, shallow=False)


# Take the ip, and the filepath
# Load the filepath and parse the data. Put it in the ip's state
# load file, parse line by line -- look for ...
#   open            ex: 2869/tcp open  upnp    Microsoft IIS httpd
#           - This will get port, protocol, possible service?, notes/version
#           - PORT     STATE SERVICE VERSION
#   MAC             ex: MAC Address: B4:AE:2B:3D:27:24 (Microsoft)
#   "OS guesses: "  ex: Aggressive OS guesses: Microsoft Windows 11 21H2 (91%), Fre...
#   "Device type: " ex: Device type: general purpose
#
#
#   <ipaddr>: {
#       'ports': {                      NOTE: 'ports' is a dict with the port nums as keys
#           <port_number>: {
#               'number': <num>,
#               'protocol': <str>,
#               'state': <str|None>,
#               'service': <str|None>,
#               'version': <str|None>,
#               'last updated': <>
#           },
#           ...
#       },
#       'mac': <str|None>,
#       'os': <str|None>,
#       'device': <str|None>,
#   }
def set_scan_state(ip, filepath):

    ip_state = STATE.get(ip, {})

    dt_now = '{}'.format(datetime.now().strftime("%Y-%m-%d %H:%M"))
    ip_state['last seen'] = dt_now

    re_port = re.compile(r'(?P<num>\d+)/(?P<protocol>tcp|udp)?\s+(?P<state>open|filtered|closed)\s*(?P<service>[\w\?]+)?\s*(?P<version>.*$)')
    re_mac_check = re.compile(r'((?:[0-9a-fA-F]:?){12})')
    re_os_details = re.compile(r'OS details: (?P<os>[^,]+)')
    re_running_os = re.compile(r'Running: (?P<os>[^,]+)')
    re_os_guess = re.compile(r'OS guesses: (?P<os>[^,]+)')
    re_devtype = re.compile(r'Device type: (?P<device>.+)')

    file_lines = []
    with open(filepath, 'r') as f:
        file_lines = f.readlines()

    # Add the most recent scan to raw_scan
    ip_state['raw_scan'] = '\n'.join(file_lines)

    for line in file_lines:
        line = line.strip()

        port_match = re_port.search(line)
        if port_match:
            ip_ports = ip_state.get('ports', {})

            new_pnum = port_match.group('num')
            new_pprot = port_match.group('protocol')
            new_pstate = port_match.group('state')
            new_pservice = port_match.group('service')
            new_pversion = port_match.group('version')

            port_dict = {
                'number': new_pnum,
                'protocol': new_pprot,
                'state': new_pstate,
                'service': new_pservice,
                'version': new_pversion,
                'last seen': dt_now,
                }

            ip_ports[new_pnum] = port_dict
            ip_state['ports'] = ip_ports

        mac_match = re_mac_check.search(line)
        if mac_match:
            ip_state['mac'] = mac_match.group()

        osdetail_match = re_os_details.search(line)
        osrun_match = re_running_os.search(line)
        osguess_match = re_os_guess.search(line)
        if osdetail_match:
            ip_state['os'] = osdetail_match.group('os')
        elif osrun_match:
            ip_state['os'] = osrun_match.group('os')
        elif osguess_match:
            ip_state['os'] = osguess_match.group('os')

        dev_match = re_devtype.search(line)
        if dev_match:
            ip_state['device'] = dev_match.group('device')

    STATE[ip] = ip_state



"""settings.
    Scans the given IP (str) and saves the results to a file in {SCAN_DIR}/{ip}.txt
    If the file exists, it clobbers it -- updates with latessettings.t data
    No return data
"""
def scan_ip(ip):
    file_path = '{}/{}.txt'.format(settings.SCAN_DIR, ip)
    cmd = 'sudo {} -sV -O --osscan-guess {} > {}'.format(settings.NMAP_PATH, ip, file_path)
    logger.debug('Scanning IP: {}. Results will be saved to {}'.format(ip, file_path))
    call(cmd, shell=True)
    set_scan_state(ip, file_path)


"""
    Given an IP file, scan all ips in the file
"""
def scan_ips(ip_f_path):

    ip_list = []
    with open(ip_f_path, "r") as f:
        for line in f:
            ip_list.append(line.strip())

    for ip in ip_list:
        scan_ip(ip)


"""
    Main run of the scanner.
    Finds ips, saves them to file, scans the IPs if its a first run or if something changed
    Saves results to file
"""
def run_scanner():

    load_state()

    # Scan network for IPs
    ip_path = find_ips()

    # Get list of IP files saved for last X days (default is 7)
    ip_f_list = _get_ip_files()

    if something_changed(ip_f_list[-1], ip_f_list[-2]):
        logger.debug('Last IP ({}) file and new ({}) on are different. Scanning: {}'.format(
            ip_f_list[-1], ip_f_list[-2], ip_path))
        scan_ips(ip_path)

    save_state()


if __name__ == "__main__":
    logger.debug('Network Scanner Started Up')
    start_time = time.time()

    try:
        run_scanner()
    except Exception as e:
        logger.error('Program exited. Exception Occurred. {}'.format(e))

    duration = time.time() - start_time
    logger.debug('Network Scanner Run Complete. Scan took {0:.0f} seconds.'.format(duration))






























