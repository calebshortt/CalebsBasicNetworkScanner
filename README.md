

# Caleb's Basic Network Scanner (CBNS)

This is a simple network scanner. It uses nmap to find IPs on your home network, then port scans them.
It saves the results to a JSON file, and to individual files for analysis.
The JSON file is used by the local server to power the dashboard (dashboard.html)

![alt text](img/screencap.jpeg)


## General Flow

    1. Run scanner (or set up a daemon to run every few hours)
    2. Once at least one successful scan is complete, start the local server (servelocally.sh)
    3. Go to ```localhost:8080/dashboard.html```

## Usage

### Run The CBNS

- ```$> sudo python3 basic_network_scanner.py```
    - This will take some time.
    - You can view the logs in the networkscanner.log file
        - ```$> tail networkscanner.log -f -n100```

### Run The Dashboard

1. ```$> ./servelocally.sh```
    - NOTE: This script will take the HOME directory from settings.py and host it.
    - NOTE: This script assumes that ```/bin/python``` exists. Modify accordingly if required.

2. Open browser and go to ```localhost:8080/dashboard.html```
    - NOTE: At least one run must have been completed and a state.json file created from it.


## Requirements

- Python 3
- nmap
- A Linux Operating System (Though the scripts can be modified to work with Windows)
