#!/bin/bash

# NOTE: This grabs the HOME directory from the settings.py file
homedir=$(cat settings.py | grep 'HOME = ' | cut -d' ' -f3 | tr -d '"');
echo "Serving dashboard locally from directory: ${homedir}";

# NOTE: -b 127.0.0.1 8080 binds the server to the local loopback, so only this host can access it.
/bin/python -m http.server -b 127.0.0.1 8080  --d ${homedir}
