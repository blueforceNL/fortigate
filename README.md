# Fortigate

This script tries to retrieve the model and serial number of a Fortigate appliance from the device certificate.<br>
The management port (TCP 541) must be open and reachable.


**Usage:**

./fortigate.py <ip|fqdn>


**Example:**

./fortigate.py 192.2.0.1
Fortigate model and s/n: FGTxxxxxxxxxxxxx, device certificate expiry: Jan 01 01:00:00 2030 GMT


**Dependencies:**

fortigate.py requires the following python3 modules:<br>
socket, ssl, sys, os, OpenSSL


**Reference**

For more information about Fortigate appliances or Fortinet see: https://www.fortinet.com/
