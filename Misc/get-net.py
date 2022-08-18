# Purpose:  REST API call to Prism Central to find network uuid from nic_name
#
# Author: Dusty Lane <dusty.lane@nutanix.com>
# Date Created:  06/15/2021
# Date Modified:  08/24/2021
# Modified by:  Dusty Lane <dusty.lane@nutanix.com>
# Change log:  modified to use requests python module.
# Change log:  added payload length to 
#
# Version: 1.1

###################### modules ######################

import requests
import re
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

###################### DECLARE VARIABLES ######################
username = '@@{prism_central.username}@@'
username_secret = '@@{prism_central.secret}@@'

infobloxnetfull = '@@{network}@@'

clustername = '@@{calm_environment_name}@@'

url = "https://localhost:9440/api/nutanix/v3/subnets/list"

# we need to split our infoblox cidr
infobloxnetarray = infobloxnetfull.split('/')
infobloxnet = infobloxnetarray[0]

###################### LAUNCH APP ############################

headers = {'content-type': 'application/json'}

# compose the json payload
payload = {
  	"kind": "subnet",
    "offset": 0,
    "length": 1024
}

try:
    entities = json.loads((requests.post(url=url, headers=headers, auth=HTTPBasicAuth(username, username_secret), data=json.dumps(payload), verify=False)).content)
except:
    print("API Request failed")
    exit(1)

#print(json.dumps(entities, indent=3))

for entity in entities['entities']:
    if re.search (infobloxnet, entity['spec']['name']):
        if re.search (clustername, entity['spec']['cluster_reference']['name']):
            nic_name = entity['spec']['name']

            print("Network {} found in array.".format(nic_name))
            # capture variables
            net_uuid = entity['metadata']['uuid']
            netdata = {'name': nic_name, 'uuid': net_uuid}

# test variable exists
try:
    netdata
    print("Found AHV network ({}) matching {} network.".format(nic_name,infobloxnet))
except:
    # fail if network not found in vsphere
    print ("Failed to find network matching: {} in Prism.".format(infobloxnet))
    exit(1)

# return variables
print('dynamic_network={}'.format(json.dumps(netdata)))

exit(0)
