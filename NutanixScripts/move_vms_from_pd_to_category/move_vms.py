"""
The goal is to get all of the VMs in the PD, remove those VMs,
then add those VMs to a category which then would be a v3 call to PC
"""

from dataclasses import dataclass
import requests
import urllib3
import argparse
import getpass
import getopt
import json
from base64 import b64encode
import sys
import os
import time
from requests.auth import HTTPBasicAuth
from collections import defaultdict
import datetime

TGREEN =  '\033[32m'  # Green Text
TYELLOW = '\033[33m'
TBLUE =  '\033[34m'
TWHITE = '\033[37m'  # White Text
TCYAN = '\033[36m'
TRED = '\033[31m'  # RED
ENDC = '\033[m' # reset to the defaults
resources_password_map = {}


class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        curdatetime = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
        filename = f"log_{curdatetime}"
        self.log = open(f"logs/{filename}", "w")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        #this flush method is needed for python 3 compatibility.
        #this handles the flush command by doing nothing.
        #you might want to specify some extra behavior here.
        pass

@dataclass
class RequestParameters:
    """
    dataclass to hold the parameters of our API request
    this is not strictly required but can make
    our requests cleaner
    """
    uri: str
    username: str
    password: str
    payload: list
    method: str


class RequestResponse:
    """
    class to hold the response from our
    requests
    again, not strictly necessary but can
    make things cleaner later
    """

    def __init__(self):
        self.code = 0
        self.message = ""
        self.json = ""
        self.details = ""

    def __repr__(self):
        '''
        decent __repr__ for debuggability
        this is something recommended by Raymond Hettinger
        it is good practice and should be left here
        unless there's a good reason to remove it
        '''
        return (f'{self.__class__.__name__}('
                f'code={self.code},'
                f'message={self.message},'
                f'json={self.json},'
                f'details={self.details})')


class RESTClient:
    """
    the RESTClient class carries out the actual API request
    by 'packaging' these functions into a dedicated class,
    we can re-use instances of this class, resulting in removal
    of unnecessary code repetition and resources
    """

    def __init__(self, parameters: RequestParameters):
        """
        class constructor
        because this is a simple class, we only have a single
        instance variable, 'params', that holds the parameters
        relevant to this request
        """
        self.params = parameters

    def __repr__(self):
        '''
        decent __repr__ for debuggability
        this is something recommended by Raymond Hettinger
        '''
        return (f'{self.__class__.__name__}('
                f'username={self.params.username},password=<hidden>,'
                f'uri={self.params.uri}',
                f'payload={self.params.payload})')

    def send_request(self):
        """
        this is the main method that carries out the request
        basic exception handling is managed here, as well as
        returning the response (success or fail), as an instance
        of our RequestResponse dataclass
        """
        response = RequestResponse()

        """
        setup the HTTP Basic Authorization header based on the
        supplied username and password
        done this way so that passwords are not supplied on the command line
        """
        username = self.params.username
        password = self.params.password
        encoded_credentials = b64encode(
            bytes(f"{username}:{password}", encoding="ascii")
        ).decode("ascii")
        auth_header = f"Basic {encoded_credentials}"

        """
        setup the request headers
        note the use of {auth_header} i.e. the Basic Authorization
        credentials we setup earlier
        """

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{auth_header}",
            "cache-control": "no-cache",
        }

        try:

            if self.params.method == 'get':
                # submit a GET request
                api_request = requests.get(
                    self.params.uri,
                    headers=headers,
                    auth=HTTPBasicAuth(username, password),
                    timeout=10,
                    verify=False
                )
            elif self.params.method == 'post' or self.params.method == 'put':
                # submit a POST request
                api_request = requests.post(
                    self.params.uri,
                    headers=headers,
                    auth=HTTPBasicAuth(username, password),
                    timeout=1000,
                    verify=False,
                    data=self.params.payload
                )

            elif self.params.method == '_put':
                # submit a PUT request
                api_request = requests.put(
                    self.params.uri,
                    headers=headers,
                    auth=HTTPBasicAuth(username, password),
                    timeout=1000,
                    verify=False,
                    data=self.params.payload
                )
            # if no exceptions occur here, we can process the response
            response.code = api_request.status_code
            response.message = "Request submitted successfully."
            response.json = api_request.json()
            response.details = "N/A"
        except requests.exceptions.ConnectTimeout:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -99
            response.message = f"Connection has timed out."
            response.details = "Exception: requests.exceptions.ConnectTimeout"
        except urllib3.exceptions.ConnectTimeoutError:
            # timeout while connecting to the specified IP address or FQDN
            response.code = -99
            response.message = f"Connection has timed out."
            response.details = "urllib3.exceptions.ConnectTimeoutError"
        except requests.exceptions.MissingSchema:
            # potentially bad URL
            response.code = -99
            response.message = "Missing URL schema/bad URL."
            response.details = "N/A"
        except requests.exceptions.ReadTimeout:
            response.code = -99
            response.message = "The server did not send any data in the allotted amount of time."
            response.details = "N/A"
        except requests.exceptions.URLRequired:
            response.code = -99
            response.message = "A valid URL is required to make a request."
            response.details = "N/A"
        except requests.exceptions.TooManyRedirects:
            response.code = -99
            response.message = "Too many redirects."
            response.details = "N/A"
        except requests.exceptions.HTTPError:
            response.code = -99
            response.message = "An HTTP error occurred."
            response.details = "N/A"
        except requests.exceptions.Timeout:
            response.code = -99
            response.message = "Timeout error."
            response.details = "N/A"
        except requests.exceptions.SSLError:
            response.code = -99
            response.message = "An SSL error occurred."
            response.details = "N/A"
        except requests.exceptions.InvalidURL:
            response.code = -99
            response.message = "The URL provided was somehow invalid."
            response.details = "N/A"
        except requests.exceptions.InvalidHeader:
            response.code = -99
            response.message = "The header value provided was somehow invalid."
            response.details = "N/A"
        except requests.exceptions.InvalidProxyURL:
            response.code = -99
            response.message = "The proxy URL provided is invalid."
            response.details = "N/A"
        except Exception as _e:
            """
            Some unexpected error has been occurred.
            """
            if response.code == 401:
                response.code = -99
                response.message = "Username/Password is incorrect!!!!. Please enter valid credentials.\n"
            else:
                response.code = -99
                response.message = "Please retry, Some unexpected error has occurred.\n"
            response.details = "N/A"

        return response


def usage():
    return """
    ========================================================
            Move VM from Protection Domain to Category
    ========================================================
    - Use included params.json as API request parameters
    - List all VMs that are entities within an existing Protection Domain
    - Remove those VMs from an existing Protection Domain
    - Assign the same VMs to the category as specified in params.json


    =====================
        Requirements
    =====================

    - Python >=3.6 (lower versions will NOT work)
    - pip3 (for dependencies installation)
    - Tested on Python 3.6, 3.7 and 3.8
    - Clone repo to your local machine
    - Setup a virtual environment on Linux or Mac (strongly recommended):

       .. code-block:: python

          python3.8 -m venv venv
          . venv/bin/activate

    - Setup a virtual environment on Windows (strongly recommended):

       .. note:: See https://docs.python.org/3/library/venv.html for Windows instructions

    - ****** Install the dependencies ******:
        pip3 install requests
        pip3 install urllib3

    - Adjust values in **params.json** to match your Prism Element, Prism Central, Protection Domain and category settings
    - Run the script:
          python3.8 move_vms.py params.json
          
    ====================
        PARAMS FILE
    ====================
    
    Pass all the resource information into the resource spec in the current directory with file name  params.json
    
    Resource spec contains list of resources (Cluster IP ,Cluster username, Prism  Central IP, PC user), protection_domain & category pairs.
        -   pd_cat_pairs:   Contains dictionary having list protection_domains and category  to which all the VMs in the mentioned PDs will be moved.
        
    SAMPLE:
    
        {
              "resources_spec":[
                {
                  "cluster_ip": "xx.xx.xx.xx",
                  "cluster_user": "admin",
                  "pc_ip": "xx.xx.xx.xx",
                  "pc_user": "admin",
                  "pd_cat_pairs": [
                    {"protection_domains":["pd1","pd2","pd3"], "category":"name1:value1"},
                    {"protection_domains":["pd4"], "category":"name2:value2"}
                  ]
                },
                {
                  "cluster_ip": "xx.xx.xx.xx",
                  "cluster_user": "admin",
                  "pc_ip": "xx.xx.xx.xx",
                  "pc_user": "admin",
                  "pd_cat_pairs": [
                    {"protection_domains":["pd1","pd2","pd3"], "category":"name1:value1"},
                    {"protection_domains":["pd4"] ,"category":"name2:value2"}
                  ]
                }
              ]
        }

    ===================
           Usage
    ===================

        OPTIONS:

            --help : help information

            --dry_run : dry run will not be the actual run ,
            it will just show more like report what will happen once the execution will be done.


        ========= EXAMPLES =========

        --help :
            cmd >> python3 move_vms.py params.json  --help

        --dry_run :
            cmd >> python3 move_vms.py params.json --dry_run
            
        ***** In order to execute don't use any option:
            cmd >> python3 move_vms.py params.json
        

        =============================

    """

def create_category(pc_ip, pc_user, pc_password,
                    category_name, category_value, category_description=None):

    ########################################
    # Create if the category doesn't exist #
    ########################################

    category_info_parameters = RequestParameters(
        uri=f'https://{pc_ip}:9440/api/nutanix/v3/categories/{category_name}',
        username=pc_user,
        password=pc_password,
        payload=[],
        method='get'
    )

    rest_client = RESTClient(category_info_parameters)
    response = rest_client.send_request()

    if response.code == 404:
        print(f"Creating the category ({category_name}: {category_value}) ")

        if category_description is None:
            _category_description=category_name

        category_create_name_payload = {
            "name": category_name,
            "description": _category_description,
        }
        category_create_name_parameters = RequestParameters(
            uri=f'https://{pc_ip}:9440/api/nutanix/v3/categories/{category_name}',
            username=pc_user,
            password=pc_password,
            payload=json.dumps(category_create_name_payload),
            method='_put'
        )

        rest_client = RESTClient(category_create_name_parameters)
        rest_client.send_request()

        ### Attaching value with the category

        attach_value_with_category_payload={
            "value": category_value,
            "description": _category_description
        }

        attach_value_with_category_parameters = RequestParameters(
            uri=f'https://{pc_ip}:9440/api/nutanix/v3/categories/{category_name}/{category_value}',
            username=pc_user,
            password=pc_password,
            payload=json.dumps(attach_value_with_category_payload),
            method='_put'
        )
        rest_client = RESTClient(attach_value_with_category_parameters)
        rest_client.send_request()

        print(f"The category ({category_name}: {category_value}) has been created SUCCESSFULLY !!!\n")
    else:
        print(f"The category ({category_name}: {category_value}) already exist .")

def get_vm_name_from_uuids(pc_ip,pc_username,pc_password,vm_uuids=None):
    uuids = "|".join(vm_uuids)
    vm_group_payload = {
      "entity_type": "vm",
     "filter_criteria": f"_entity_id_=in={uuids}",
      "group_member_attributes": [
      {"attribute": "vm_name"}
      ]
    }

    vm_info_parameters = RequestParameters(
        uri=f'https://{pc_ip}:9440/api/nutanix/v3/groups',
        username=pc_username,
        password=pc_password,
        payload=json.dumps(vm_group_payload),
        method='post'
    )

    rest_client = RESTClient(vm_info_parameters)
    response = rest_client.send_request().json
    vm_names = []
    count = response["filtered_entity_count"]
    for i in range(count):
        group_result = response["group_results"][0]["entity_results"][i]["data"]
        for data in group_result:
            if data["name"] == "vm_name":
                vm_names.append(data["values"][0]["values"][0])
    return vm_names


def get_vm_from_vg(cluster_ip,cluster_username,cluster_password,pc_ip,pc_username,pc_password,vg_list=None):
    vg_vm_map = {}
    vg_info_parameters = RequestParameters(
        uri=f'https://{cluster_ip}:9440/PrismGateway/services/rest/v2.0/volume_groups',
        username=cluster_username,
        password=cluster_password,
        payload=[],
        method='get'
    )
    rest_client = RESTClient(vg_info_parameters)
    response = rest_client.send_request()
    for vg in response.json["entities"]:
        uuid_list = []
        if vg["name"] in vg_list:
            if "attachment_list" in vg.keys() :
                [uuid_list.append(vm["vm_uuid"]) for vm in vg["attachment_list"]]
        if uuid_list:
            vg_vm_map[vg["name"]] = get_vm_name_from_uuids(pc_ip,pc_username,pc_password,uuid_list)
    return vg_vm_map if vg_vm_map else None

def vms_consistency_map(pc_ip,pc_username,pc_password,vm_uuids=None):
    uuids = "|".join(vm_uuids)
    cg_vm_map = defaultdict(list)
    vm_group_payload = {
        "entity_type": "vm",
        "filter_criteria": f"_entity_id_=in={uuids}",
        "group_member_attributes": [
            {"attribute": "vm_name"},
            {"attribute": "consistency_group_name"}
        ]
    }

    vm_info_parameters = RequestParameters(
        uri=f'https://{pc_ip}:9440/api/nutanix/v3/groups',
        username=pc_username,
        password=pc_password,
        payload=json.dumps(vm_group_payload),
        method='post'
    )

    rest_client = RESTClient(vm_info_parameters)
    response = rest_client.send_request().json

    group_results = response["group_results"][0]["entity_results"]
    for results in group_results:
        if results["data"][1]["values"]:

            key = results["data"][1]["values"][0]["values"][0]
            value = results["data"][0]["values"][0]["values"][0]

            cg_vm_map[key].append(value)

    return cg_vm_map

def pd_schedule_info(cluster_ip,cluster_username,cluster_password,protection_domain):
    parameters = RequestParameters(
        uri=f"https://{cluster_ip}:9440/api/nutanix/v2.0/protection_domains/{protection_domain}",
        username=cluster_username,
        password=cluster_password,
        payload=[],
        method='get'
    )
    rest_client = RESTClient(parameters)
    # get the entities that belong to the specified PD
    response = rest_client.send_request().json
    op_str = []
    op_str.append(f"\nSchdeule defined in the given protection domain {protection_domain} : ")
    for res in response["cron_schedules"]:
        op_str.append("  "+str(res["every_nth"]) + " " +str(res["type"]))
    return op_str

def get_prs_attached_to_given_category(pc_ip,pc_username,pc_password,category_name,category_value):
    payload_info = {
        "usage_type": "USED_IN",
        "category_filter": {
            "kind_list": [
                "protection_rule"
            ],
            "type": "CATEGORIES_MATCH_ANY",
            "params": {
                category_name: [category_value]
            }
        },
        "api_version": "3.1.0"
    }
    parameters = RequestParameters(
        uri=f"https://{pc_ip}:9440/api/nutanix/v3/category/query",
        username=pc_username,
        password=pc_password,
        payload=json.dumps(payload_info),
        method='post'
    )
    rest_client = RESTClient(parameters)
    # get the entities that belong to the specified PD
    response = rest_client.send_request().json
    op_str = ""
    if "results" in response.keys():
        if response["results"]:
            pr_uuid = response["results"][0]['kind_reference_list'][0]['uuid']
            pr_name = response["results"][0]['kind_reference_list'][0]["name"]
            op_str = op_str + f"Given category : ({category_name}:{category_value}) is attached to the protection rule : {pr_name} \n"
        else:
            return f"No Protection Rule is attached to the category : ({category_name}:{category_value})"

    parameters = RequestParameters(
        uri=f"https://{pc_ip}:9440/api/nutanix/v3/protection_rules/{pr_uuid}",
        username=pc_username,
        password=pc_password,
        payload=[],
        method='get'
    )
    rest_client = RESTClient(parameters)
    # get the entities that belong to the specified PD
    response = rest_client.send_request().json
    rpo_time = response["status"]["resources"]["availability_zone_connectivity_list"][0]["snapshot_schedule_list"][0][
        "recovery_point_objective_secs"]
    op_str += f"\nSchdeule defined in the the pr {pr_name} : \n  {rpo_time//3600} HOURLY"
    return op_str


def dry_run(path_to_param_file):
    # get the time the script started

    """
    suppress warnings about insecure connections
    you probably shouldn't do this in production
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    """
    setup our command line parameters
    for this example we only require the a single parameter
    - the name of the JSON file that contains our request parameters
    this is a very clean way of passing parameters to this sort of
    script, without the need for excessive parameters on the command line

    parser = argparse.ArgumentParser()
    parser.add_argument("json", help="listparms")
    args = parser.parse_args()
    """

    """
    try and read the JSON parameters from the supplied file
    """
    data = ""
    try:
        with open(f"{path_to_param_file}", "r") as params:
            data = json.load(params)
    except FileNotFoundError:
        print(f"{path_to_param_file} parameters file not found.")
        sys.exit()
    except json.decoder.JSONDecodeError:
        print("\nThe provided JSON file cannot be parsed.")
        print("Please check the file contains valid JSON, then try again.\n")
        sys.exit()

    for json_data in data["resources_spec"]:

        #######################################
        # gather some info before carrying on #
        #######################################
        info = []
        try:
            cluster_ip = json_data["cluster_ip"]
            cluster_user = json_data["cluster_user"]
            pc_ip = json_data["pc_ip"]
            pc_user = json_data["pc_user"]
            pd_cat_pairs = json_data["pd_cat_pairs"]

        except KeyError:
            print('Required key was not found in the specified JSON parameters file.  Exiting ...')
            sys.exit()

        # get the cluster password
        cluster_password = getpass.getpass(
            prompt=f"\nCluster IP: {cluster_ip} , Cluster User: {cluster_user} \n\nPlease enter your cluster password: ",
            stream=None
        )
        # get the PC password
        pc_password = getpass.getpass(
            prompt=f"\nPrism Central IP: {pc_ip} , Prism Central User: {pc_user} \n\nPlease enter your Prism Central password: ",
            stream=None
        )
        resources_password_map[cluster_ip] = cluster_password
        resources_password_map[pc_ip] = pc_password
        # for this test script we're just going to assume both PE and PC authenticate as 'admin'
        print(
            TCYAN + "============================================================================================================================================" + ENDC)
        print(f"#########    Resources Information   ############")
        print(f"#   Cluster IP : {cluster_ip}")
        print(f"#   Cluster Username : {cluster_user}")
        print(f"#   Prism Central IP : {pc_ip}")
        print(f"#   Cluster Username : {pc_user}")
        print(f"################################################\n")
        for pd_cat_pair in pd_cat_pairs:
            protection_domains, category = \
                pd_cat_pair['protection_domains'], pd_cat_pair['category']

            # extract the category name and value from the value specified via JSON parameters file
            category_name, category_value = category.split(":")
            for protection_domain in protection_domains:
                # setup the parameters for the initial request
                parameters = RequestParameters(
                    uri=f"https://{cluster_ip}:9440/api/nutanix/v2.0/protection_domains/{protection_domain}",
                    username=cluster_user,
                    password=cluster_password,
                    payload=[],
                    method='get'
                )
                rest_client = RESTClient(parameters)
                # get the entities that belong to the specified PD
                get_pd_entities_response = rest_client.send_request()
                if get_pd_entities_response.code != 200:
                    print(f"There is no protection domain : {protection_domain}")
                    continue

                ##############################################
                # see if there are any entities to work with #
                # if there aren't, there's no point going    #
                # any further                                #
                ##############################################

                vm_count = len(get_pd_entities_response.json['vms'])
                if vm_count == 0:
                    print(f'PD {protection_domain} has no existing entities.  Nothing to do.')
                    continue

                """
                create the list containing all VM names and UUIDs
                these VMs are existing members of the specified PD
                """
                vm_names = []
                vm_uuids = []
                vm_details = []
                for vm in get_pd_entities_response.json['vms']:
                    vm_names.append(vm['vm_name'])
                    vm_uuids.append(vm['vm_id'])
                    vm_details.append({'uuid': vm['vm_id'], 'name': vm['vm_name']})



                ##############################################
                # Validation check                           #
                #    For entities which can't be part of     #
                #     PD to Category i.e Volume groups       #
                ##############################################
                warning_dict = {}

                ### Volume group
                if get_pd_entities_response.json['volume_groups']:
                    warning_dict["Volume group"] = []
                    for vg in get_pd_entities_response.json['volume_groups']:
                        warning_dict["Volume group"].append(vg["name"])

                ### NFS Files

                if get_pd_entities_response.json['nfs_files']:
                    warning_dict["NFS Files"] = []
                    for nfs_files in get_pd_entities_response.json['nfs_files']:
                        warning_dict["NFS Files"].append(nfs_files["name"])

                ### vStore ID
                if get_pd_entities_response.json['vstore_id']:
                    warning_dict["vStore Id"] = []
                    for vstore_ids in get_pd_entities_response.json['vstore_id']:
                        warning_dict["vStore Id"].append(vstore_ids["name"])

                print(TGREEN + "############################    INFORMATION   ################################################\n"+ENDC)
                print(
                     f"VMs associated with the protection domain - {protection_domain}, will be moved to "
                             f"category - ({category_name}:{category_value}) are as follows : \n")
                print(f" , ".join(vm_names))
                print("\n".join(pd_schedule_info(cluster_ip, cluster_user, cluster_password, protection_domain)))
                print("\n")
                print(
                    get_prs_attached_to_given_category(pc_ip, pc_user, pc_password, category_name, category_value))
                print("\n")
                if vms_consistency_map(pc_ip, pc_user, pc_password, vm_uuids):
                    print("\nBelow shown entities are list of VMs associated with the CGs \n")
                    print(dict(vms_consistency_map(pc_ip, pc_user, pc_password, vm_uuids)))
                print(TGREEN + "\n###########################################################################################" + ENDC)

                if warning_dict:
                    print(
                        TYELLOW + f"The VMs in the protection domain :{protection_domain} can't be migrated to LEAP due to following Error. " + ENDC)
                    print("\n")
                    print(TRED + "########################     ***********ERROR***********   ##########################\n" + ENDC)

                    print(f"Below shown entities associated with PD : {protection_domain} ,"
                                f" wont be preserved after migrating to LEAP. \n\n    {warning_dict} \n")




                    if "Volume group" in warning_dict.keys():
                        print(
                            "\nBelow shown VMs which are associated with the volume groups and these volume groups wont be preserved after migrating to LEAP : \n")
                        vg_list = warning_dict["Volume group"]
                        vg_vm_map = get_vm_from_vg(cluster_ip, cluster_user, cluster_password, pc_ip, pc_user,
                                                   pc_password, vg_list)
                        print(vg_vm_map)

                    if "NFS Files" in warning_dict.keys():
                        print(warning_dict["NFS Files"])

                    if "vStore Id" in warning_dict.keys():
                        print(warning_dict["vStore Id"])

                    print(
                        TRED + "#######################################################################################\n" + ENDC)

                print(
                    TBLUE + "======================================================================================================================" + ENDC)
                print("\n")
        print(
            TCYAN + "============================================================================================================================================" + ENDC)


def run(path_to_param_file):
    # get the time the script started
    start_time = time.time()

    """
    suppress warnings about insecure connections
    you probably shouldn't do this in production
    """
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    """
    try and read the JSON parameters from the supplied file
    """
    try:
        with open(f"{path_to_param_file}", "r") as params:
            data = json.load(params)
    except FileNotFoundError:
        print(f"{args.json} parameters file not found.")
        sys.exit()
    except json.decoder.JSONDecodeError:
        print("\nThe provided JSON file cannot be parsed.")
        print("Please check the file contains valid JSON, then try again.\n")
        sys.exit()

    for json_data in data["resources_spec"]:

        #######################################
        # gather some info before carrying on #
        #######################################
        try:
            cluster_ip = json_data["cluster_ip"]
            cluster_user = json_data["cluster_user"]
            pc_ip = json_data["pc_ip"]
            pc_user = json_data["pc_user"]
            pd_cat_pairs = json_data["pd_cat_pairs"]


        except KeyError:
            print('Required key was not found in the specified JSON parameters file.  Exiting ...')
            sys.exit()

        print(f'\nCluster IP : {cluster_ip}')
        print(f'Cluster Username : {cluster_user}')

        # get the cluster password
        cluster_password = resources_password_map[cluster_ip]


        print(f'Prism Central IP : {pc_ip}')
        print(f'Prism Central Username : {pc_user}\n')

        # get the PC password

        pc_password = resources_password_map[pc_ip]

        for pd_cat_pair in pd_cat_pairs:
            protection_domains, category = \
                pd_cat_pair['protection_domains'], pd_cat_pair['category']

            # extract the category name and value from the value specified via JSON parameters file
            category_name, category_value = category.split(":")

            for protection_domain in protection_domains:

                # setup the parameters for the initial request
                parameters = RequestParameters(
                    uri=f"https://{cluster_ip}:9440/api/nutanix/v2.0/protection_domains/{protection_domain}",
                    username=cluster_user,
                    password=cluster_password,
                    payload=[],
                    method='get'
                )
                rest_client = RESTClient(parameters)
                # get the entities that belong to the specified PD
                get_pd_entities_response = rest_client.send_request()

                """
                check that the first request was successful
                if it wasn't, there's no point continuing as it means later requests will also fail
                """

                if get_pd_entities_response.code == -99:
                    print(get_pd_entities_response.message)
                    print(get_pd_entities_response.details)
                    sys.exit()

                print(f'\nGetting entities that belong to PD named {protection_domain} ...')
                ##############################################
                # see if there are any entities to work with #
                # if there aren't, there's no point going    #
                # any further                                #
                ##############################################

                vm_count = len(get_pd_entities_response.json['vms'])
                if vm_count == 0:
                    print(f'PD {protection_domain} has no existing entities.Nothing to do.')
                    continue
                elif vm_count == 1:
                    print(f'\n1 VM will be reconfigured.\n')
                else:
                    print(f'\n{vm_count} VMs will be reconfigured.\n')

                """
                create the list containing all VM names and UUIDs
                these VMs are existing members of the specified PD
                """
                vm_names = []
                vm_uuids = []
                vm_details = []
                for vm in get_pd_entities_response.json['vms']:
                    vm_names.append(vm['vm_name'])
                    vm_uuids.append(vm['vm_id'])
                    vm_details.append({'uuid': vm['vm_id'], 'name': vm['vm_name']})

                ##############################################
                # Validation check                           #
                #    For entities which can't be part of     #
                #     PD to Category i.e Volume groups       #
                ##############################################
                warning_dict = {}

                ### Volume group
                if get_pd_entities_response.json['volume_groups']:
                    warning_dict["Volume group"] = []
                    for vg in get_pd_entities_response.json['volume_groups']:
                        warning_dict["Volume group"].append(vg["name"])

                ### NFS Files

                if get_pd_entities_response.json['nfs_files']:
                    warning_dict["NFS Files"] = []
                    for nfs_files in get_pd_entities_response.json['nfs_files']:
                        warning_dict["NFS Files"].append(nfs_files["name"])

                ### vStore ID
                if get_pd_entities_response.json['vstore_id']:
                    warning_dict["vStore Id"] = []
                    for vstore_ids in get_pd_entities_response.json['vstore_id']:
                        warning_dict["vStore Id"].append(vstore_ids["name"])

                print(
                    TGREEN + "############################    INFORMATION   ################################################" + ENDC)
                print(
                    f"VMs associated with the protection domain - {protection_domain} ,will be moved to "
                    f"category -  {category_name} : {category_value} are as follows : ")
                print(f" , ".join(vm_names))
                print("\n".join(pd_schedule_info(cluster_ip, cluster_user, cluster_password, protection_domain)))
                print("\n")
                print(
                    get_prs_attached_to_given_category(pc_ip, pc_user, pc_password, category_name, category_value))
                print("\n")
                if vms_consistency_map(pc_ip, pc_user, pc_password, vm_uuids):
                    print("\nBelow shown entities are list of VMs associated with the Consistency groups \n")
                    print(dict(vms_consistency_map(pc_ip, pc_user, pc_password, vm_uuids)))
                print(
                    TGREEN + "\n############################################################################################" + ENDC)

                if warning_dict:
                    print(TRED+f"The VMs in the protection domain :{protection_domain} will not to be moved from legacy PD to LEAP as following entities wont be preserved after migration"+ENDC)
                    print("\n")
                    print(TYELLOW + "###########################     *********** WARNINGs ***********   ############################\n" + ENDC)

                    print(f"Below shown entities associated with PD : {protection_domain} ,"
                                f" wont be preserved after migrating to LEAP. \n\n    {warning_dict} \n")

                    if "Volume group" in warning_dict.keys():
                        print(
                            "\nVMs mapping with Volume group :\n")
                        vg_list = warning_dict["Volume group"]
                        vg_vm_map = get_vm_from_vg(cluster_ip, cluster_user, cluster_password, pc_ip, pc_user,
                                                   pc_password, vg_list)
                        print(vg_vm_map)

                    print(
                        TYELLOW + "############################################################################################\n" + ENDC)
                    print(
                        TBLUE + "======================================================================================================================" + ENDC)
                    print("\n")
                    continue




                ##############################
                # delete the VMs from the PD #
                ##############################

                # at this point we have confirmed there is at least 1 VM in the PD
                ### Custom : Validation check

                remove_vm_parameters = RequestParameters(
                    uri=f'https://{cluster_ip}:9440/api/nutanix/v2.0/protection_domains/{protection_domain}/unprotect_vms',
                    username=cluster_user,
                    password=cluster_password,
                    payload=json.dumps(vm_names),
                    method='post'
                )
                rest_client = RESTClient(remove_vm_parameters)
                print(f'Removing VMs from PD {protection_domain} ...')
                remove_response = rest_client.send_request()
                print('Done.\n')

                ########################################
                # Create if the category doesn't exist #
                ########################################

                create_category(pc_ip,pc_user,pc_password,category_name,category_value)

                ###############################
                # add the VMs to the category #
                ###############################

                """
                for each of the VMs in the PD we now need to do a few things
                we need to add the spec, the api_version and the metadata to the individual VM payload
                then add the category information to the individual VM payload
                the final step is to add the VM payload to the api_request_list of the main PUT payload
                """

                """
                start building the PUT request payload
                this first batch request will get info about all VMs in the PD
                """

                get_vm_info_put_payload = {
                    "action_on_failure": "CONTINUE",
                    "execution_order": "SEQUENTIAL",
                    "api_request_list": [],
                    "api_version": "3.0",
                    "length": 500000
                }

                """
                build the payload for getting each VM's info
                it is cleaner to do this with the batch API than "manually" running individual vms API requests
                """
                all_vms_details = []
                batch_size_limit = 60   ## MAX SIZE SUPPORTED is 60.
                temp_list = []
                for i in range(len(vm_details)):
                    if i != 0 and i % batch_size_limit == 0:
                        all_vms_details.append(temp_list)
                        temp_list = []
                        temp_list.append(vm_details[i])
                    else:
                        temp_list.append(vm_details[i])
                if temp_list:
                    all_vms_details.append(temp_list)


                for vm_details in all_vms_details:
                    get_vm_info_put_payload['api_request_list'] = []
                    for vm in vm_details:
                        # get the VM info
                        vm_info_payload = {
                            'operation': "GET",
                            'path_and_params': f"/api/nutanix/v3/vms/{vm['uuid']}",
                            'body': {}
                        }
                        get_vm_info_put_payload['api_request_list'].append(vm_info_payload)


                    # setup the request parameters
                    vm_info_parameters = RequestParameters(
                        uri=f'https://{pc_ip}:9440/api/nutanix/v3/batch',
                        username=pc_user,
                        password=pc_password,
                        payload=json.dumps(get_vm_info_put_payload),
                        method='post'
                    )
                    rest_client = RESTClient(vm_info_parameters)
                    # send the request
                    print(f'Running batch request to get VM info ...')
                    info_response = rest_client.send_request()
                    print('Done.\n')

                    # build the categories part of the PUT request payload
                    category_payload = {f'{category_name}': f'{category_value}'}

                    """
                    start building the PUT request payload
                    this second batch request will add the VMs to the specified category
                    """
                    update_vm_category_put_payload = {
                        "action_on_failure": "CONTINUE",
                        "execution_order": "SEQUENTIAL",
                        "api_request_list": [],
                        "api_version": "3.0",
                        "length": 500000

                    }

                    """
                    now that we have spec, metadata etc for each VM in the PD,
                    we can construct the batch request to add each of those VMs
                    to the specified category
                    """
                    print(f'Building batch request payload before updating categories ...')

                    for api_response in info_response.json['api_response_list']:
                        update_vm_payload = {
                            'operation': 'PUT',
                            'path_and_params': f'{api_response["path_and_params"]}',
                            'body': {}
                        }
                        update_vm_payload['body']['spec'] = api_response['api_response']['spec']
                        update_vm_payload['body']['api_version'] = api_response['api_response']['api_version']
                        update_vm_payload['body']['metadata'] = api_response['api_response']['metadata']
                        update_vm_payload['body']['metadata']['categories'] = category_payload
                        update_vm_category_put_payload['api_request_list'].append(update_vm_payload)
                    print('Done.\n')

                    # setup the request parameters
                    vm_update_parameters = RequestParameters(
                        uri=f'https://{pc_ip}:9440/api/nutanix/v3/batch',
                        username=pc_user,
                        password=pc_password,
                        payload=json.dumps(update_vm_category_put_payload),
                        method='post'
                    )
                    rest_client = RESTClient(vm_update_parameters)
                    # send the request
                    print(f'Adding VMs to category "{category_name}:{category_value}" ...')
                    update_response = rest_client.send_request()
                    print('Done.\n')

                    # format and display the results of the batch request
                    for api_response in update_response.json['api_response_list']:
                        print(
                            f"HTTP code {api_response['status']} | State {api_response['api_response']['status']['state']} "
                            f"| VM {api_response['api_response']['spec']['name']}")
            print("============================================================================================")
            print(
                TBLUE + "======================================================================================================================" + ENDC)
            print("\n")



    print('\nAll operations finished (%.2f seconds)' % (time.time() - start_time))


if __name__ == '__main__':
    if not os.path.exists('logs'):
        os.makedirs('logs')
    sys.stdout = Logger()
    args_len = len(sys.argv)
    if args_len > 2:
        try:
            argv = sys.argv[2:]
            opts, args = getopt.getopt(argv, "dry_run:h",
                                       ["dry_run", "help"])

            for opt, arg in opts:
                if opt in ['-h', '--help']:
                    print(usage())
                    sys.exit(0)
                elif opt in ['-dry_run', '--dry_run']:
                    script_dir = os.path.dirname(os.path.realpath(__file__))
                    path_to_param_file = f"{script_dir}/{sys.argv[1]}"
                    dry_run(path_to_param_file)
                    sys.exit(0)
                else:
                    print(usage())
                    sys.exit(0)

        except getopt.GetoptError as err:
            print("-----------------ERROR MESSAGE------------------------------------")
            print(err)
            print(usage())
            sys.exit(0)
    elif args_len == 2:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        path_to_param_file = f"{script_dir}/{sys.argv[1]}"
        print("\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  DRY RUN  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        dry_run(path_to_param_file)
        print(
            "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  END %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        print(
            TYELLOW + "Above is the dry run output." + ENDC)
        print(TGREEN + "Since its an irreversible process make sure you have reviewed the the above dry run output."+ENDC)
        input_val = input("\nAre you sure you want to proceed ? (y/n) :  ")
        if input_val in ['y', 'yes', 'Y']:
            print(
                "\n%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  ACTUAL RUN  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
            run(path_to_param_file)
            print(
                "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  END %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        else:
            print(usage())
            sys.exit(0)
    else:
        print("""
        #########################################################
        # INVALID    NUMBER/TYPE   OF    ARGUMENTS   ARE PASSED  !!! #
        ######################################################### 
         """)
        print()
        print(usage())
