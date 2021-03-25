========================================================
        Move VM from Protection Domain to Category
========================================================
- Use included params.json as API request parameters
- List all VMs that are entities within an existing Protection Domain
- Remove those VMs from an existing Protection Domain
- Assign the same VMs to the category category


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

        --param_file_format : param file info

        --dry_run : dry run will not be the actual run ,
        it will just show more like report what will happen once the execution will be done.


    ========= EXAMPLES =========

    --help :
        cmd >> python3 move_vms.py param.json --help

    --dry_run :
        cmd >> python3 move_vms.py param.json --dry_run

    ***** In order to execute don't use any option:
        cmd >> python3 move_vms.py param.json

===================
       Logs
===================
- The logs will be generated in logs directory having the filename logs_<timestamp> i.e log_2020_09_21-20_16_03

=============================