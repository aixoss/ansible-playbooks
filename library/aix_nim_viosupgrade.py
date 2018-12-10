#!/usr/bin/python
#
# Copyright 2018, International Business Machines Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

############################################################################
"""AIX NIM viosupgrade: tool to upgrade VIOSes in NIM environment"""

import os
import re
import subprocess
import threading
import logging
import time
import distutils.util

# Ansible module 'boilerplate'
from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = """
---
module: nim_upgradeios
authors: Vianney Robin, Alain Poncet, Pascal Oliva
short_description: Perform upgrade operation on a list of targets
using viosupgrade (perl) tool
"""


# -----------------------------------------------------------------------------
def exec_cmd(cmd, module, exit_on_error=False, debug_data=True, shell=False):

    """
    Execute the given command

    Note: If executed in thread, fail_json does not exit the parent

    args:
        - cmd           array of the command parameters
        - module        the module variable
        - exit_on_error use fail_json if true and cmd return !0
        - debug_data    prints some trace in DEBUG_DATA if set
        - shell         execute cmd through the shell if set (vulnerable to shell
                        injection when cmd is from user inputs). If cmd is a string
                        string, the string specifies the command to execute through
                        the shell. If cmd is a list, the first item specifies the
                        command, and other items are arguments to the shell itself.
    return
        - ret    return code of the command
        - output output and stderr of the command
        - errout command stderr
    """

    global DEBUG_DATA
    global CHANGED
    global OUTPUT

    ret = 0
    output = ''
    errout = ''

    th_id = threading.current_thread().ident
    stderr_file = '/tmp/ansible_upgradeios_cmd_stderr_{}'.format(th_id)

    logging.debug('command:{}'.format(cmd))
    if debug_data is True:
        DEBUG_DATA.append('exec_cmd:{}'.format(cmd))
    try:
        myfile = open(stderr_file, 'w')
        output = subprocess.check_output(cmd, stderr=myfile, shell=shell)
        myfile.close()
        s = re.search(r'rc=([-\d]+)$', output)
        if s:
            ret = int(s.group(1))
            output = re.sub(r'rc=[-\d]+\n$', '', output)  # remove the rc of c_rsh with echo $?

    except subprocess.CalledProcessError as exc:
        myfile.close()
        errout = re.sub(r'rc=[-\d]+\n$', '', exc.output)  # remove the rc of c_rsh with echo $?
        ret = exc.returncode

    except OSError as exc:
        myfile.close()
        errout = re.sub(r'rc=[-\d]+\n$', '', exc.args[1])  # remove the rc of c_rsh with echo $?
        ret = exc.args[0]

    except IOError as exc:
        # generic exception
        myfile.close()
        msg = 'Command: {} Exception: {}'.format(cmd, exc)
        ret = 1
        module.fail_json(changed=CHANGED, msg=msg, output=OUTPUT)

    # check for error message
    if os.path.getsize(stderr_file) > 0:
        myfile = open(stderr_file, 'r')
        errout += ''.join(myfile)
        myfile.close()
    os.remove(stderr_file)

    if debug_data is True:
        DEBUG_DATA.append('exec_cmd rc:{}, output:{} errout:{}'
                          .format(ret, output, errout))
        logging.debug('retrun rc:{}, output:{} errout:{}'
                      .format(ret, output, errout))

    if ret != 0 and exit_on_error is True:
        msg = 'Command: {} RetCode:{} ... stdout:{} stderr:{}'\
              .format(cmd, ret, output, errout)
        module.fail_json(changed=CHANGED, msg=msg, output=OUTPUT)

    return (ret, output, errout)


# ----------------------------------------------------------------
def get_ios_mksysb(module):

    """
    Get all resources of type ios_mksysb and the associated
    spot resources and ioslevel
    defined on the nim master.
    Arguments:
        module: {}
    Return: info_hash = {}
        info_hash[ios_mksysb_name]['spot'] = (String)spot_name
        info_hash[ios_mksysb_name]['ioslevel'] = (String)ioslevel
    """
    global CHANGED
    global OUTPUT
    info_hash = {}
    cmd = 'LC_ALL=C lsnim -t ios_mksysb -l'
    (ret, std_out, std_err) = exec_cmd(cmd, module, shell=True)
    if ret != 0:
        msg = 'Cannot list NIM ios_mksysb objects: {}'.format(std_err)
        logging.error(msg)
        module.fail_json(changed=CHANGED, msg=msg, meta=OUTPUT)
        # mksysb_name name and associated spot
        ios_mksysb_name = ""
    for line in std_out.split('\n'):
        line = line.strip()
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            ios_mksysb_name = match_key.group(1)
            info_hash[ios_mksysb_name] = {}
            continue

        match_key = re.match(r"^ioslevel\s+=\s+(.*)$", line)
        if match_key:
            ioslevel = match_key.group(1)
            info_hash[ios_mksysb_name]['ioslevel'] = ioslevel
            continue
        match_key = re.match(r"^extracted_spot\s+=\s+(.*)$", line)
        if match_key:
            spot = match_key.group(1)
            info_hash[ios_mksysb_name]['spot'] = spot
            continue

    logging.debug('ios_mksysb={}'.format(info_hash))
    return info_hash


# ----------------------------------------------------------------
def get_nim_user_res(module):

    """
    Get the list of resources of type resolv_conf, script,
    fb_script, file_res, image_data, and log
    defined on the nim master.
    Arguments:
        module: {}

    Return: Dictionary of reources key=name valu=type
    type=resolv_conf|script|fb_script|file_res|image_data|and log
    """
    global CHANGED
    global OUTPUT
    std_out = ''
    nim_user_res = {}

    cmd = 'LC_ALL=C lsnim -t resolv_conf; lsnim -t script; lsnim -t fb_script; '\
        'lsnim -t file_res; lsnim -t image_data; lsnim -t log'
    (ret, std_out, std_err) = exec_cmd(cmd, module, shell=True)
    if ret != 0:
        msg = 'Cannot list NIM resource: {}'.format(std_err)
        logging.error(msg)
        module.fail_json(changed=CHANGED, msg=msg, meta=OUTPUT)

    for line in std_out.split('\n'):
        line = line.strip()
        match_key = re.match(r"^(\S+)\s+\S+\s+(\S+)$", line)
        if match_key:
            nim_user_res[match_key.group(1)] = match_key.group(2)
            continue

    return nim_user_res


# ----------------------------------------------------------------
def get_nim_clients_info(module):
    """
    Get the list of vios defined on the nim master, and get their
    associated cstate and hostname.
    Arguments:
        module: {}
    Return: info_hash = {}
        info_hash[vios_name]['cstate'] = (String) vios cstate
        info_hash[vios_name]['host_name'] = (String) hostname to access vios
    """
    global CHANGED
    global OUTPUT
    std_out = ''
    info_hash = {}

    cmd = 'LC_ALL=C lsnim -t vios -l'
    (ret, std_out, std_err) = exec_cmd(cmd, module, shell=True)
    if ret != 0:
        msg = 'Cannot list NIM vios objects: {}'.format(std_err)
        logging.error(msg)
        module.fail_json(changed=CHANGED, msg=msg, meta=OUTPUT)

    vios_name = ""
    for line in std_out.split('\n'):
        line = line.strip()
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            vios_name = match_key.group(1)
            info_hash[vios_name] = {}
            continue

        match_cstate = re.match(r"^Cstate\s+=\s+(.*)$", line)
        if match_cstate:
            cstate = match_cstate.group(1)
            info_hash[vios_name]['cstate'] = cstate
            continue

        # Get VIOS interface info in case we need c_rsh
        match_if = re.match(r"^if1\s+=\s+\S+\s+(\S+)\s+.*$", line)
        if match_if:
            info_hash[vios_name]['vios_ip'] = match_if.group(1)
            continue

    return info_hash


# ----------------------------------------------------------------
def get_cluster_status(module, vios):

    """
    get the status of the vios node in the cluster of vios
    Arguments:
        module: {}
        vios: {}
    Return: integer 0 or 1
    """

    rc = 1
    if not vios["cluster_id"]:
        return 0
    # get cluster status
    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', vios["host_name"],
           'LC_ALL=C /usr/ios/cli/ioscli cluster -status -fmt :']
    # 'LC_ALL=C /usr/ios/cli/ioscli cluster -status -field '\
    # 'node_name node_state pool_state node_upgrade_status -verbose"']
    (ret, std_out, std_err) = exec_cmd(cmd, module)
    # parse std_out
    for line in std_out.split('\n'):
        line = line.strip()
        match_key = re.match(r"^(\S+):(\S+):(\S+):(\S+):(\d+):(\S+):(.*)", line)
        if match_key:
            if match_key.group(6) == "DOWN" or match_key.group(7) == "DOWN":
                return 1
            else:
                rc = 0
    return rc


# ----------------------------------------------------------------
def get_viosupgrade_status(module, vios):

    """
    Run lsnim command to get the vios status during upgrade process
    set vios["status"]   = DONE | RUNNING | ERROR
    Arguments:
        module: {}
        vios: {}
    Return: String status = DONE | RUNNING | ERROR
    """
    global ERROR
    global RUNNING
    global DONE
    status = RUNNING
    std_out = ""
    cmd = 'LC_ALL=C /usr/sbin/lsnim -l {}'.format(vios["name"])
    (ret, std_out, std_err) = exec_cmd(cmd, module, shell=True)
    if ret != 0:
        msg = 'Viosupgrade error on vios: {}  :{}'\
                    .format(vios["name"], std_err)
        logging.error(msg)
        status = ERROR
        vios["status"] = ERROR
    else:
        # parse std_out
        # wait for strings:
        #   Cstate        = ready for a NIM operation
        #   Mstate        = currently running
        #   Cstate_result = success
        #   info          =  m..e..s..s..a..g..e..
        #   err_info      =  m..e..s..s..a..g..e..
        Mstate = ""
        Cstate = ""
        Cstate_result = ""
        info = ""
        for line in std_out.split('\n'):
            line = line.strip()
            match_key = re.match(r"^(\S+)\s+=\s+(.*)", line)
            if match_key:
                if match_key.group(1) == "Mstate":
                    Mstate = match_key.group(2)

                if match_key.group(1) == "Cstate":
                    Cstate = match_key.group(2)

                if match_key.group(1) == "Cstate_result":
                    Cstate_result = match_key.group(2)

                if match_key.group(1) == "info":
                    info = match_key.group(2)
                    continue
                if match_key.group(1) == "err_info":
                    status = ERROR
                    vios["status"] = ERROR
                    messages = std_out.split("\n", 1)
                    OUTPUT.append("NIM error info {})".format(messages[0]))
                    for line in messages[1].split("\n"):
                        OUTPUT.append(line)
                    return status

        if not info and Cstate == "ready for a NIM operation"\
           and (Cstate_result == "success" or Cstate_result == "reset")\
           and (Mstate == "currently running" or Mstate == "ready for use"):
            status = DONE
        else:
            status = RUNNING
        vios["status"] = status
    return status


# ----------------------------------------------------------------
def build_viosupgrade_cmd(vios, validate):

    """
    Build the viosupgrade command for a specific vios
    with apropriate parameters in a restricted use.

    viosupgrade -t bosinst -n hostname -m mksysbname -p spotname
        {-a RootVGCloneDisk: ... | -s} [-c] [-e Resources: ...] [-v]

    viosupgrade -t altdisk -n hostname -m mksysb_name -a RootVGCloneDisk
        [-c] [-e Resources: ...] [-v]

    Used Flags:
    -t      Specifies the type of install. Supported types are: bosinst, altdisk.
    -n      Specifies the target VIOS hostname or IP address to perform VIOS upgrade operation.
    -m      Specifies the MKSYSB resource name.
    -p      Specifies the SPOT resource name.
    -a      Specifies the alternate physical volume. if install type is 'bosinst' then
            the disk(s) will be used to take backup of current rootvg.
            For 'altdisk' type installation disk(s) will be used to install the provided image.
    -s      Specify to skip cloning of the current rootvg disk(s) to alternate disk(s).
    -c      Specify if VIOS is part of the cluster.
    -e      Specifies configuration resource(s) to apply as part of the installation.
        supported resources are resolv_conf, script, fb_script, file_res, image_data, log.
    -v      Validates the input data for the given VIO Server(s).

    Not Used Flags:
    -b      Specifies VIOS configuration backup file resource name.
    -r      Specifies the new rootvg physical volume to install the provided image.
    -f      Specifies file name which contains the list of nodes.
    -q      Check the status of triggered upgrade operation.

    Arguments:
        vios: {} Dictionary of attributes for the vios object
        validate: boolean

    return: string command with flags and parameters
    """
    cmd = '/usr/sbin/viosupgrade -t {} -n {} -m {} '\
        .format(vios["action"], vios["name"], vios["ios_mksysb"])
    if vios["action"] == "bosinst":
        cmd = cmd + " -p " + vios["spot"]
    if len(vios["user_res"]) != 0:
        cmd = cmd + " -e "
        for res in vios["user_res"]:
            cmd = cmd + res + ":"
    if vios["cluster_id"] != "":
        cmd = cmd + " -c"

    if vios["alt_disk"] != "":
        cmd = cmd + " -a " + re.sub(' +', ':', vios["alt_disk"])
    elif vios["skip"] is True:
        cmd = cmd + " -s"
    if validate:
        cmd = cmd + " -v"
    return cmd


# ----------------------------------------------------------------
def validate_vios(module, vios):
    """
    Validate the execution of the viosupgrade command
    Arguments:
        module: {} dictionary
        vios: {} dictionary of attributes of vios object
    Return: integeger 0 --> OK  !=0  --> NOK
    """
    global ERROR
    global READY

    rc = 0
    cmd = build_viosupgrade_cmd(vios, validate=True)
    (rc, std_out, std_err) = exec_cmd(cmd, module, shell=True)
    if rc != 0:
        msg = 'Viosupgrade error on vios: {} :{}:{}'\
            .format(vios["name"], std_out, std_err)
        logging.error(msg)
        vios["status"] = ERROR
    else:
        vios["status"] = READY
    return rc


# ----------------------------------------------------------------
def validate_tuple(module, tuple, tuple_key, upgrade_status):
    """
    validate the execution of viosupgrade command for a list of vios
    beloonging to the same cluster or deserving the same lpar
    and set the result in upgrade_status dict

    Arguments:
        module:
        tuple: {} dictionary ov vioses
        tuple_key: String: "vioses with space separator"
        upgrade_status: {} key: tuple_key,  value:tuple status
    Return: Integer  0 --> OK
    """
    rc = 0
    for vios in tuple.values():
        rc = validate_vios(module, vios)
        if rc != 0:
            upgrade_status[tuple_key] = ERROR
            return rc
    upgrade_status[tuple_key] = READY
    return rc


# ----------------------------------------------------------------
def viosupgrade(module, tuples, upgrade_status):
    """
    Execute the viosupgrade command on all vios of all targets selected
    in the tuples dictionary
    In parallel all targets but sequentialy each vios of one target
    set the status of tuples in upgrade_status dict
    Arguments:
        module: {}
        tuples: {}
        upgrade_status: {}
    Return: Integer: number of error
    """
    global CHANGED
    global ERROR
    global READY
    global RUNNING
    global DONE
    TIMEOUT = 5400  # 1 H 30 Min
    LOOP_TIME = 90  # 1 Min 30 Sec
    nb_error = 0
    CONTINUE = True
    while CONTINUE:     # continue while at least one tuple is not done even not in error
        loop_start = int(time.time())
        CONTINUE = False
        for tuple_key in tuples.keys():
            tuple = tuples[tuple_key]
            if upgrade_status[tuple_key] == ERROR or upgrade_status[tuple_key] == DONE:
                continue    # go to next tuple
            elif upgrade_status[tuple_key] == READY:
                validate_tuple(module, tuple, tuple_key, upgrade_status)
            if upgrade_status[tuple_key] == ERROR:
                continue    # go to next tuple
            CONTINUE = True
            vioses = tuple_key.split()
            nb_vioses = len(vioses)
            for index, vios_name in enumerate(vioses):
                vios = tuple[vios_name]
                previous_vios = {}
                if index != 0:
                    previous_vios = tuple[vioses[index - 1]]
                # if vios is ready ant it is the first or the previous is done
                # then start migration
                if vios["status"] == READY:
                    if index == 0 or previous_vios["status"] == DONE:
                        # now run the upgrade command.
                        cmd = build_viosupgrade_cmd(vios, False)
                        (ret, std_out, std_err) = exec_cmd(cmd, module, shell=True)
                        if ret != 0:
                            msg = 'Viosupgrade error on vios: {}  :{}'\
                                .format(vios_name, std_err)
                            logging.error(msg)
                            upgrade_status[tuple_key] = ERROR
                            vios["status"] = ERROR
                            nb_error += 1
                            break   # break vioses loop and go to next tuple
                        upgrade_status[tuple_key] = RUNNING
                        vios["status"] = RUNNING
                        start_time = int(time.time())
                        vios["loop_time"] = start_time
                        vios["start_time"] = start_time
                        break   # break vioses loop and go to next tuple

                # if vios is running then test real state
                if vios["status"] == RUNNING:
                    actual_time = int(time.time())
                    # wait until LOOP_TIME in sec since last test
                    if actual_time < vios["loop_time"] + LOOP_TIME:
                        # sleep until loop_time + LOOP_TIME in sec
                        time.sleep(vios["loop_time"] + LOOP_TIME - loop_start)
                        actual_time = vios["loop_time"] + LOOP_TIME
                    # test real status an change the status if reqiured then continue
                    # Query to get the status of the upgrade for each target
                    status = get_viosupgrade_status(module, vios)
                    if status == ERROR:
                        vios["status"] = ERROR
                        upgrade_status[tuple_key] = ERROR
                        upgrade_status[tuple_key] = ERROR
                        nb_error += 1
                        break
                    if status == DONE:
                        if get_cluster_status(module, vios) != 0:
                            status = RUNNING
                    vios["loop_time"] = actual_time
                    vios["status"] = status
                    # set tuple in error if TimeOut
                    if status == RUNNING and (actual_time > vios["start_time"] + TIMEOUT):
                        vios["status"] = ERROR
                        upgrade_status[tuple_key] = ERROR
                        upgrade_status[tuple_key] = ERROR
                        break   # break vioses loop and go to next tuple

                # if vios is migrated --> next vios
                if vios["status"] == DONE:
                    CHANGED = True
                    # if last vios is migrated  set tuple to migrated --> next tuple
                    if index == (len(vioses) - 1):
                        upgrade_status[tuple_key] = DONE
                        # End of vios loop, go to the next tuple
                    # else:
                    # continue # loop on the next vios
    return nb_error


###################################################################################

if __name__ == '__main__':
    DEBUG_DATA = []
    OUTPUT = []
    NIM_NODE = {}
    CHANGED = False
    VARS = {}
    ERROR = "ERROR"
    READY = "READY"
    RUNNING = "RUNNING"
    DONE = "DONE"
    REJECTED = "REJECTED"
    nb_error = 0

    MODULE = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),

            # IBM automation generic attributes
            targets=dict(required=True, type='list'),
            actions=dict(required=True, type='dict'),
            vars=dict(required=False, type='dict'),
            vios_status=dict(required=False, type='dict'),
            nim_node=dict(required=False, type='dict'),

            # following attributes are dictionaries with
            # key: 'all_vios' or hostname and value: a string or boolean
            # example:
            # ios_mksysb={"target1": "mksysb_name_1", "target2": "mksysb_name_2"}
            # ios_mksysb={"all_vios": "mksysb_name", "target2": "mksysb_name_2"}
            ios_mksysb=dict(required=True, type='dict'),
            # force={"all_vios": False, "target_x": True}
            force=dict(required=False, type='dict'),
            alt_disk=dict(required=False, type='dict'),
            # Resources (-e option) The valid resource type are:
            # resolv_conf, script, fb_script, file_res, image_data, and log
            # Dictionary with key: 'all_vios' or hostname and value: string
            # exemple: user_res={"all_vios": "resolv_conf_name", "vios_name": "file_res_name"}
            # in that exemple the viosupgrade will be called with -e resolv_conf_name:file_res_name
            user_res=dict(required=False, type='dict'),
        ),
    )

    # =========================================================================
    # Get Module params
    # =========================================================================

    msg = ""
    user_res = {}
    alt_disk = {}
    targets = MODULE.params['targets']
    actions = MODULE.params['actions']
    ios_mksysb = MODULE.params['ios_mksysb']
    force = MODULE.params['force']
    nim_user_res = []
    REQUIRED_IOSLEVEL = "2.2.6.30"
    # Handle playbook variables
    LOGNAME = '/tmp/ansible_upgradeios_debug.log'
    if MODULE.params['vars']:
        VARS = MODULE.params['vars']
        if'log_file' in VARS.keys():
            LOGNAME = VARS['log_file']
    if MODULE.params['vios_status']:
        tuples_status = MODULE.params['vios_status']
    else:
        vios_status = None
    # Open log file
    OUTPUT.append('Log file: {}'.format(LOGNAME))
    LOGFRMT = '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s'
    logging.basicConfig(
        filename='{}'.format(LOGNAME), format=LOGFRMT,
        level=logging.DEBUG)

    logging.debug('*** START NIM VIOSUPGRADE OPERATION ***')
    logging.debug('VIOSUpgrade operation for tagets:{}'.format(targets))

    OUTPUT.append('VIOSUpgrade operation for {}'.format(targets))
    # build mksysb - spot table. spot is needed (if action = bosinst)
    mksysb_htab = get_ios_mksysb(MODULE)
    # build NIM node info (if needed)
    if MODULE.params['nim_node']:
        NIM_NODE = MODULE.params['nim_node']
    else:
        NIM_NODE['nim_vios'] = get_nim_clients_info(MODULE)
    logging.debug('NIM VIOS: {}'.format(NIM_NODE['nim_vios']))
    if MODULE.params['user_res']:
        user_res = MODULE.params['user_res']
        # get all existing user_res from nim server
        # The valid types are: resolv_conf, script, fb_script, file_res, image_data, and log.
        nim_user_res = get_nim_user_res(MODULE)
    if MODULE.params['alt_disk']:
        alt_disk = MODULE.params['alt_disk']

    # if health check status is known remove tuple with wrong status
    # build the list of target matching nim client list
    # remove duplicates
    # check vios connectivity and get ClusterID
    # get altinst_rootvg disk
    # remove tuples without c_rsh connectivity
    # exclude tuples with different clusterID
    # remove tuple having the same clusterID than an other tuple
    # remove tuple having unsuficient ioslevel
    all_targets = list(set(MODULE.params['targets']))   # remove duplicates tuples
    all_targets = [elem.replace(',', ' ').replace(':', ' ') for elem in all_targets]
    logging.debug("ALL_TARGETS = {}".format(all_targets))
    new_target_list = []
    all_vioses = []
    all_cluster_ids = []

    # build here the targets tuple structure
    tuples = {}
    # tuples = {}            # Dict: key = tuple  ex: "vios1 vios2"
    # tuples[tuple] = {}     # Dict: key = vios_name   ex: "vios1" or "vios2"
    # tuples[tuple][vios_name] = {}  # Dict: keys are "name", "cluster_id", "ios_mksysb"...
    # tuples[tuple][vios_name]["name"] = "" # String: <vios name>
    # tuples[tuple][vios_name]["host_name"] = "" # String: <host name> get from nim object
    # tuples[tuple][vios_name]["ip"] = "" # String: ip adress coresponding to host_name
    # tuples[tuple][vios_name]["interface"] = "" # String: interface configured wit ip
    # tuples[tuple][vios_name]["cluster_id"] = "" # String: <clusterID unique>
    # tuples[tuple][vios_name]["altinst_rootvg"] = "" # String: <altinst_rootvg disk>
    # tuples[tuple][vios_name]["rootvg"] = "" # String: <one of the rootvg disk>
    # tuples[tuple][vios_name]["level"] = "" # String: <vios level>
    # tuples[tuple][vios_name]["free_pv"] = {} # Dict: key = disk value = size
    # tuples[tuple][vios_name]["skip"] = Boolean: skip the alt disk copy operation
    # tuples[tuple][vios_name]["action"] = "" # String: <bosinst | altdisk>
    # tuples[tuple][vios_name]["ios_mksysb"] = "" # String: <ios_mksysb resource name>
    # tuples[tuple][vios_name]["spot"] = "" # String: <spot resource name>
    # tuples[tuple][vios_name]["alt_disk"] = "" # String: <disk name for clonning rootvg
    #                                                      or alternate disk for installation>
    # tuples[tuple][vios_name]["user_res"] = [] # Liste of resource name
    # tuples[tuple][vios_name]["status"] = "" # String: status to follow installation steps
    # tuples[tuple][vios_name]["start_time"] = 0 # Integer: viosupgrade start time from epoch
    # tuples[tuple][vios_name]["loop_time"] = 0 # Integer: viosupgrade start time from epoch

    upgrade_status = {}     # the key is the tuple string ex: "vios1 vios2"
    for tuple_key in all_targets:
        tuple = {}
        vioses = tuple_key.split()
        msg = ""
        cluster_id = ""

        if not (vios_status is None):
            if len(vioses) == 1 and vioses[0] in vios_status\
               and vios_status[vioses[0]] != 'SUCCESS-HC'\
               and ios_status[vioses[0]] != 'SUCCESS-ALTDC':
                OUTPUT.append("    {} vios skiped ({})"
                              .format(vioses[0], vios_status[vioses[0]]))
                logging.warn("{} vios skiped ({})"
                             .format(vioses[0], vios_status[vioses[0]]))
                upgrade_status[tuple_key] = vios_status[vioses[0]]
                continue
            if len(vioses) == 2:
                key1 = vioses[0] + "-" + vioses[1]
                key2 = vioses[1] + "-" + vioses[0]
                if key1 in vios_status.keys()\
                   and vios_status[key1] != 'SUCCESS-HC'\
                   and vios_status[key1] != 'SUCCESS-ALTDC':
                    OUTPUT.append("    {} vioses skiped ({})"
                                  .format(tuple_key, vios_status[key1]))
                    logging.warn("{} vioses skiped ({})"
                                 .format(tuple_key, vios_status[key1]))
                    upgrade_status[tuple_key] = vios_status[key1]
                    continue
                if key2 in vios_status.keys()\
                   and vios_status[key2] != 'SUCCESS-HC'\
                   and vios_status[key2] != 'SUCCESS-ALTDC':
                    OUTPUT.append("    {} vioses skiped ({})"
                                  .format(tuple_key, vios_status[key2]))
                    logging.warn("{} vioses skiped ({})"
                                 .format(tuple_key, vios_status[key2]))
                    vios_status[key1] = vios_status[key2]
                    upgrade_status[tuple_key] = vios_status[key2]
                    continue
                else:
                    OUTPUT.append("    {} vioses skiped (no previous status found)"
                                  .format(key1))
                    logging.warn("{} vioses skiped (no previous status found)"
                                 .format(key1))
                    upgrade_status[tuple_key] = "FAILURE-NO-PREV-STATUS"

        for vios_name in vioses:
            msg = ""
            vios = {}
            vios["name"] = vios_name
            vios["status"] = READY
            vios["altinst_rootvg"] = ""
            vios["rootvg"] = ""
            vios["alt_disk"] = ""
            vios["cluster_id"] = ""
            vios["host_name"] = ""
            vios["ip"] = ""
            vios["interface"] = ""
            vios["interface_type"] = ""
            vios["cluster_status"] = ""
            vios["skip"] = False
            vios["level"] = ""
            vios["start_time"] = 0
            vios["loop_time"] = 0
            vios["free_pv"] = {}
            tuple[vios_name] = vios

            if vios_name not in NIM_NODE['nim_vios']:
                msg = "vios: {} is not a nim client.".format(vios_name)
                upgrade_status[tuple_key] = "UNKNOWN-NIM-CLIENT"
            if vios_name in all_vioses:
                msg = "vios: {} is already in the list of targets."\
                        .format(vios_name)
                upgrade_status[tuple_key] = "DUPLICATE-VIOS"
            if msg:
                vios["status"] = upgrade_status[tuple_key]
                break   # vios loop

            cluster_id = ""
            vios["host_name"] = NIM_NODE['nim_vios'][vios_name]["vios_ip"]
            # get dominized host_name and ip @ of the vios
            cmd = 'LC_ALL=C /bin/host {}'.format(vios["host_name"])
            (ret, std_out, std_err) = exec_cmd(cmd, MODULE, False, True, True)
            if ret != 0:
                msg = 'skip target: {}, cannot get {} ip address.'\
                    .format(tuple_key, vios_name)
                break   # vios loop
            else:
                # parse stdout
                for line in std_out.split('\n'):
                    line = line.strip()
                    match_key = re.match(r"^(\S+)\s+\S+\s+(\d+.\d+.\d+.\d+)$", line)
                    if match_key:
                        vios["ip"] = match_key.group(2)
            rootvg_size = 0
            cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', vios["host_name"],
                   '"LC_ALL=C /etc/lsattr -El vioscluster0; /usr/bin/netstat -in;'
                   ' /usr/sbin/lsdev -c adapter -t sea -s pseudo -F name:description;'
                   ' /usr/ios/cli/ioscli lspv; /usr/ios/cli/ioscli ioslevel;'
                   ' /usr/ios/cli/ioscli lspv -free;'
                   ' /usr/ios/cli/ioscli cluster -status -field cluster_state"']
            (ret, std_out, std_err) = exec_cmd(cmd, MODULE)
            # check vios connectivity
            if ret != 0:
                msg = 'skip target: {}, cannot reach {} with c_rsh.'\
                    .format(tuple_key, vios_name)
                break   # vios loop
            else:
                # parse std_out and get clusterID, altinst_rootvg,
                # vios version, free pv, rootvg size
                for line in std_out.split('\n'):
                    line = line.strip()

                    # search cluster_id
                    if vios["cluster_id"] == "":
                        match_key = re.match(r"^cluster_id\s+(\S+).*", line)
                        if match_key:
                            cluster_id = match_key.group(1)
                            vios["cluster_id"] = cluster_id
                            if cluster_id in all_cluster_ids:
                                msg = '{}: an other node is allready belonginng'\
                                      'to the cluster with ID: {}.'.format(vios_name, cluster_id)
                                break   # parse std_out loop
                            if len(vioses) > 1\
                               and vios["cluster_id"] != tuple[vioses[0]]["cluster_id"]:
                                msg = '{}: vioses belong to different cluster"'.format(tuple_key)
                                break   # parse std_out loop
                            continue    # next line

                    # search vios hsot interface
                    if vios["interface"] == "":
                        match_key = re.match(r"^(\S+)\s+\d+\s+\S+\s+(\d+.\d+.\d+.\d+)\s+.*", line)
                        if match_key and match_key.group(2) == vios["ip"]:
                            interface = match_key.group(1)
                            vios["interface"] = interface.replace("en", "ent")
                            continue    # next line
                    # search SEA adapter
                    if vios["interface_type"] == "":
                        match_key = re.match(r"^(\S+):Shared Ethernet Adapter", line)
                        if match_key and match_key.group(1) == vios["interface"]:
                            vios["interface_type"] = "SEA"
                            continue    # next line

                    # search altinst_rootvg and rootvg disk name
                    if vios["altinst_rootvg"] == "" or vios["rootvg"] == "":
                        match_key = re.match(r"^(\S+)\s+(\S+)\s+(\S+).*", line)
                        if match_key and match_key.group(3) == "altinst_rootvg":
                            vios["altinst_rootvg"] = match_key.group(1)
                            vios["skip"] = True
                            continue    # next line
                        elif match_key and match_key.group(3) == "rootvg":
                            if vios["interface_type"] == "":
                                vios["interface_type"] = "OTHER"    # end of search SEA section
                            vios["rootvg"] = match_key.group(1)
                            continue    # next line

                    # search vios level
                    if vios["level"] == "":
                        match_key = re.match(r"^(\d+.\d+.\d+.\d+)$", line)
                        if match_key:
                            if match_key.group(1) >= REQUIRED_IOSLEVEL:
                                vios["level"] = match_key.group(1)
                            else:
                                msg = '{} ioslevel is {}, '\
                                    'the minimum required is {}'\
                                    .format(vios_name, match_key.group(1), REQUIRED_IOSLEVEL)
                                break   # parse std_out loop
                            continue    # next line

                    # search free pv
                    match_key = re.match(r"^(\S+)\s+(\S+)\s+(\d+)$", line)
                    if match_key:
                        vios["free_pv"][match_key.group(1)] = int(match_key.group(3), 10)
                        continue    # next line

                    # get cluster status
                    match_key = re.match(r"^Cluster\s+State:\s+(\S+)$", line)
                    if match_key:
                        vios["cluster_status"] = match_key.group(1)
                        continue    # next line
                    elif line == "Cluster does not exist.":
                        vios["cluster_status"] = "UNKOWN"
                        continue    # next line
                # end annalysis of command output

                if vios["cluster_id"] and vios["cluster_status"] != "OK":
                    msg = '{}, the cluster is not in the correct state to be upgraded.'\
                           .format(tuple_key)
                if msg:
                    break   # vios loop

            cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', vios["host_name"],
                   '"LC_ALL=C /usr/sbin/lqueryvg -p {} -At"'.format(vios["rootvg"])]
            (ret, std_out, std_err) = exec_cmd(cmd, MODULE)
            # check vios connectivity
            if ret != 0:
                msg = 'skip target: {}, cannot reach {} with c_rsh.'\
                    .format(tuple_key, vios_name)
                break   # vios loop
            else:
                total_pps = 0
                free_pps = 0
                pp_size = 0
                for line in std_out.split('\n'):
                    line = line.strip()
                    # search rootvg size
                    match_key = re.match(r"^PP Size:\s+(\d+).*", line)
                    if match_key:
                        pp_size = int(match_key.group(1))
                    match_key = re.match(r"^Total PPs:\s+(\S+).*", line)
                    if match_key:
                        total_pps = int(match_key.group(1))
                    match_key = re.match(r"^Free PPs:\s+(\S+).*", line)
                    if match_key:
                        free_pps = int(match_key.group(1))
                if pp_size == 0 or total_pps == 0:
                    msg = "Program Error"
                else:
                    # root vg size in Megabytes
                    rootvg_size = (total_pps - free_pps) * (2 ** (pp_size - 20))    # in Megabytes

                if msg:
                    vios["status"] = REJECTED
                    break   # vios loop

            force_install = False   # default value
            disks = ""
            action = ""
            mksysb = ""
            vios["user_res"] = []
            if vios_name in force.keys():
                force_install = force[vios_name]
            elif "all_vios" in force.keys():
                force_install = force["all_vios"]

            if vios_name in ios_mksysb.keys():
                mksysb = ios_mksysb[vios_name]
            elif "all_vios" in ios_mksysb.keys():
                mksysb = ios_mksysb["all_vios"]
            else:
                msg = '{}: no ios_mksysb property specified.'\
                    .format(vios_name)
                break   # vios loop
            vios["ios_mksysb"] = mksysb
            if mksysb not in mksysb_htab.keys():
                msg = '{}: The specified ios_mksysb: {} resource does not exist'\
                    .format(vios_name, mksysb)
                break   # vios loop
            elif mksysb_htab[mksysb]["ioslevel"] < "3.1.0.0":
                msg = '{}: the ios_mksysb level: {} {}, is insufficient.'\
                      ' The minimum level is 3.1.0.0'\
                    .format(vios_name, mksysb, mksysb_htab[mksysb]["ioslevel"])
                break   # vios loop
            elif mksysb_htab[mksysb]["ioslevel"] < vios["level"] and not force_install:
                msg = '{}: the ios_mksysb level {} {} should be greater than vios level {}.'\
                    .format(vios_name,  mksysb, mksysb_htab[mksysb]["ioslevel"], vios["level"])
                break   # vios loop
            elif mksysb_htab[mksysb]["ioslevel"] == vios["level"] and not force_install:
                vios["status"] = DONE
            if vios_name in actions.keys():
                action = actions[vios_name]
            elif "all_vios" in actions.keys():
                action = actions["all_vios"]
            else:
                msg = '{}: atcion property must be specified.'\
                    .format(vios_name)
                break   # vios loop
            vios["action"] = action
            if action != "bosinst" and action != "altdisk":
                msg = '{}: action type should be bosinst or altdisk.'\
                    .format(vios_name)
                break   # vios loop

            # a bosinst installation type needs a spot resource.
            if action == 'bosinst':
                if "spot" in mksysb_htab[mksysb].keys():
                    vios["spot"] = mksysb_htab[mksysb]["spot"]
                else:
                    msg = '{}: There is no defined spot for ios_mksysb '\
                          'resource: {}, the bosinst installation required one.'\
                        .format(vios_name, mksysb)
                    break   # vios loop
            # an aldisk installation requires that the ip interface is configured on a non SEA
            elif vios["interface_type"] == "SEA":
                msg = '{}: altdisk method is not supported on a VIOS defined with SEA interface.'\
                    .format(vios_name)
                break   # vios loop
            res_list = []
            if vios_name in user_res.keys():
                res_list = user_res[vios_name].split()
            if "all_vios" in user_res.keys():
                res_list.extend(user_res["all_vios"].split())
            res_list = list(set(res_list))
            vios["user_res"] = res_list
            for res in res_list:
                if res not in nim_user_res.keys():
                    msg = '{}: the resource {} does not exist or is not '\
                          'an authorized  nim resource.'\
                        .format(vios_name, res)
                    break
                if action == 'altdisk' and nim_user_res[res] == "file_res":
                    msg = '{}: the resource {} of type file_res is not '\
                        'supported for altdisk type installation.'\
                        .format(vios_name, res)
                    logging.warning(msg)
            if msg:
                break   # vios loop

            if vios_name in alt_disk.keys():
                disks = alt_disk[vios_name].strip()
            elif "all_vios" in alt_disk.keys():
                disks = alt_disk["all_vios"].strip()
            if disks:
                disks = disks.replace(':', ' ').replace(',', ' ').strip()
                vios["alt_disk"] = disks
            if not disks and action == 'altdisk':
                msg = '{}: No alt_disk property is specified.'\
                    .format(vios_name)
                break   # vios loop
            elif not disks:
                if not vios["altinst_rootvg"]:
                    msg = '{}: The bosinst operation requires an altinst_rootvg.'\
                            'Create one or add the alt_disk property for this node.'\
                            .format(vios_name)
                    break   # vios loop
                else:
                    vios["skip"] = True

            # Reject vios and tuple if altinst_rootvg already exists
            # and alt_disk property is specified
            elif disks and vios["altinst_rootvg"]:
                msg = '{}: altinst_rootvg already exist, rename it.'.format(vios_name)
                if action == 'bosinst':
                    msg += ' Or remove the alt_disk property.'

            # test if alt_disks are free.
            # test the total size of alt_disks is enhougth for installation or clonne rootvg
            elif disks:
                d_lsit = disks.split()
                total_size = 0
                for disk in d_lsit:
                    if disk in vios["free_pv"].keys():
                        total_size += vios["free_pv"][disk]
                    else:
                        msg = '{}: the specified disk {} is not free'\
                            .format(vios_name, disk)
                        break   # test disk loop
                if msg:
                    break   # vios loop
                if total_size < 30720 and action == "altdisk":
                    msg = '{}: The total size of alternate disk(s) {}: {} '\
                        'is less than 30G. Choose disk(s) with adequate size.'\
                        .format(vios_name, disks, total_size)
                elif action == 'bosinst' and total_size < rootvg_size:
                    msg = '{}: The total size of alternate disk(s) {}: {} '\
                        'is less than the actual rootvg size {}.'\
                        'Choose disk(s) with adequate size.'\
                        .format(vios_name, disks, total_size, rootvg_size)
                if msg:
                    break   # vios loop
                vios["skip"] = False
            # end management disk size
        # end vios loop
        if msg:
            logging.warning(msg)
            OUTPUT.append(msg)
            msg = "Then the target: <{}> will not be selected for upgrade operation"\
                .format(tuple_key)
            logging.warning(msg)
            OUTPUT.append(msg)
            logging.debug('Rejected vios tuple: {} struct={}'.format(tuple_key, tuple))
            vios["status"] = REJECTED
            upgrade_status[tuple_key] = REJECTED
        else:
            all_vioses.extend(vioses)
            upgrade_status[tuple_key] = DONE
            for vios_name in vioses:
                if tuple[vios_name]["status"] == READY:
                    upgrade_status[tuple_key] = READY
                    tuples[tuple_key] = tuple
                    if cluster_id:
                        all_cluster_ids.append(cluster_id)
                    break
    # end tuple loop

    logging.debug('Remaining TARGETS={}'.format(tuples))

    MODULE.targets = all_targets
    OUTPUT.append('Remaining Targets list:{}'.format(tuples.keys()))

    if len(tuples.keys()) == 0:
        msg = 'All targets have been rejected. It remains no thing to do!'
        OUTPUT.append(msg)
        MODULE.exit_json(
            changed=False,
            msg=msg,
            nim_node=NIM_NODE,
            debug_output=DEBUG_DATA,
            output=OUTPUT,
            status=upgrade_status)

    nb_error = viosupgrade(MODULE, tuples, upgrade_status)

    # Prints vios status for each targets
    for tuple_key in upgrade_status:
        status = upgrade_status[tuple_key]
        msg = 'VIOSUpgrade operation on target: {} end with status: {}.'\
            .format(tuple_key, status)
        OUTPUT.append(msg)
        logging.info(msg)
        if status == DONE or status == ERROR:
            for vios_name in tuple_key.split():
                msg = 'VIOSUpgrade {} operation on {} status: {}.'\
                    .format(tuples[tuple_key][vios_name]["action"], vios_name,
                            tuples[tuple_key][vios_name]["status"])
                logging.info(msg)
                OUTPUT.append(msg)

    # Prints a global result statement
    if nb_error == 0:
        msg = 'VIOSUpgrade operation succeeded'
        OUTPUT.append(msg)
        logging.info(msg)
    else:
        msg = 'VIOSUpgrade operation failed: {} errors'.format(nb_error)
        OUTPUT.append(msg)
        logging.error(msg)

    # # =========================================================================
    # # Exit
    # # =========================================================================
    if nb_error == 0:
        MODULE.exit_json(
            changed=CHANGED,
            msg=msg,
            targets=MODULE.targets,
            output=OUTPUT,
            status=upgrade_status)
    else:
        MODULE.fail_json(
            changed=CHANGED,
            msg=msg,
            targets=MODULE.targets,
            debug_output=DEBUG_DATA,
            output=OUTPUT,
            status=upgrade_status)
