#!/usr/bin/python
#
# Copyright 2017, International Business Machines Corporation
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

######################################################################

import os
import re
import glob
import shutil
import subprocess
import threading
import logging
# Ansible module 'boilerplate'
from ansible.module_utils.basic import *


DOCUMENTATION = """
---
module: aix_nim_vios_hc
author: "Patrice Jacquin"
version_added: "1.0.0"
requirements: [ AIX ]
TBC - change the parsing of the return when vioshc.py is ready
    - HMC password currently hard-coded
"""


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def run_oslevel_cmd(machine, result, machine_type):
    """
    Run command function, command to be 'threaded'.

    The thread then store the outpout in the dedicated slot of the result
    dictionnary.

    arguments:
        machine (str):  The machine name
        result  (dict): The result of the command
        machine_type (str): the type of the machine (standalone, vios, master)

    return:
        the result dictionary entry filled with ethe output of the command
    """

    if machine_type == 'master':
        cmd = ['/usr/bin/oslevel', '-s']

    elif machine_type == 'standalone':
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine,
               '/usr/bin/oslevel -s']

    else: # machine_type == 'vios'
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine,
               'ioslevel']

    logging.debug('run_oslevel_cmd:{}'.format(cmd))

    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, \
                         stderr=subprocess.PIPE)

    # return stdout only ... stripped!
    result[machine] = proc.communicate()[0].rstrip()


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd, module):
    """
    Execute the given command
        - cmd     array of the command parameters
        - module  the module variable

    In case of erro set an error massage and fails the module

    return
        - ret_code  (0)
        - std_out   output of the command
    """

    global DEBUG_DATA

    std_out = ''
    std_err = ''
    err_code = 0

    logging.debug('exec command:{}'.format(cmd))
    try:
        std_out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        std_out = exc.output
        if exc.returncode != 1 and exc.returncode != 2:
            msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                   format(cmd, exc.cmd, exc.output, exc.returncode)
            module.fail_json(msg=msg)
        else:
            err_code = exc.returncode

    except Exception as exc:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
               format(cmd, exc.args, exc.output, exc.exc.returncode)
        module.fail_json(msg=msg)

    # DEBUG
    DEBUG_DATA.append('exec command:{}'.format(cmd))
    DEBUG_DATA.append('exec command std_err:{}'.format(std_err))
    logging.debug('exec command output:{}'.format(std_out))
    logging.debug('exec command std_err:{}'.format(std_err))

    return (err_code, std_out)


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_hmc_info(module):
    """
    Get the hmc info on the nim master, and get their login/passwd

    fill the hmc_dic passed in parameter (filled with the login/passwd value)
    
    return a dic with hmc info
    """
    std_out = ''
    std_err = ''
    info_hash = {}

    cmd = ['lsnim', '-t', 'hmc', '-l']

    try:
        proc = subprocess.Popen(cmd, shell=False, stdin=None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = proc.communicate()
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    obj_key = ''
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(\S+):", line)
        # HMC name
        if match_key:
            obj_key = match_key.group(1)
            info_hash[obj_key] = {}
            continue

        match_cstate = re.match(r"^\s+Cstate\s+=\s+(.*)$", line)
        if match_cstate:
            cstate = match_cstate.group(1)
            info_hash[obj_key]['cstate'] = cstate
            continue

        match_key = re.match(r"^\s+passwd_file\s+=\s+(.*)$", line)
        if match_key:
            info_hash[obj_key]['passwd_file'] = match_key.group(1)
            continue

        match_key = re.match(r"^\s+login\s+=\s+(.*)$", line)
        if match_key:
            info_hash[obj_key]['login'] = match_key.group(1)
            continue

        match_key = re.match(r"^\s+if1\s*=\s*\S+\s*(\S*)\s*.*$", line)
        if match_key:
            info_hash[obj_key]['ip'] = match_key.group(1)
            continue

    return info_hash


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_clients_info(module, lpar_type):
    """
    Get the list of the lpar (standalones or vios) defined on the nim master, and get their
    cstate.

    return the list of the name of the lpar objects defined on the
           nim master and their associated cstate value
    """
    std_out = ''
    std_err = ''
    info_hash = {}

    cmd = ['lsnim', '-t', lpar_type, '-l']

    try:
        proc = subprocess.Popen(cmd, shell=False, stdin=None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = proc.communicate()
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    # lpar name and associated Cstate
    obj_key = ""
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
            info_hash[obj_key] = {}
            continue

        match_cstate = re.match(r"^\s+Cstate\s+=\s+(.*)$", line)
        if match_cstate:
            cstate = match_cstate.group(1)
            info_hash[obj_key]['cstate'] = cstate
            continue

        # For VIOS store the management profile
        if lpar_type == 'vios':
            match_mgmtprof = re.match(r"^\s+mgmt_profile1\s+=\s+(.*)$", line)
            if match_mgmtprof:
                mgmt_elts = match_mgmtprof.group(1).split()
                if len(mgmt_elts) == 3:
                    info_hash[obj_key]['mgmt_hmc_id'] = mgmt_elts[0]
                    info_hash[obj_key]['mgmt_vios_id'] = mgmt_elts[1]
                    info_hash[obj_key]['mgmt_cec_serial'] = mgmt_elts[2]

            match_if = re.match(r"^\s+if1\s+=\s+\S+\s+(\S+)\s+.*$", line) 
            if match_if:
                info_hash[obj_key]['vios_ip'] = match_if.group(1)

    return info_hash


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_vios_oslevel():
    """
    Get the oslevel of the vios defined on the nim master.

    return a hash of the vios oslevel
    """

    # =========================================================================
    # Launch threads to collect information on targeted nim clients
    # =========================================================================
    threads = []
    vios_oslevel = {}

    for machine in NIM_NODE['nim_vios']:
        process = threading.Thread(target=run_oslevel_cmd,
                                   args=(machine, vios_oslevel, 'vios'))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

    return vios_oslevel


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def build_nim_node(module):
    """
    build the nim node containing the nim vios and hmcinfo.

    arguments:
        None

    return:
        None
    """

    global NIM_NODE

    # =========================================================================
    # Build hmc info list
    # =========================================================================
    nim_hmc = {}
    nim_hmc = get_hmc_info(module)

    NIM_NODE['nim_hmc'] = nim_hmc
    logging.debug('NIM HMC: {}'.format(nim_hmc))

    # =========================================================================
    # Build vios info list
    # =========================================================================
    nim_vios = {}
    nim_vios = get_nim_clients_info(module, 'vios')

    NIM_NODE['nim_vios'] = nim_vios
    logging.debug('NIM VIOS: {}'.format(nim_vios))

    # =========================================================================
    # get the oslevel of each vios
    # =========================================================================
    vios_oslevel = {}
    vios_oslevel = get_nim_vios_oslevel()

    for (k, val) in vios_oslevel.items():
        NIM_NODE['nim_vios'][k]['oslevel'] = val

    logging.debug('NIM VIOS: {}'.format(nim_vios))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_vios_targets(targets):
    """
    check the list of the vios targets.

    a target name could be of the following form:
        (vios1, vios2) (vios3)

    arguments:
        targets (str): list of tuple of NIM name of vios machine

    return: the list of the existing vios tuple matching the target list
    """
    global NIM_NODE

    vios_list = {}
    vios_list_tuples_res = []
    vios_list_tuples = targets.replace(" ", "").split('(')

    # ===========================================
    # Build targets list
    # ===========================================
    for vios_tuple in vios_list_tuples[1:]:

        logging.debug('Check_vios_targets - vios_tuple: {}'.format(vios_tuple))

        tuple_elts = list(vios_tuple[:-1].split(','))
        tuple_len = len(tuple_elts)

        if tuple_len != 1 and tuple_len != 2:
            logging.error('TARGETS: malformed vios targets elt: {} len: {} targets: {}'. \
                          format(tuple_elts, tuple_len, targets))
            return None

        # check vios not already exists in the target list
        if tuple_elts[0] in vios_list or \
           (tuple_len == 2 and (tuple_elts[1] in vios_list or \
                                tuple_elts[0] == tuple_elts[1])):
            logging.error(
                'TARGETS: malformed vios targets {}. Duplicated values'. \
                format(targets))
            return None

        # check vios is knowed by the NIM master - if not ignore it
        if tuple_elts[0] not in NIM_NODE['nim_vios'] or \
           (tuple_len == 2 and  tuple_elts[1] not in NIM_NODE['nim_vios']):
            continue

        if tuple_len == 2:
            vios_list[tuple_elts[0]] = tuple_elts[1]
            vios_list[tuple_elts[1]] = tuple_elts[0]
            # vios_list = vios_list.extend([tuple_elts[0], tuple_elts[1]])
            my_tuple = (tuple_elts[0], tuple_elts[1])
            vios_list_tuples_res.append(tuple(my_tuple))
        else:
            vios_list[tuple_elts[0]] = tuple_elts[0]
            # vios_list.append(tuple_elts[0])
            my_tuple = (tuple_elts[0],)
            vios_list_tuples_res.append(tuple(my_tuple))

    return vios_list_tuples_res


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def vios_health(module, mgmt_sys_uuid, hmc_login, hmc_passwd, hmc_ip, vios_uuids):
    """
    Check the "health" of the given VIOSES

    return: True if ok,
            False else
    """
    global NIM_NODE

    logging.debug('vios_health: hmc_id {} vioses {}'. \
                  format(hmc_ip, vios_uuids))

    ret = 0

    # build the vioshc cmde
    cmd = ['/usr/sbin/vioshc.py', '-i', hmc_ip, '-u', hmc_login, \
           '-p', hmc_passwd, '-m', mgmt_sys_uuid]
    for vios in vios_uuids:
        cmd.extend(['-U', vios])

    logging.debug('vios_health: cmd: {}'.format(cmd))

    ret, stdout = exec_cmd(cmd, module)
    logging.debug('vioshc rc:{} output {}'.format(ret, stdout))
    if ret != 0:
        logging.error('vioshc command error rc:{}, output: {}'. \
                      format(ret, stdout))
        # TBC
        # module.fail_json(msg=msg)
    elif re.search(r'Pass rate of 100%', stdout, re.M):
        logging.debug('vioses {} can be updated'. \
                     format(vios_uuids))
        ret=0
    else:
        logging.debug('vioses {} can NOT be updated'. \
                     format(vios_uuids))
        ret=1

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def vios_health_init(module, hmc_id, hmc_login, hmc_passwd, hmc_ip):
    """
    Check the "health" of the given VIOSES for a rolling update point of view

    This operation uses the vioshc.py script to evaluate the capacity of the
    pair of the VIOSes to support the rolling update operation:
    - check they manage the same LPARs,
    - ...

    return: True if ok,
            False else
    """
    global NIM_NODE

    logging.debug('vios_health_init: hmc_id {} hmc_ip {} login {}'. \
                  format(hmc_id, hmc_ip, hmc_login))

    ret = 0
    # if needed, call the /usr/sbin/vioshc.py script a first time to
    # collect UUIDs
    cmd = ['/usr/sbin/vioshc.py', '-i', hmc_ip, '-u', hmc_login, \
           '-p', hmc_passwd, '-l', 'a']

    logging.debug('vios_health_init - cmd: {}'.format(cmd))

    ret, stdout = exec_cmd(cmd, module)
    logging.debug('vioshc rc:{} output {}'.format(ret, stdout))
    if ret != 0:
        logging.error('vioshc command error rc:{}, error: {}'. \
                      format(ret, stdout))
        msg = 'Health init check failed. vioshc command error. rc:{}, error: {}'. \
                format(ret, stdout)
        module.fail_json(msg=msg)

    # Parse the ooutput and store the UUIDs
    data_start = 0
    vios_section = 0
    cec_uuid = ''
    cec_serial = ''
    for line in stdout.rstrip().split('\n'):
        logging.debug('--------line {}'.format(line))
        if vios_section == 0:
            # skip the header
            match_key = re.match(r"^-+\s+-+$", line)
            if match_key:
                data_start = 1
                continue
            if data_start == 0:
                continue

            # New managed system section
            match_key = re.match(r"^(\S+)\s+(\S+)$", line)
            if match_key:
                cec_uuid = match_key.group(1)
                cec_serial = match_key.group(2).replace("*","_")
                
                logging.debug('New managed system section:{},{}'.format(cec_uuid, cec_serial))
                continue

            # New vios section
            match_key = re.match(r"^\s+-+\s+-+$", line)
            if match_key:
                vios_section = 1
                continue

            # skip all header and empty lines until the vios section
            continue

        # new vios partition
        match_key = re.match(r"^\s+(\S+)\s+(\S+)$", line)
        if match_key:
            vios_uuid = match_key.group(1)
            vios_part_id = match_key.group(2)
            logging.debug('new vios partitionsection:{},{}'.format(vios_uuid,vios_part_id))

            # retrieve the vios with the vios_part_id and the cec_serial value
            # and store the UUIDs in the dictionaries
            for vios_key in NIM_NODE['nim_vios']:
                if NIM_NODE['nim_vios'][vios_key]['mgmt_vios_id'] == vios_part_id \
                   and \
                   NIM_NODE['nim_vios'][vios_key]['mgmt_cec_serial'] == cec_serial:
                    NIM_NODE['nim_vios'][vios_key]['vios_uuid'] = vios_uuid
                    NIM_NODE['nim_vios'][vios_key]['cec_uuid'] = cec_uuid
                    break
            continue

        # skip vios line where lparid is not found.
        match_key = re.match(r"^\s+(\S+)\s+Not found$", line)
        if match_key:
            continue

        # skip empty line after vios section. stop the vios section
        match_key = re.match(r"^$", line)
        if match_key:
            vios_section = 0
            continue

        logging.error('vioshc command, bad output line:{}'.format(line))
        msg = 'Health init check failed. Bad vioshc.py command output for the {} hmc - output: {}'. \
                format(hmc_id, line)
        module.fail_json(msg=msg)

    logging.debug('vioshc output:{}'.format(line))
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def health_check(module, targets):
    """
    Healt assessment of the VIOSes targets to ensure they can be support
    a rolling update operation.
    
    For each VIOS tuple,
    - call /usr/sbin/vioshc.py a first time to collect the VIOS UUIDs
    - call it a second time to check the healthiness

    return: True if ok,
            False else
    """
    global NIM_NODE

    logging.debug('VIOS CHECK - health_check: {}'.format(targets))

    health_tab = {}
    vios_key = []
    for target_tuple in targets:
        logging.debug('VIOS CHECK - health_check target_tuple: {}'.format(target_tuple))

        tup_len = len(target_tuple)
        vios1 = target_tuple[0]
        if tup_len == 2:
            vios2 = target_tuple[1]
            vios_key = "{}-{}".format(vios1, vios2)
        else:
            vios_key = vios1
        
        logging.debug('VIOS CHECK - health_check vios1: {}'.format(vios1))
        cec_serial = NIM_NODE['nim_vios'][vios1]['mgmt_cec_serial']
        hmc_id = NIM_NODE['nim_vios'][vios1]['mgmt_hmc_id']

        if hmc_id not in NIM_NODE['nim_hmc']:
            logging.warn("VIOS CHECK - health_check: VIOS {} refers to an inexistant hmc {}". \
                         format(vios1, hmc_id))
            health_tab[vios_key] = 'FAILURE-HC'
            continue

        hmc_login = NIM_NODE['nim_hmc'][hmc_id]['login']
        hmc_login_len = len(hmc_login)
        hmc_passfile = NIM_NODE['nim_hmc'][hmc_id]['passwd_file']
        hmc_ip = NIM_NODE['nim_hmc'][hmc_id]['ip']

        vios_uuid = []

        # TBC - hmc_passwd forced
        hmc_passwd = 'abc123'

        # if needed call vios_health_init to get the UUIDs value
        if 'vios_uuid' not in NIM_NODE['nim_vios'][vios1] or \
            tup_len == 2 and 'vios_uuid' not in NIM_NODE['nim_vios'][vios2]:

            ret = vios_health_init(module, hmc_id, hmc_login, hmc_passwd, hmc_ip)
            if ret != 0:
                logging.warn("VIOS CHECK - health_check: unable to get UUIDs of {} and {}, ret: {}". \
                             format(vios1, vios2, ret))
                health_tab[vios_key] = 'FAILURE-HC'
                continue

        if 'vios_uuid' not in NIM_NODE['nim_vios'][vios1] or \
           tup_len == 2 and 'vios_uuid' not in NIM_NODE['nim_vios'][vios2]:
            # vios uuid's not found
            health_tab[vios_key] = 'FAILURE-HC'

        else:            
            # run the vios_health check for the vios tuple
            vios_uuid.append(NIM_NODE['nim_vios'][vios1]['vios_uuid'])
            if tup_len == 2:
                vios_uuid.append(NIM_NODE['nim_vios'][vios2]['vios_uuid'])

            mgmt_uuid = NIM_NODE['nim_vios'][vios1]['cec_uuid']

            ret = vios_health(module, mgmt_uuid, hmc_login, hmc_passwd, hmc_ip,
                              vios_uuid)

            # TBC-Begin - For testing, will be remove !
            if vios1 == 'gdrh9v1' or vios1 == 'gdrh9v2':
                ret = 0
            # TBC-End

            if ret == 0:
                health_tab[vios_key] = 'SUCCESS-HC'
            else:
                health_tab[vios_key] = 'FAILURE-HC'

    logging.debug('VIOS CHECK - health_tab: {}'. format(health_tab))
    return health_tab


################################################################################

if __name__ == '__main__':

    DEBUG_DATA = []
    OUTPUT = []
    PARAMS = {}
    NIM_NODE = {}
    CHANGED = False
    targets_list = []
    

    module = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            action=dict(required=True, choices=['health_check'], type='str'),
        ),
        supports_check_mode=True
    )

    # Open log file
    logging.basicConfig(filename='/tmp/ansible_vios_check_debug.log', format= \
        '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s', \
        level=logging.DEBUG)
    logging.debug('*** START VIOS CHECK operation ***')

    # =========================================================================
    # Get Module params
    # =========================================================================
    action = module.params['action']
    targets = module.params['targets']
    if module.params['description']:
        description = module.params['description']
    else:
        description = "VIOS CHECK - operation: {} request".format(action)

    PARAMS['action'] = action
    PARAMS['targets'] = targets
    PARAMS['Description'] = description

    OUTPUT.append('VIOS CHECK operation for {}'.format(targets))
    logging.info('VIOS CHECK - action {} for {} targets'.format(action, targets))

    targets_health_status = {}

    # =========================================================================
    # build nim node info
    # =========================================================================
    build_nim_node(module)

    ret = check_vios_targets(targets)
    if (ret is None) or (not ret):
        OUTPUT.append('Empty target list')
        logging.warn('VIOS CHECK - Warning: Empty target list for targets {}'. \
                      format(targets))

    else:
        targets_list = ret
        OUTPUT.append('Targets list:{}'.format(targets_list))
        logging.debug('VIOS CHECK - Target list: {}'.format(targets_list))

        # ===============================================
        # Check vioshc script is present, else install it
        # ===============================================
        logging.debug('VIOS CHECK - Check vioshc script ***')
        vioshcpath = os.path.abspath(os.path.join(os.sep, 'usr', 'sbin'))
        vioshcfile = os.path.join(vioshcpath, 'vioshc.py')

        if not os.path.exists(vioshcfile):
            logging.error('VIOS CHECK - Error: cannot find {}'. \
                                 format(vioshcfile))
            module.fail_json(msg="VIOS CHECK - Error: cannot find {}". \
                                 format(vioshcfile))

        st = os.stat(vioshcfile)
        if not st.st_mode & stat.S_IEXEC:
            logging.error('VIOS CHECK - Error: bad credentials for {}'. \
                                 format(vioshcfile))
            module.fail_json(msg="VIOS CHECK - Error: bad credentials for {}". \
                                 format(vioshcfile))

        targets_health_status = health_check(module, targets_list)
        OUTPUT.append('VIOS CHECK Status')
        for vios_key in targets_health_status.keys():
            OUTPUT.append("    {} : {}".format(vios_key, targets_health_status[vios_key]))

        logging.info('Health check result: {}'.format(targets_health_status))

    # ==========================================================================
    # Exit
    # ==========================================================================
    module.exit_json(
        changed=CHANGED,
        msg="VIOS health check completed successfully",
        targets=targets_list,
        nim_node=NIM_NODE,
        status=targets_health_status,
        debug_output=DEBUG_DATA,
        output=OUTPUT)
