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
"""AIX VIOS Health Check: check the pair of VIOS can be updated"""

import os
import re
import subprocess
import logging
# Ansible module 'boilerplate'
# pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin
from ansible.module_utils.basic import *


DOCUMENTATION = """
---
module: aix_nim_vios_hc
author: "Patrice Jacquin"
version_added: "1.0.0"
requirements: [ AIX ]
"""


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd, module, exit_on_error=False, debug_data=True):
    """
    Execute the given command
        - cmd           array of the command parameters
        - module        the module variable
        - exit_on_error execption is raised if true and cmd return !0
        - debug_data    prints some trace in DEBUG_DATA if set

    In case of error set an error massage and fails the module

    return
        - ret_code  (return code of the command)
        - output   output of the command
    """

    global DEBUG_DATA

    ret_code = 0
    output = ''

    logging.debug('exec command:{}'.format(cmd))
    if debug_data is True:
        DEBUG_DATA.append('exec command:{}'.format(cmd))
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as exc:
        # exception for ret_code != 0 can be cached if exit_on_error is set
        output = exc.output
        ret_code = exc.returncode
        if exit_on_error is True:
            msg = 'Command: {} Exception.Args{} =>RetCode:{} ... Error:{}'\
                  .format(cmd, exc.cmd, ret_code, output)
            module.fail_json(msg=msg)

    except Exception as exc:
        # uncatched exception
        msg = 'Command: {} Exception.Args{}'.format(cmd, exc.args)
        module.fail_json(msg=msg)

    if ret_code == 0:
        if debug_data is True:
            DEBUG_DATA.append('exec output:{}'.format(output))
        logging.debug('exec command output:{}'.format(output))
    else:
        if debug_data is True:
            DEBUG_DATA.append('exec command ret_code:{}, stderr:{}'.format(ret_code, output))
        logging.debug('exec command ret_code:{}, stderr:{}'.format(ret_code, output))

    return (ret_code, output)


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_hmc_info(module):
    """
    Get the hmc info on the nim master

    fill the hmc_dic passed in parameter

    return a dic with hmc info
    """
    std_out = ''
    info_hash = {}

    cmd = ['lsnim', '-t', 'hmc', '-l']
    (ret, std_out) = exec_cmd(cmd, module)

    obj_key = ''
    for line in std_out.split('\n'):
        line = line.rstrip()
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
def get_nim_cecs_info(module):
    """
    Get the list of the cec defined on the nim master and gat their serial number.

    return the list of the name of the cec objects defined on the
           nim master and their associated CEC serial number value
    """
    std_out = ''
    info_hash = {}

    cmd = ['lsnim', '-t', 'cec', '-l']
    (ret, std_out) = exec_cmd(cmd, module)

    # lpar name and associated Cstate
    obj_key = ""
    for line in std_out.split('\n'):
        line = line.rstrip()
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
            info_hash[obj_key] = {}
            continue

        match_serial = re.match(r"^\s+serial\s+=\s+(.*)$", line)
        if match_serial:
            info_hash[obj_key]['serial'] = match_serial.group(1)
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
    info_hash = {}

    cmd = ['lsnim', '-t', lpar_type, '-l']
    (ret, std_out) = exec_cmd(cmd, module)

    # lpar name and associated Cstate
    obj_key = ""
    for line in std_out.split('\n'):
        line = line.rstrip()
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
            info_hash[obj_key] = {}
            continue

        match_cstate = re.match(r"^\s+Cstate\s+=\s+(.*)$", line)
        if match_cstate:
            info_hash[obj_key]['cstate'] = match_cstate.group(1)
            continue

        # For VIOS store the management profile
        if lpar_type == 'vios':
            match_mgmtprof = re.match(r"^\s+mgmt_profile1\s+=\s+(.*)$", line)
            if match_mgmtprof:
                mgmt_elts = match_mgmtprof.group(1).split()
                if len(mgmt_elts) == 3:
                    info_hash[obj_key]['mgmt_hmc_id'] = mgmt_elts[0]
                    info_hash[obj_key]['mgmt_vios_id'] = mgmt_elts[1]
                    info_hash[obj_key]['mgmt_cec'] = mgmt_elts[2]

            match_if = re.match(r"^\s+if1\s+=\s+\S+\s+(\S+)\s+.*$", line)
            if match_if:
                info_hash[obj_key]['vios_ip'] = match_if.group(1)

    return info_hash


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
    # Build CEC list
    # =========================================================================
    nim_cec = {}
    nim_cec = get_nim_cecs_info(module)

    # =========================================================================
    # Build vios info list
    # =========================================================================
    nim_vios = {}
    nim_vios = get_nim_clients_info(module, 'vios')

    # =========================================================================
    # Complete the CEC serial in nim_vios dict
    # =========================================================================
    for key in nim_vios:
        if nim_vios[key]['mgmt_cec'] in nim_cec:
            nim_vios[key]['mgmt_cec_serial'] = nim_cec[nim_vios[key]['mgmt_cec']]['serial']

    NIM_NODE['nim_vios'] = nim_vios
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
    vios_list_tuples = targets.replace(" ", "").replace("),(", ")(").split('(')

    # ===========================================
    # Build targets list
    # ===========================================
    for vios_tuple in vios_list_tuples[1:]:

        logging.debug('vios_tuple: {}'.format(vios_tuple))

        tuple_elts = list(vios_tuple[:-1].split(','))
        tuple_len = len(tuple_elts)

        if tuple_len != 1 and tuple_len != 2:
            logging.error('Malformed VIOS targets {}. Tuple {} should be a 2 or 4 elements.'
                          .format(targets, tuple_elts))
            return None

        # check vios not already exists in the target list
        if tuple_elts[0] in vios_list or \
           (tuple_len == 2 and (tuple_elts[1] in vios_list or
                                tuple_elts[0] == tuple_elts[1])):
            logging.error('Malformed VIOS targets {}. Duplicated VIOS'
                          .format(targets))
            return None

        # check vios is known by the NIM master - if not ignore it
        if tuple_elts[0] not in NIM_NODE['nim_vios'] or \
           (tuple_len == 2 and tuple_elts[1] not in NIM_NODE['nim_vios']):
            logging.debug('skipping {} as VIOS not known by the NIM master.'
                          .format(vios_tuple))
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
def vios_health(module, mgmt_sys_uuid, hmc_ip, vios_uuids):
    """
    Check the "health" of the given VIOSES

    return: True if ok,
            False else
    """
    global NIM_NODE

    logging.debug('hmc_ip: {} vios_uuids: {}'.format(hmc_ip, vios_uuids))

    # build the vioshc cmde
    cmd = ['/usr/sbin/vioshc.py', '-i', hmc_ip, '-m', mgmt_sys_uuid]
    for vios in vios_uuids:
        cmd.extend(['-U', vios])
    if VERBOSITY != 0:
        vstr = "-v"
        verbose = 1
        while verbose < VERBOSITY:
            vstr += "v"
            verbose += 1
        cmd.extend([vstr])
        
    if VERBOSITY >= 3:
        cmd.extend(['-D'])

    (ret, std_out) = exec_cmd(cmd, module)
    if ret != 0:
        OUTPUT.append('    VIOS Health check failed, vioshc returns: {} {}'
                      .format(ret, std_out))
        logging.error('VIOS Health check failed, vioshc returns: {} {}'
                      .format(ret, std_out))
        OUTPUT.append('    VIOS can NOT be updated')
        logging.info('vioses {} can NOT be updated'.format(vios_uuids))
        ret = 1
    elif re.search(r'Pass rate of 100%', std_out, re.M):
        OUTPUT.append('    VIOS Health check passed')
        logging.info('vioses {} can be updated'.format(vios_uuids))
        ret = 0
    else:
        OUTPUT.append('    VIOS can NOT be updated')
        logging.info('vioses {} can NOT be updated'.format(vios_uuids))
        ret = 1

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def vios_health_init(module, hmc_id, hmc_ip):
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

    logging.debug('hmc_id: {}, hmc_ip: {}'.format(hmc_id, hmc_ip))

    ret = 0
    # if needed, call the /usr/sbin/vioshc.py script a first time to
    # collect UUIDs
    cmd = ['/usr/sbin/vioshc.py', '-i', hmc_ip, '-l', 'a']
    if VERBOSITY != 0:
        vstr = "-v"
        verbose = 1
        while verbose < VERBOSITY:
            vstr += "v"
            verbose += 1
        cmd.extend([vstr])
    if VERBOSITY >= 3:
        cmd.extend(['-D'])

    (ret, std_out) = exec_cmd(cmd, module)
    if ret != 0:
        OUTPUT.append('    Failed to get the VIOS information, vioshc returns: {} {}'
                      .format(ret, std_out))
        logging.error('Failed to get the VIOS information, vioshc returns: {} {}'
                      .format(ret, std_out))
        msg = 'Health init check failed. vioshc command error. rc:{}, error: {}'\
              .format(ret, std_out)
        module.fail_json(msg=msg)

    # Parse the output and store the UUIDs
    data_start = 0
    vios_section = 0
    cec_uuid = ''
    cec_serial = ''
    for line in std_out.split('\n'):
        line = line.rstrip()
        # TBC - remove?
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
                cec_serial = match_key.group(2)

                logging.debug('New managed system section:{},{}'
                              .format(cec_uuid, cec_serial))
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
            logging.debug('new vios partitionsection:{},{}'
                          .format(vios_uuid, vios_part_id))

            # retrieve the vios with the vios_part_id and the cec_serial value
            # and store the UUIDs in the dictionaries
            for vios_key in NIM_NODE['nim_vios']:
                if NIM_NODE['nim_vios'][vios_key]['mgmt_vios_id'] == vios_part_id \
                   and NIM_NODE['nim_vios'][vios_key]['mgmt_cec_serial'] == cec_serial:
                    NIM_NODE['nim_vios'][vios_key]['vios_uuid'] = vios_uuid
                    NIM_NODE['nim_vios'][vios_key]['cec_uuid'] = cec_uuid
                    break
            continue

        # skip vios line where lparid is not found.
        match_key = re.match(r"^\s+(\S+)\s+none$", line)
        if match_key:
            continue

        # skip empty line after vios section. stop the vios section
        match_key = re.match(r"^$", line)
        if match_key:
            vios_section = 0
            continue

        OUTPUT.append('    Bad command output for the hmc: {}'.format(hmc_id))
        logging.error('vioshc command, bad output line: {}'.format(line))
        msg = 'Health init check failed. Bad vioshc.py command output for the {} hmc - output: {}'\
              .format(hmc_id, line)
        module.fail_json(msg=msg)

    logging.debug('vioshc output: {}'.format(line))
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

    logging.debug('targets: {}'.format(targets))

    health_tab = {}
    vios_key = []
    for target_tuple in targets:
        OUTPUT.append('Checking: {}'.format(target_tuple))
        logging.debug('target_tuple: {}'.format(target_tuple))

        tup_len = len(target_tuple)
        vios1 = target_tuple[0]
        if tup_len == 2:
            vios2 = target_tuple[1]
            vios_key = "{}-{}".format(vios1, vios2)
        else:
            vios_key = vios1

        logging.debug('vios1: {}'.format(vios1))
        # cec_serial = NIM_NODE['nim_vios'][vios1]['mgmt_cec_serial']
        hmc_id = NIM_NODE['nim_vios'][vios1]['mgmt_hmc_id']

        if hmc_id not in NIM_NODE['nim_hmc']:
            OUTPUT.append('    VIOS {} refers to an inexistant hmc {}'
                          .format(vios1, hmc_id))
            logging.warn("VIOS {} refers to an inexistant hmc {}"
                         .format(vios1, hmc_id))
            health_tab[vios_key] = 'FAILURE-HC'
            continue

        hmc_ip = NIM_NODE['nim_hmc'][hmc_id]['ip']

        vios_uuid = []

        # if needed call vios_health_init to get the UUIDs value
        if 'vios_uuid' not in NIM_NODE['nim_vios'][vios1] \
           or tup_len == 2 and 'vios_uuid' not in NIM_NODE['nim_vios'][vios2]:
            OUTPUT.append('    Getting VIOS UUID')

            ret = vios_health_init(module, hmc_id, hmc_ip)
            if ret != 0:
                OUTPUT.append('    Unable to get UUIDs of {} and {}, ret: {}'
                              .format(vios1, vios2, ret))
                logging.warn("Unable to get UUIDs of {} and {}, ret: {}"
                             .format(vios1, vios2, ret))
                health_tab[vios_key] = 'FAILURE-HC'
                continue

        if 'vios_uuid' not in NIM_NODE['nim_vios'][vios1] \
           or tup_len == 2 and 'vios_uuid' not in NIM_NODE['nim_vios'][vios2]:
            # vios uuid's not found
            OUTPUT.append('    One VIOS UUID not found')
            logging.warn("Unable to find one vios_uuid in NIM_NODE")
            health_tab[vios_key] = 'FAILURE-HC'

        else:
            # run the vios_health check for the vios tuple
            vios_uuid.append(NIM_NODE['nim_vios'][vios1]['vios_uuid'])
            if tup_len == 2:
                vios_uuid.append(NIM_NODE['nim_vios'][vios2]['vios_uuid'])

            mgmt_uuid = NIM_NODE['nim_vios'][vios1]['cec_uuid']

            OUTPUT.append('    Checking if we can update the VIOS')
            ret = vios_health(module, mgmt_uuid, hmc_ip, vios_uuid)

            if ret == 0:
                OUTPUT.append('    Health check succeeded')
                logging.info("Health check succeeded for {}".format(vios_key))
                health_tab[vios_key] = 'SUCCESS-HC'
            else:
                OUTPUT.append('    Health check failed')
                logging.info("Health check failed for {}".format(vios_key))
                health_tab[vios_key] = 'FAILURE-HC'

    logging.debug('health_tab: {}'. format(health_tab))
    return health_tab


################################################################################

if __name__ == '__main__':

    DEBUG_DATA = []
    OUTPUT = []
    PARAMS = {}
    NIM_NODE = {}
    CHANGED = False
    targets_list = []
    VARS = {}
    VERBOSITY = 0

    module = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            action=dict(required=True, choices=['health_check'], type='str'),
            vars=dict(required=False, type='dict'),
        ),
        supports_check_mode=True
    )

    # =========================================================================
    # Get Module params
    # =========================================================================
    action = module.params['action']
    targets = module.params['targets']
    VERBOSITY = module._verbosity

    if module.params['description']:
        description = module.params['description']
    else:
        description = "Perform a VIOS Health Check operation: {} request".format(action)

    PARAMS['action'] = action
    PARAMS['targets'] = targets
    PARAMS['Description'] = description

    # Handle playbook variables
    if module.params['vars']:
        VARS = module.params['vars']
    if VARS is not None and 'log_file' not in VARS:
        VARS['log_file'] = '/tmp/ansible_vios_check_debug.log'

    # Open log file
    logging.basicConfig(
        filename="{}".format(VARS['log_file']),
        format='[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s',
        level=logging.DEBUG)

    logging.debug('*** START VIOS {} ***'.format(action.upper()))

    OUTPUT.append('VIOS Health Check operation for {}'.format(targets))
    logging.info('action {} for {} targets'.format(action, targets))
    logging.info('VERBOSITY is set to {}'.format(VERBOSITY))

    targets_health_status = {}

    # =========================================================================
    # build nim node info
    # =========================================================================
    build_nim_node(module)

    ret = check_vios_targets(targets)
    if (ret is None) or (not ret):
        OUTPUT.append('    Warning: Empty target list')
        logging.warn('Empty target list: "{}"'.format(targets))
    else:
        targets_list = ret
        OUTPUT.append('    Targets list: {}'.format(targets_list))
        logging.debug('Targets list: {}'.format(targets_list))

        # ===============================================
        # Check vioshc script is present, else install it
        # ===============================================
        logging.debug('Check vioshc script: /usr/sbin/vioshc.py')

        vioshcpath = os.path.abspath(os.path.join(os.sep, 'usr', 'sbin'))
        vioshcfile = os.path.join(vioshcpath, 'vioshc.py')

        if not os.path.exists(vioshcfile):
            OUTPUT.append('Cannot find {}'.format(vioshcfile))
            logging.error('Cannot find {}'.format(vioshcfile))
            module.fail_json(msg="Cannot find {}".format(vioshcfile))

        st = os.stat(vioshcfile)
        if not st.st_mode & stat.S_IEXEC:
            OUTPUT.append('Bad credentials for {}'.format(vioshcfile))
            logging.error('Bad credentials for {}'.format(vioshcfile))
            module.fail_json(msg="Bad credentials for {}".format(vioshcfile))

        targets_health_status = health_check(module, targets_list)

        OUTPUT.append('VIOS Health Check status:')
        logging.info('VIOS Health Check status:')
        for vios_key in targets_health_status.keys():
            OUTPUT.append("    {} : {}".format(vios_key, targets_health_status[vios_key]))
            logging.info('    {} : {}'.format(vios_key, targets_health_status[vios_key]))

    # ==========================================================================
    # Exit
    # ==========================================================================
    module.exit_json(
        changed=CHANGED,
        msg="VIOS Health Check completed successfully",
        targets=targets_list,
        nim_node=NIM_NODE,
        status=targets_health_status,
        debug_output=DEBUG_DATA,
        output=OUTPUT)
