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
import time
import logging
import string

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *


DOCUMENTATION = """
---
module: aix_nim_vios_alt_disk
short_description: "Copy the rootvg to an alternate disk or cleanup an existing one"
author: "Patrice Jacquin, Vianney Robin"
version_added: "1.0.0"
requirements: [ AIX ]

TBC - Does proc.communicate set the return code with the command's return code? (seems to get 0 even we get "command not found" in stderr)

Note - alt_disk_copy only backs up mounted file systems. Mount all file systems that you want to back up.
     - copy is performed only on one alternate hdisk even if the rootvg contains multiple hdisks
     - error if several altinst_rootvg exist for cleanup operation in automatic mode
"""


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd, module, exit_on_error, debug_data=True):
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

    rc = 0
    output = ''

    logging.debug('exec command:{}'.format(cmd))
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)

    except subprocess.CalledProcessError as exc:
        # exception for rc != 0 can be cached if exit_on_error is set
        output = exc.output
        rc = exc.returncode
        if exit_on_error == True:
            msg = 'Command: {} Exception.Args{} =>RetCode:{} ... Error:{}'. \
                    format(cmd, exc.cmd, rc, output)
            module.fail_json(msg=msg)

    except Exception as exc:
        # uncatched exception
        msg = 'Command: {} Exception.Args{}'. \
               format(cmd, exc.args)
        module.fail_json(msg=msg)

    if rc == 0:
        if debug_data == True:
            DEBUG_DATA.append('exec command:{}'.format(cmd))
        logging.debug('exec command output:{}'.format(output))
    else:
        if debug_data == True:
            DEBUG_DATA.append('exec command rc:{}, stderr:{}'.format(rc, output))
        logging.debug('exec command rc:{}, stderr:{}'.format(rc, output))

    return (rc, output)

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_shell_cmd(cmd, module, debug_data=True):
    """
    Execute the given command with the shell
        - cmd       array of the command parameters
        - module    the module variable
    One should use this for ioscli commands instead of exec_cmd

    In case of error set an error massage and fails the module

    return
        - ret_code              (return code of the command)
        - std_out or std_err    output of the command
    """

    global DEBUG_DATA

    rc = 0
    (std_out, std_err) = ("", "")

    logging.debug('exec command:{}'.format(cmd))
    try:
        proc = subprocess.Popen(cmd, shell=True, stdin=None, \
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (std_out, std_err) = proc.communicate()

    except Exception as exc:
        # uncatched exception
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    rc = proc.returncode
    if debug_data == True:
        DEBUG_DATA.append('exec command:{}'.format(cmd))
    if rc == 0:
        logging.debug('exec command output:{}'.format(std_out))
        return (rc, std_out)
    else:
        if debug_data == True:
            DEBUG_DATA.append('exec command rc:{}, stderr:{}'.format(rc, std_err))
        logging.debug('exec command rc:{}, stderr:{}'.format(rc, std_err))
        return (rc, std_err)


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_hmc_info(module):
    """
    Get the hmc info on the nim master, and get their login/passwd

    fill the hmc_dic passed in parameter (filled with the login/passwd value)

    return a dic with hmc info
    """
    ret = 0
    std_out = ''
    info_hash = {}

    cmd = ['lsnim', '-t', 'hmc', '-l']
    (ret, std_out) = exec_cmd(cmd, module, exit_on_error=True)

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
    ret = 0
    std_out = ''
    info_hash = {}

    cmd = ['lsnim', '-t', lpar_type, '-l']
    (ret, std_out) = exec_cmd(cmd, module, exit_on_error=True)

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
                else:
                    logging.warning('WARNING: VIOS {} management profile has not 3 elements: {}'. \
                                  format(obj_key, match_mgmtprof.group(1)))
                continue

            match_if = re.match(r"^\s+if1\s+=\s+\S+\s+(\S+)\s+.*$", line)
            if match_if:
                info_hash[obj_key]['vios_ip'] = match_if.group(1)
                continue

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
    # Build vios info list
    # =========================================================================
    nim_vios = {}
    nim_vios = get_nim_clients_info(module, 'vios')

    NIM_NODE['nim_vios'] = nim_vios
    logging.debug('NIM VIOS: {}'.format(nim_vios))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_vios_targets(targets):
    """
    check the list of the vios targets.

    a target name could be of the following forms:
        (vios1, altdisk1, vios2, altdisk2) (...)
        (vios1, altdisk1) (vios2, altdisk2) (...)
    a altdisk can be omitted if one wants to use the automatic discovery
    in that case, the first available disk with a enough space will be taken

    arguments:
        targets (str): list of tuple of NIM name of vios machine and
                           associated alternate disk

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

        logging.debug('vios_tuple: {}'.format(vios_tuple))

        tuple_elts = list(vios_tuple[:-1].split(','))
        tuple_len = len(tuple_elts)

        if tuple_len != 2 and tuple_len != 4:
            logging.error('Malformed VIOS targets {}. Should be a 2 or 4 elements tuple'. \
                          format(tuple_elts, tuple_len, targets))
            return None

        # check vios not already exists in the target list
        if tuple_elts[0] in vios_list or \
           (tuple_len == 4 and (tuple_elts[2] in vios_list or \
                                tuple_elts[0] == tuple_elts[2])):
            logging.error('Malformed VIOS targets {}. Duplicated VIOS'. \
                          format(targets))
            return None

        # check if duplicate alt_disk value
        if tuple_len == 4 and tuple_elts[1] == tuple_elts[3]:
            logging.error('Malformed VIOS targets {}. Duplicated alternate disks'. \
                          format(targets))
            return None

        # check vios is knowed by the NIM master - if not ignore it
        # because it can concern an other ansible host (nim master)
        if tuple_elts[0] not in NIM_NODE['nim_vios'] or \
           (tuple_len == 4 and  tuple_elts[2] not in NIM_NODE['nim_vios']):
            continue

        # fill vios_list dictionnary
        if tuple_len == 4:
            vios_list[tuple_elts[0]] = tuple_elts[1]
            vios_list[tuple_elts[2]] = tuple_elts[3]
            # vios_list = vios_list.extend([tuple_elts[0], tuple_elts[1]])
            my_tuple = (tuple_elts[0], tuple_elts[1], tuple_elts[2], \
                        tuple_elts[3])
            vios_list_tuples_res.append(tuple(my_tuple))
        else:
            vios_list[tuple_elts[0]] = tuple_elts[1]
            # vios_list.append(tuple_elts[0])
            my_tuple = (tuple_elts[0],tuple_elts[1])
            vios_list_tuples_res.append(tuple(my_tuple))

    return vios_list_tuples_res


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_pvs(module, vios):
    """
    get the list of PV on the VIOS

    return: dictionnary with free PVs information
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('vios: {}'.format(vios))

    ret = 0
    std_out = ''
    pvs = {}

    cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} '/usr/ios/cli/ioscli lspv'". \
            format(NIM_NODE['nim_vios'][vios]['vios_ip'])
    (ret, std_out) = exec_shell_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the PV list on {}, lspv returns: {}'. \
                format(vios, std_out))
        logging.error('Failed to get the PV list on {}, lspv returns: {} {}'. \
                format(vios, ret, std_out))
        return None

    # NAME             PVID                                 VG               STATUS
    # hdisk0           000018fa3b12f5cb                     rootvg           active
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(hdisk\S+)\s+(\S+)\s+(\S+)\s*(\S*)", line)
        if match_key:
            pvs[match_key.group(1)] = {}
            pvs[match_key.group(1)]['pvid'] = match_key.group(2)
            pvs[match_key.group(1)]['vg'] = match_key.group(3)
            pvs[match_key.group(1)]['status'] = match_key.group(4)

    logging.debug('List of PVs:')
    for key in pvs.keys():
        logging.debug('    pvs[{}]: {}'.format(key, pvs[key]))

    return pvs


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_free_pvs(module, vios):
    """
    get the list of free PV on the VIOS

    return: dictionnary with free PVs information
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('vios: {}'.format(vios))

    ret = 0
    std_out = ''
    free_pvs = {}

    cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} '/usr/ios/cli/ioscli lspv -free'". \
            format(NIM_NODE['nim_vios'][vios]['vios_ip'])
    (ret, std_out) = exec_shell_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the list of free PV on {}: {}'. \
                format(vios, std_out))
        logging.error('Failed to get the list of free PVs on {}, lspv returns: {} {}'. \
                format(vios, ret, std_out))
        return None

    # NAME            PVID                                SIZE(megabytes)
    # hdiskX          none                                572325
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(hdisk\S+)\s+(\S+)\s+(\S+)", line)
        if match_key:
            free_pvs[match_key.group(1)] = {}
            free_pvs[match_key.group(1)]['pvid'] = match_key.group(2)
            free_pvs[match_key.group(1)]['size'] = int(match_key.group(3))

    logging.debug('List of available PVs:')
    for key in free_pvs.keys():
        logging.debug('    free_pvs[{}]: {}'.format(key, free_pvs[key]))

    return free_pvs


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_vg_size(module, vios, vg_name):
    """
    get the size in MB of the VG on the VIOS

    return:
        size of the vg otherwise
        -1   upon error
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('vios: {}'.format(vios))

    ret = 0
    std_out = ''
    vg_size = -1

    cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} '/usr/ios/cli/ioscli lsvg {}'". \
            format(NIM_NODE['nim_vios'][vios]['vios_ip'], vg_name)
    (ret, std_out) = exec_shell_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the {} VG size on {}, lsvg returns: {}'. \
                format(vg_name, vios, std_out))
        logging.error('Failed to get the {} VG size on {}, lsvg returns: {} {}'. \
                format(vg_name, vios, ret, std_out))
        return -1

    # parse lsvg outpout to get the size in megabytes:
    # VG PERMISSION:      read/write               TOTAL PPs:      558 (285696 megabytes)
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r".*TOTAL PPs:\s+\d+\s+\((\d+)\s+megabytes\).*", line)
        if match_key:
            vg_size = int(match_key.group(1))

    if vg_size == -1:
        OUTPUT.append('    Failed to get the {} VG size on {}, parsing error'. \
                format(vg_name, vios))
        logging.error('Failed to get the {} VG size on {}, parsing error'. \
                format(vg_name, vios))
        return -1

    return vg_size


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def find_valid_altdisk(module, action, vios, vios_dict, vios_key, altdisk_op_tab, err_label):
    """
    find a valid alternate disk that
    - exists,
    - is not part of a VG
    and so can be used.

    sets the altdisk_op_tab acordingly:
        altdisk_op_tab[vios_key] = "FAILURE-ALTDC[12] <error message>"
        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"

    return:
        the disk name that can be used
        None otherwise
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('action: {}, vios: {}, vios_dict[{}]: {}, vios_key: {}'. \
            format(action, vios, vios, vios_dict[vios], vios_key))

    OUTPUT.append('    Check the alternate disk {} on {}'.format(vios_dict[vios], vios))
    pvs = {}

    if action == 'alt_disk_copy':

        pvs = get_free_pvs(module, vios)
        if (pvs is None) or (not pvs):
            altdisk_op_tab[vios_key] = "{} to get the list of free PVs on {}". \
                    format(err_label, vios)
            return None

        rootvg_size = get_vg_size(module, vios, "rootvg")
        if rootvg_size <= 0:
            altdisk_op_tab[vios_key] = "{} to get the rootvg size on {}". \
                    format(err_label, vios)
            return None
        logging.debug('rootvg size is: {} MB'.format(rootvg_size))

        # in auto mode, find the first alternate disk available
        if vios_dict[vios] == "":
            for hdisk in pvs.keys():
                if pvs[hdisk]['size'] >= rootvg_size:
                    vios_dict[vios] = hdisk
                    return hdisk
            altdisk_op_tab[vios_key] = "{} to find an alternate disk {} on {}". \
                    format(err_label, vios_dict[vios], vios)
            OUTPUT.append('    No available alternate disk with size greater than {} MB found on {}'. \
                    format(rootvg_size, vios))
            logging.error('No available alternate disk with size greater than {} MB found on {}'. \
                    format(rootvg_size, vios))
            return None

        # check the specified hdisk is large enough
        if pvs.has_key(vios_dict[vios]):
            if pvs[vios_dict[vios]]['size'] >= rootvg_size:
                return vios_dict[vios]
            else:
                altdisk_op_tab[vios_key] = "{} alternate disk {} too small on {}". \
                        format(err_label, vios_dict[vios], vios)
                logging.error('Alternate disk {} too small ({} < {}) on {}.'. \
                        format(vios_dict[vios], pvs[vios_dict[vios]]['size'], rootvg_size, vios))
                return None
        else:
            altdisk_op_tab[vios_key] = "{} disk {} is not available on {}". \
                    format(err_label, vios_dict[vios], vios)
            OUTPUT.append('    Alternate disk {} is not available on {}'. \
                    format(vios_dict[vios], vios))
            logging.error('Alternate disk {} is either not found or not available on {}'. \
                    format(vios_dict[vios], vios))
            return None

    elif action == 'alt_disk_clean':

        pvs = get_pvs(module, vios)
        if (pvs is None) or (not pvs):
            altdisk_op_tab[vios_key] = "{} to get the list of PVs on {}". \
                    format(err_label, vios)
            return None

        if vios_dict[vios] != "":
            if pvs.has_key(vios_dict[vios]) and pvs[vios_dict[vios]]['vg'] == "altinst_rootvg":
                return vios_dict[vios]
            else:
                altdisk_op_tab[vios_key] = "{} disk {} is not an alternate install rootvg on {}". \
                        format(err_label, vios_dict[vios], vios)
                OUTPUT.append('    Specified disk {} is not an alternate install rootvg on {}'. \
                        format(vios_dict[vios], vios))
                logging.error('Specified disk {} is not an alternate install rootvg on {}'. \
                        format(vios_dict[vios], vios))
                return None
        else:
            # check there is one and only one alternate install rootvg
            for hdisk in pvs.keys():
                if pvs[hdisk]['vg'] == "altinst_rootvg":
                    if vios_dict[vios]:
                        altdisk_op_tab[vios_key] = "{} there are several alternate install rootvg on {}". \
                                format(err_label, vios)
                        OUTPUT.append('    There are several alternate install rootvg on {}: {} and {}'. \
                                format(vios, vios_dict[vios], hdisk))
                        logging.error('There are several alternate install rootvg on {}: {} and {}'. \
                                format(vios, vios_dict[vios], hdisk))
                        vios_dict[vios] = ""    # reset previously set hdisk
                        return None
                    else:
                        vios_dict[vios] = hdisk
            return vios_dict[vios]


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def wait_altdisk_install(module, vios, vios_dict, vios_key, altdisk_op_tab, err_label):
    """
    wait for the alternate disk copy operation to finish.

    when alt_disk_install operation ends the NIM object state changes
    from "a client is being prepared for alt_disk_install" or
         "alt_disk_install operation is being performed"
    to   "ready for NIM operation"

    return:
        -1  if timedout before alt_disk_install ends
        0   if the alt_disk_install operation ends with success
        1   if the alt_disk_install operation ends with error
    """
    global OUTPUT

    logging.debug('vios: {}, vios_dict[{}]: {}, vios_key: {}'. \
            format(vios, vios, vios_dict[vios], vios_key))

    logging.info('Waiting completion of alt_disk copy {} on {}...'. \
            format(vios_dict[vios], vios))

    operation_ends = -1
    wait_time = 0

    # if there is no progress in nim operation "info" attribute for more than
    # 30 minutes we time out: 180 * 10s = 30 min
    check_count = 0
    nim_info_prev = "___"   # this info should not appears in nim info attribute
    while check_count <= 180:
        time.sleep(10)
        wait_time += 10

        cmd = ['lsnim', '-Z', '-a',  'Cstate', '-a',  'info', '-a',  'Cstate_result', vios]
        (ret, std_out) = exec_cmd(cmd, module, exit_on_error=False, debug_data=False)

        if ret != 0:
            altdisk_op_tab[vios_key] = "{} to get the NIM state for {}".format(err_label, vios)
            OUTPUT.append('    Failed to get the NIM state for {}: {}'. \
                    format(vios, std_out))
            logging.error('Failed to get the NIM state for {}: {}'. \
                    format(vios, std_out))
            break

        # info attribute (that appears in 3rd possition) can be empty. So stdout looks like:
        # #name:Cstate:info:Cstate_result:
        # <viosName>:ready for a NIM operation:success
        # <viosName>:alt_disk_install operation is being performed:Creating logical volume alt_hd2.:success:
        # <viosName>:ready for a NIM operation:0505-126 alt_disk_install- target disk hdisk2 has a volume group assigned to it.:failure:
        nim_status = std_out.rstrip().split('\n')[1].split(':')
        nim_Cstate = nim_status[1]
        if len(nim_status) == 4 and (string.lower(nim_status[2]) == "success" or string.lower(nim_status[2].lower()) == "failure"):
            nim_result = string.lower(nim_status[2])
        else:
            nim_info = nim_status[2]
            nim_result = string.lower(nim_status[3])

        if nim_Cstate == "ready for a NIM operation":
            logging.info('alt_disk copy operation on {} ended with nim_result: {}'.format(vios, nim_result))
            if nim_result != "success":
                altdisk_op_tab[vios_key] = "{} to perform alt_disk copy on {} {}".format(err_label, vios, nim_info)
                OUTPUT.append('    Failed to perform alt_disk copy on {}: {}'. \
                        format(vios, nim_info))
                logging.error('Failed to perform alt_disk copy on {}: {}'. \
                        format(vios, nim_info))
                return 1
            else:
                return 0
        else:
            if nim_info_prev == nim_info:
                check_count += 1
            else:
                nim_info_prev = nim_info
                check_count = 0

        if wait_time % 60 == 0:
            logging.info('Waiting completion of alt_disk copy {} on {}... {} minute(s)'. \
                format(vios_dict[vios], vios, wait_time / 60))

    # timed out before the end of alt_disk_install
    altdisk_op_tab[vios_key] = "{} alternate disk copy of {} blocked on {}: NIM operation blocked". \
        format(err_label, vios, nim_info)
    OUTPUT.append('    Alternate disk copy of {} blocked on {}: {}'.format(vios_dict[vios], vios, nim_info))
    logging.error('Alternate disk copy of {} blocked on {}: {}'.format(vios_dict[vios], vios, nim_info))

    return -1


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def alt_disk_action(module, action, targets, vios_status, time_limit):
    """
    alt_dik_copy / alt_disk_clean operation

    For each VIOS tuple,
    - retrieve the previous status if any (looking for SUCCESS-HC and SUCCESS-UPDT1)
    - for each VIOS of the tuple, find and valid the hdisk for the operation
    - perform the alt disk copy or cleanup operation
    - wait for the copy to finish

    return: dictionary containing the altdisk status for each vios tuple
        altdisk_op_tab[vios_key] = "FAILURE-NO-PREV-STATUS"
        altdisk_op_tab[vios_key] = "FAILURE-ALTDC[12] <error message>"
        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('action: {}, targets: {}, vios_status: {}'. \
                  format(action, targets, vios_status))

    altdisk_op_tab = {}
    vios_key = []
    for target_tuple in targets:
        logging.debug('action: {} for target_tuple: {}'. \
                      format(action, target_tuple))

        vios_dict = {}
        tup_len = len(target_tuple)
        vios1 = target_tuple[0]
        vios2 = ""
        vios_dict[vios1] = target_tuple[1]
        if tup_len == 4:
            vios2 = target_tuple[2]
            vios_dict[vios2] = target_tuple[3]
            vios_key = "{}-{}".format(vios1, vios2)
        else:
            vios_key = vios1

        logging.debug('vios_key: {}'.format(vios_key))

        # if health check status is known, check the vios tuple has passed
        # the health check successfuly
        if not (vios_status is None):
            if vios_key not in vios_status:
                altdisk_op_tab[vios_key] = "FAILURE-NO-PREV-STATUS"
                OUTPUT.append("    {} vioses skiped (no previous status found)". \
                               format(vios_key))
                logging.warn("{} vioses skiped (no previous status found)". \
                              format(vios_key))
                continue

            elif vios_status[vios_key] != 'SUCCESS-HC' and vios_status[vios_key] != 'SUCCESS-UPDT1':
                altdisk_op_tab[vios_key] = vios_status[vios_key]
                OUTPUT.append("    {} vioses skiped (vios_status[vios_key])". \
                               format(vios_key))
                logging.warn("{} vioses skiped (vios_status[vios_key])". \
                              format(vios_key))
                continue

        # check if there is time to handle this tuple
        if not (time_limit is None) and time.localtime(time.time()) >= time_limit:
            altdisk_op_tab[vios_key] = "SKIPPED-TIMEDOUT"
            time_limit_str = time.strftime("%m/%d/%Y %H:%M", time_limit)
            OUTPUT.append("    Time limit {} reached, no further operation". \
                    format(time_limit_str))
            logging.info('Time limit {} reached, no further operation'. \
                    format(time_limit_str))
            continue

        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"

        # TBC - Uncomment for testing without effective altdisk operation
        # continue

        for vios in vios_dict.keys():

            # set the error label to be used in sub routines
            if action == 'alt_disk_copy':
                err_label = "FAILURE-ALTDCOPY1"
                if vios == vios2:
                    err_label = "FAILURE-ALTDCOPY2"
            elif action == 'alt_disk_clean':
                err_label = "FAILURE-ALTDCLEAN1"
                if vios == vios2:
                    err_label = "FAILURE-ALTDCLEAN2"

            hdisk = find_valid_altdisk(module, action, vios, vios_dict, vios_key, altdisk_op_tab, err_label)
            if hdisk is None:
                break
            else:
                OUTPUT.append('    Using {} as alternate disk on {}'.format(vios_dict[vios], vios))
                logging.info('Using {} as alternate disk on {}'.format(vios_dict[vios], vios))

            if action == 'alt_disk_copy':
                OUTPUT.append('    Alternate disk copy on {}'.format(vios))

                # alt_disk_copy
                ret = 0
                std_out = ''
                cmd = "/usr/sbin/nim -o alt_disk_install -a source=rootvg \
                       -a disk={} -a set_bootlist=no -a boot_client=no {}". \
                       format(vios_dict[vios], vios)
                (ret, std_out) = exec_shell_cmd(cmd, module)

                if ret != 0:
                    altdisk_op_tab[vios_key] = "{} to copy {} on {}".format(err_label, vios_dict[vios], vios)
                    OUTPUT.append('    Failed to copy {} on {}: {}'. \
                            format(vios_dict[vios], vios, std_out))
                    logging.error('Failed to copy {} on {}: {}'. \
                            format(vios_dict[vios], vios, std_out))
                    break

                # wait till alt_disk_install ends
                ret = wait_altdisk_install(module, vios, vios_dict, vios_key, altdisk_op_tab, err_label)
                if ret != 0:
                    # timed out or an error occured, continue with next target_tuple
                    break

            elif action == 'alt_disk_clean':
                OUTPUT.append('    Alternate disk clean on {}'.format(vios))

                # First remove the alternate VG
                OUTPUT.append('    Remove altinst_rootvg from {} of {}'.format(hdisk, vios))
                ret = 0
                std_out = ''
                cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} \
                        '/usr/sbin/alt_rootvg_op -X altinst_rootvg'". \
                        format(NIM_NODE['nim_vios'][vios]['vios_ip'])
                (ret, std_out) = exec_shell_cmd(cmd, module)

                if ret != 0:
                    altdisk_op_tab[vios_key] = "{} to remove altinst_rootvg on {}". \
                        format(err_label, vios)
                    OUTPUT.append('    Failed to remove altinst_rootvg on {}: {}'. \
                        format(vios, std_out))
                    logging.error('Failed to remove altinst_rootvg on {}: {}'. \
                        format(vios, std_out))
                    break

                # Clear the hdisk PVID and the LVM info on the disk itself
                OUTPUT.append('    Clean the PVID and LVM info of {} on {}'.format(hdisk, vios))
                ret = 0
                std_out = ''
                cmd = "/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} \
                        '/etc/chdev -a pv=clear -l {}; \
                         /usr/bin/dd if=/dev/zero of=/dev/{}  seek=7 count=1 bs=512'". \
                        format(NIM_NODE['nim_vios'][vios]['vios_ip'], hdisk, hdisk)
                (ret, std_out) = exec_shell_cmd(cmd, module)

                if ret != 0:
                    altdisk_op_tab[vios_key] = "{} to clean {} PVID of {} on {}". \
                        format(err_label, vios_dict[vios], hdisk, vios)
                    OUTPUT.append('    Failed to clean {} PVID of {} on {}: {}'. \
                        format(vios_dict[vios], hdisk, vios, std_err))
                    logging.error('Failed to clean {} PVID of {} on {}: {}'. \
                        format(vios_dict[vios], hdisk, vios, std_err))
                    break

    logging.debug('altdisk_op_tab: {}'. format(altdisk_op_tab))
    return altdisk_op_tab


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
            action=dict(required=True,
                        choices=['alt_disk_copy', 'alt_disk_clean'],
                        type='str'),
            time_limit=dict(required=False, type='str'),
            vios_status=dict(required=False, type='dict'),
            nim_node=dict(required=False, type='dict'),
        ),
        supports_check_mode=True
    )

    # Open log file
    logging.basicConfig(filename='/tmp/ansible_vios_alt_disk_debug.log', format= \
        '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s', \
        level=logging.DEBUG)
    logging.debug('*** START VIOS ALT_DISK operation ***')

    # =========================================================================
    # Get Module params
    # =========================================================================
    action = module.params['action']
    targets = module.params['targets']

    if module.params['description']:
        description = module.params['description']
    else:
        description = "VIOS ALT_DISK - operation: {} request".format(action)

    PARAMS['action'] = action
    PARAMS['targets'] = targets
    PARAMS['Description'] = description

    if module.params['time_limit']:
        time_limit = module.params['time_limit']

    OUTPUT.append('VIOS Alternate disk operation for {}'.format(targets))
    logging.info('action {} for {} targets'.format(action, targets))

    vios_status = {}
    targets_altdisk_status = {}
    target_list = []

    # build nim node info
    if module.params['nim_node']:
        NIM_NODE = module.params['nim_node']
    else:
        build_nim_node(module)

    if module.params['vios_status']:
        vios_status = module.params['vios_status']
    else:
        vios_status = None

    # build a time structurei for time_limit attribute,
    # the date can be omitted if sameday
    time_limit = None
    if module.params['time_limit']:
        match_key = re.match(r"^\S*\d{2}/\d{2}/\d{4} \S*\d{2}:\d{2}\S*$", module.params['time_limit'])
        if match_key:
            time_limit = time.strptime(module.params['time_limit'], '%m/%d/%Y %H:%M')
        else:
            msg = 'Malformed time limit "{}", please use mm/dd/yyyy hh:mm format.'. \
                    format(module.params['time_limit'])
            module.fail_json(msg=msg)

    # =========================================================================
    # Perfom check and operation
    # =========================================================================
    ret = check_vios_targets(targets)
    if (ret is None) or (not ret):
        OUTPUT.append('    Warning: Empty target list')
        logging.warn('Empty target list for targets {}'. \
                      format(targets))

    else:
        target_list = ret
        OUTPUT.append('    Targets list: {}'.format(target_list))
        logging.debug('Targets list: {}'.format(target_list))

        targets_altdisk_status = alt_disk_action(module, action, target_list,
                                                 vios_status, time_limit)

        if targets_altdisk_status:
            OUTPUT.append('VIOS Alternate disk operation status:')
            logging.info('VIOS Alternate disk operation status:')
            for vios_key in targets_altdisk_status.keys():
                OUTPUT.append("    {} : {}".format(vios_key, targets_altdisk_status[vios_key]))
                logging.info('    {} : {}'.format(vios_key, targets_altdisk_status[vios_key]))
        else:
            OUTPUT.append('VIOS Alternate disk operation: Error getting the status')
            logging.error('VIOS Alternate disk operation: Error getting the status')
            targets_altdisk_status = vios_status

    # ==========================================================================
    # Exit
    # ==========================================================================
    module.exit_json(
        changed=CHANGED,
        msg="VIOS alt disk operation completed successfully",
        targets=target_list,
        nim_node=NIM_NODE,
        status=targets_altdisk_status,
        debug_output=DEBUG_DATA,
        output=OUTPUT)
