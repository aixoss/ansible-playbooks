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
"""AIX VIOS NIM ALTDISK: Create/Cleanup an alternate rootvg disk"""

import re
import subprocess
import time
import logging
import string

# Ansible module 'boilerplate'
from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = """
---
module: aix_nim_vios_alt_disk
short_description: "Copy the rootvg to an alternate disk or cleanup an existing one"
author: "Patrice Jacquin, Vianney Robin, Alain Poncet"
version_added: "1.0.0"
requirements: [ AIX ]

Note - alt_disk_copy only backs up mounted file systems. Mount all file
       systems that you want to back up.
     - copy is performed only on one alternate hdisk even if the rootvg
       contains multiple hdisks
     - error if several altinst_rootvg exist for cleanup operation in
       automatic mode
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
        output = re.sub(r'[-\d]+\n$', '', output)  # remove the rc

    except subprocess.CalledProcessError as exc:
        # exception for ret_code != 0 can be cached if exit_on_error is set
        output = re.sub(r'[-\d]+\n$', '', exc.output)  # remove the rc
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
    Get the hmc info on the nim master, and get their login/passwd

    fill the hmc_dic passed in parameter (filled with the login/passwd value)

    return a dic with hmc info
    """
    ret = 0
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

    cmd = ['LC_ALL=C lsnim', '-t', lpar_type, '-l']
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
                    logging.warning('WARNING: VIOS {} management profile has not 3 elements: {}'
                                    .format(obj_key, match_mgmtprof.group(1)))
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
    vios_list_tuples = targets.replace(" ", "").replace("),(", ")(").split('(')

    # ===========================================
    # Build targets list
    # ===========================================
    for vios_tuple in vios_list_tuples[1:]:
        logging.debug('Checking vios_tuple: {}'.format(vios_tuple))

        tuple_elts = list(vios_tuple[:-1].split(','))
        tuple_len = len(tuple_elts)

        if tuple_len != 2 and tuple_len != 4:
            OUTPUT.append('Malformed VIOS targets {}. Tuple {} should be a 2 or 4 elements.'
                          .format(targets, tuple_elts))
            logging.error('Malformed VIOS targets {}. Tuple {} should be a 2 or 4 elements.'
                          .format(targets, tuple_elts))
            return None

        # check vios not already exists in the target list
        if tuple_elts[0] in vios_list or \
           (tuple_len == 4 and (tuple_elts[2] in vios_list or
                                tuple_elts[0] == tuple_elts[2])):
            OUTPUT.append('Malformed VIOS targets {}. Duplicated VIOS'
                          .format(targets))
            logging.error('Malformed VIOS targets {}. Duplicated VIOS'
                          .format(targets))
            return None

        # check vios is known by the NIM master - if not ignore it
        # because it can concern an other ansible host (nim master)
        if tuple_elts[0] not in NIM_NODE['nim_vios'] or \
           (tuple_len == 4 and tuple_elts[2] not in NIM_NODE['nim_vios']):
            logging.debug('skipping {} as VIOS not known by the NIM master.'
                          .format(vios_tuple))
            continue

        # fill vios_list dictionnary
        if tuple_len == 4:
            vios_list[tuple_elts[0]] = tuple_elts[1]
            vios_list[tuple_elts[2]] = tuple_elts[3]
            # vios_list = vios_list.extend([tuple_elts[0], tuple_elts[1]])
            my_tuple = (tuple_elts[0], tuple_elts[1], tuple_elts[2],
                        tuple_elts[3])
            vios_list_tuples_res.append(tuple(my_tuple))
        else:
            vios_list[tuple_elts[0]] = tuple_elts[1]
            # vios_list.append(tuple_elts[0])
            my_tuple = (tuple_elts[0], tuple_elts[1])
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

    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
           NIM_NODE['nim_vios'][vios]['vios_ip'],
           '"/usr/ios/cli/ioscli lspv; echo $?"']
    (ret, std_out) = exec_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the PV list on {}, lspv returns: {}'
                      .format(vios, std_out))
        logging.error('Failed to get the PV list on {}, lspv returns: {} {}'
                      .format(vios, ret, std_out))
        return None

    # NAME             PVID                                 VG               STATUS
    # hdisk0           000018fa3b12f5cb                     rootvg           active
    for line in std_out.split('\n'):
        line = line.rstrip()
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

    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
           NIM_NODE['nim_vios'][vios]['vios_ip'],
           '"/usr/ios/cli/ioscli lspv -free; echo $?"']
    (ret, std_out) = exec_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the list of free PV on {}: {}'
                      .format(vios, std_out))
        logging.error('Failed to get the list of free PVs on {}, lspv returns: {} {}'
                      .format(vios, ret, std_out))
        return None

    # NAME            PVID                                SIZE(megabytes)
    # hdiskX          none                                572325
    for line in std_out.split('\n'):
        line = line.rstrip()
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
def get_vg_size(module, vios, vg_name, used_lp):
    """
    get the size in MB of the VG on the VIOS and the USED size

    return:
        size of the vg and used size (+ 1 PP size) otherwise
        -1   upon error
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('vios: {}'.format(vios))

    ret = 0
    std_out = ''
    vg_size = -1
    vg_used = -1

    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
           NIM_NODE['nim_vios'][vios]['vios_ip'],
           '"LC_ALL=C; /usr/ios/cli/ioscli lsvg {}; echo $?"'.format(vg_name)]
    (ret, std_out) = exec_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get the {} VG size on {}, lsvg returns: {}'
                      .format(vg_name, vios, std_out))
        logging.error('Failed to get the {} VG size on {}, lsvg returns: {} {}'
                      .format(vg_name, vios, ret, std_out))
        return -1, -1

    # parse lsvg outpout to get the size in megabytes:
    # VG PERMISSION:      read/write               TOTAL PPs:      558 (285696 megabytes)
    for line in std_out.split('\n'):
        line = line.rstrip()
        match_key = re.match(r".*TOTAL PPs:\s+\d+\s+\((\d+)\s+megabytes\).*", line)
        if match_key:
            vg_size = int(match_key.group(1))
            continue

        match_key = re.match(r".*USED PPs:\s+\d+\s+\((\d+)\s+megabytes\)", line)
        if match_key:
            vg_used += int(match_key.group(1))
            continue

        match_key = re.match(r".*PP SIZE:\s+(\d+)\s+megabyte\(s\)", line)
        if match_key:

            vg_used += int(match_key.group(1))
            continue

    if vg_size == -1 or vg_used == -1:
        OUTPUT.append('    Failed to get the {} VG size and the USED size on {}, parsing error'
                      .format(vg_name, vios))
        logging.error('Failed to get the {} VG size and the USED size on {}, parsing error'
                      .format(vg_name, vios))
        return -1, -1

    return vg_size, vg_used


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def find_valid_altdisk(module, action, vios_dict, vios_key, rootvg_info, altdisk_op_tab):
    """
    find a valid alternate disk that
    - exists,
    - is not part of a VG
    - with a correct size
    and so can be used.

    sets the altdisk_op_tab accordingly:
        altdisk_op_tab[vios_key] = "FAILURE-ALTDC <error message>"
        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"

    return:
        0 if alternate disk is found
        1 otherwise
    """
    global NIM_NODE
    global OUTPUT
    global PARAMS

    pvs = {}
    used_pv = []

    for vios in vios_dict:
        logging.debug('action: {}, vios: {}, vios_dict[{}]: {}, vios_key: {}'
                      .format(action, vios, vios, vios_dict[vios], vios_key))

        OUTPUT.append('    Check the alternate disk {} on {}'.format(vios_dict[vios], vios))

        err_label = "FAILURE-ALTDC"
        # check rootvg
        if rootvg_info[vios]["status"] != 0:
            altdisk_op_tab[vios_key] = "{} wrong rootvg state on {}"\
                                       .format(err_label, vios)
            return 1

        # get pv list
        pvs = get_pvs(module, vios)
        if (pvs is None) or (not pvs):
            altdisk_op_tab[vios_key] = "{} to get the list of PVs on {}"\
                                       .format(err_label, vios)
            return 1

        # check an alternate disk not already exists
        for hdisk in pvs:
            if pvs[hdisk]['vg'] == 'altinst_rootvg':
                altdisk_op_tab[vios_key] = "{} an alternate disk ({}) already exists on {}"\
                                           .format(err_label, hdisk, vios)
                OUTPUT.append('    An alternate disk is already available on disk {} on {}'
                              .format(hdisk, vios))
                logging.error('An alternate disk is already available on disk {} on {}'
                              .format(hdisk, vios))
                return 1

        pvs = get_free_pvs(module, vios)
        if (pvs is None):
            altdisk_op_tab[vios_key] = "{} to get the list of free PVs on {}"\
                                       .format(err_label, vios)
            return 1

        if (not pvs):
            altdisk_op_tab[vios_key] = "{} no disk available on {}"\
                                       .format(err_label, vios)
            return 1

        used_size = rootvg_info[vios]["used_size"]
        rootvg_size = rootvg_info[vios]["rootvg_size"]
        # in auto mode, find the first alternate disk available
        if vios_dict[vios] == "":
            prev_disk = ""
            diffsize = 0
            prev_diffsize = 0
            # parse free disks in increasing size order
            for key in sorted(pvs, key=lambda k: pvs[k]['size']):
                hdisk = key

                # disk to small or already used
                if pvs[hdisk]['size'] < used_size or pvs[hdisk]['pvid'] in used_pv:
                    continue

                # smallest disk that can be selected
                if PARAMS['disk_size_policy'] == 'minimize':
                    vios_dict[vios] = hdisk
                    if pvs[hdisk]['pvid'] != 'none':
                        used_pv.append(pvs[hdisk]['pvid'])
                    break

                diffsize = pvs[hdisk]['size'] - rootvg_size
                # matching disk size
                if diffsize == 0:
                    vios_dict[vios] = hdisk
                    if pvs[hdisk]['pvid'] != 'none':
                        used_pv.append(pvs[hdisk]['pvid'])
                    break

                if diffsize > 0:
                    # diffsize > 0: first disk found bigger than the rootvg disk
                    selected_disk = ""
                    if PARAMS['disk_size_policy'] == 'upper':
                        selected_disk = hdisk
                    elif PARAMS['disk_size_policy'] == 'lower':
                        if prev_disk == "":
                            # Best Can Do...
                            selected_disk = hdisk
                        else:
                            selected_disk = prev_disk
                    else:
                        # PARAMS['disk_size_policy'] == 'nearest'
                        if prev_disk == "":
                            selected_disk = hdisk
                        elif abs(prev_diffsize) > diffsize:
                            selected_disk = hdisk
                        else:
                            selected_disk = prev_disk

                    vios_dict[vios] = selected_disk
                    if pvs[selected_disk]['pvid'] != 'none':
                        used_pv.append(pvs[selected_disk]['pvid'])
                    break
                else:
                    # disk size less than rootvg disk size
                    #   but big enough to contain the used PPs
                    prev_disk = hdisk
                    prev_diffsize = diffsize
                    continue

            if vios_dict[vios] == "":
                if prev_disk != "":
                    # Best Can Do...
                    vios_dict[vios] = prev_disk
                    if pvs[prev_disk]['pvid'] != 'none':
                        used_pv.append(pvs[prev_disk]['pvid'])
                else:
                    altdisk_op_tab[vios_key] = "{} to find an alternate disk {} on {}"\
                                               .format(err_label, vios_dict[vios], vios)
                    OUTPUT.append('    No available alternate disk with size greater than {} MB'
                                  ' found on {}'.format(rootvg_size, vios))
                    logging.error('No available alternate disk with size greater than {} MB'
                                  ' found on {}'.format(rootvg_size, vios))
                    return 1

            logging.debug('Selected disk on vios {} is {} (select mode: {})'
                          .format(vios, vios_dict[vios], PARAMS['disk_size_policy']))

        # hdisk specified by the user
        else:
            # check the specified hdisk is large enough
            hdisk = vios_dict[vios]
            if hdisk in pvs:
                if pvs[hdisk]['pvid'] in used_pv:
                    altdisk_op_tab[vios_key] = "{} alternate disk {} already"\
                                               " used on the mirror VIOS"\
                                               .format(err_label, vios_dict[vios])
                    logging.error('Alternate disk {} already used on the mirror VIOS.'
                                  .format(vios_dict[vios]))
                    return 1
                if pvs[vios_dict[vios]]['size'] >= rootvg_size:
                    if pvs[hdisk]['pvid'] != 'none':
                        used_pv.append(pvs[hdisk]['pvid'])
                else:
                    if pvs[vios_dict[vios]]['size'] >= used_size:
                        if pvs[hdisk]['pvid'] != 'none':
                            used_pv.append(pvs[hdisk]['pvid'])
                        logging.warn('Alternate disk {} smaller than the current rootvg.'
                                     .format(vios_dict[vios]))
                    else:
                        altdisk_op_tab[vios_key] = "{} alternate disk {} too small on {}"\
                                                   .format(err_label, vios_dict[vios], vios)
                        logging.error('Alternate disk {} too small ({} < {}) on {}.'
                                      .format(vios_dict[vios], pvs[vios_dict[vios]]['size'],
                                              rootvg_size, vios))
                        return 1
            else:
                altdisk_op_tab[vios_key] = "{} disk {} is not available on {}"\
                                           .format(err_label, vios_dict[vios], vios)
                OUTPUT.append('    Alternate disk {} is not available on {}'
                              .format(vios_dict[vios], vios))
                logging.error('Alternate disk {} is either not found or not available on {}'
                              .format(vios_dict[vios], vios))
                return 1

    # Disks found
    return 0


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_rootvg(module, vios):
    """
    Check the rootvg
    - check if the rootvg is mirrored
    - check stale partitions
    - calculate the total and used size of the rootvg

    return:
        Dictionnary with following keys: value
            "status":
                0 the rootvg can be saved in a alternate disk copy
                1 otherwise (cannot unmirror then mirror again)
            "copy_dict":
                dictionary key, value
                    key: copy number (int)
                    value: hdiskx
                    example: {1: 'hdisk4', : 2: 'hdisk8', 3: 'hdisk9'}
            "rootvg_size": size in Megabytes (int)
            "used_size": size in Megabytes (int)
    """
    global NIM_NODE
    global OUTPUT

    vg_info = {}
    copy_dict = {}
    vg_info["status"] = 1
    vg_info["copy_dict"] = copy_dict
    vg_info["rootvg_size"] = 0
    vg_info["used_size"] = 0

    ret = 0
    nb_lp = 0
    copy = 0
    used_size = -1
    total_size = -1
    pp_size = -1
    pv_size = -1
    std_out = ''
    hdisk_dict = {}

    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
           NIM_NODE['nim_vios'][vios]['vios_ip'],
           '"LC_ALL=C; /usr/sbin/lsvg -M rootvg; echo $?"']
    (ret, std_out) = exec_cmd(cmd, module)
    # lsvg -M rootvg command OK, check mirroring
    # hdisk4:453      hd1:101
    # hdisk4:454      hd1:102
    # hdisk4:257      hd10opt:1:1
    # hdisk4:258      hd10opt:2:1
    # hdisk4:512-639
    # hdisk8:255      hd1:99:2        stale
    # hdisk8:256      hd1:100:2       stale
    # hdisk8:257      hd10opt:1:2
    # hdisk8:258      hd10opt:2:2
    # ..
    # hdisk9:257      hd10opt:1:3
    # ..

    if ret != 0:  # c_rsh command failed
        OUTPUT.append('    Failed to test mirror on {}: {}'
                      .format(vios, std_out))
        logging.error('Failed to test mirror on {}: {}'
                      .format(vios, std_out))
        return vg_info

    if std_out.find('stale') > 0:
        OUTPUT.append('    {} rootvg contains stale partitions'
                      .format(vios))
        logging.error('{} rootvg contains stale partitions: {}'
                      .format(vios, std_out))
        return vg_info
    hdisk = ''

    for line in std_out.split('\n'):
        line = line.rstrip()
        mirror_key = re.match(r"^(\S+):\d+\s+\S+:\d+:(\d+)$", line)
        if mirror_key:
            hdisk = mirror_key.group(1)
            copy = int(mirror_key.group(2))
        else:
            single_key = re.match(r"^(\S+):\d+\s+\S+:\d+$", line)
            if single_key:
                hdisk = single_key.group(1)
                copy = 1
            else:
                continue

        if copy == 1:
            nb_lp += 1

        if hdisk in hdisk_dict.keys():
            if hdisk_dict[hdisk] != copy:
                msg = "rootvg data structure is not compatible with an "\
                      "alt_disk_copy operation (2 copies on the same disk)"
                OUTPUT.append('    ' + msg)
                logging.error(msg)
                return vg_info
        else:
            hdisk_dict[hdisk] = copy

        if copy not in copy_dict.keys():
            if hdisk in copy_dict.values():
                msg = "rootvg data structure is not compatible with an alt_disk_copy operation"
                OUTPUT.append('    ' + msg)
                logging.error(msg)
                return vg_info
            copy_dict[copy] = hdisk

    if len(copy_dict.keys()) > 1:
        if len(copy_dict.keys()) != len(hdisk_dict.keys()):
            msg = "The {} rootvg is partially or completly mirrored but some "\
                  "LP copies are spread on several disks. This prevents the "\
                  "system from creating an alternate rootvg disk copy."\
                  .format(vios)
            OUTPUT.append('    ' + msg)
            logging.error(msg)
            return vg_info

        # the (rootvg) is mirrored then get the size of hdisk from copy1
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
               NIM_NODE['nim_vios'][vios]['vios_ip'],
               '"LC_ALL=C; /usr/sbin/lsvg -p rootvg; echo $?"']
        (ret, std_out) = exec_cmd(cmd, module)

        if ret != 0:
            OUTPUT.append('    Failed to get the pvs of rootvg on {}, lsvg returns: {}'
                          .format(vios, std_out))
            logging.error('Failed to get the pvs of rootvg on {}, lsvg returns: {} {}'
                          .format(vios, ret, std_out))
            return vg_info

        # parse lsvg outpout to get the size in megabytes:
        # rootvg:
        # PV_NAME           PV STATE          TOTAL PPs   FREE PPs    FREE DISTRIBUTION
        # hdisk4            active            639         254         126..00..00..00..128
        # hdisk8            active            639         254         126..00..00..00..128

        for line in std_out.split('\n'):
            line = line.rstrip()
            match_key = re.match(r"^(\S+)\s+\S+\s+(\d+)\s+\d+\s+\S+", line)
            if match_key:
                pv_size = int(match_key.group(2))
                if match_key.group(1) == copy_dict[1]:
                    break
                continue

        if pv_size == -1:
            OUTPUT.append('    Failed to get pv size on {}, parsing error'
                          .format(vios))
            logging.error('Failed to get pv size on {}, parsing error'
                          .format(vios))
            return vg_info

    # get now the rootvg pp size
    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
           NIM_NODE['nim_vios'][vios]['vios_ip'],
           '"LC_ALL=C; /usr/sbin/lsvg rootvg; echo $?"']
    (ret, std_out) = exec_cmd(cmd, module)

    if ret != 0:
        OUTPUT.append('    Failed to get rootvg VG size on {}, lsvg returns: {}'
                      .format(vios, std_out))
        logging.error('Failed to get rootvg VG size on {}, lsvg returns: {} {}'
                      .format(vios, ret, std_out))
        return vg_info

    # parse lsvg outpout to get the size in megabytes:
    # VG PERMISSION:      read/write               TOTAL PPs:      558 (285696 megabytes)
    for line in std_out.split('\n'):
        line = line.rstrip()
        match_key = re.match(r".*TOTAL PPs:\s+\d+\s+\((\d+)\s+megabytes\).*", line)
        if match_key:
            total_size = int(match_key.group(1))
            continue

        match_key = re.match(r".*PP SIZE:\s+(\d+)\s+megabyte\(s\)", line)
        if match_key:
            pp_size = int(match_key.group(1))
            continue

    if pp_size == -1:
        OUTPUT.append('    Failed to get rootvg pp size on {}, parsing error'
                      .format(vios))
        logging.error('Failed to get rootvg pp size on {}, parsing error'
                      .format(vios))
        return vg_info

    if len(copy_dict.keys()) > 1:
        total_size = pp_size * pv_size

    used_size = pp_size * (nb_lp + 1)

    vg_info["status"] = 0
    vg_info["copy_dict"] = copy_dict
    vg_info["rootvg_size"] = total_size
    vg_info["used_size"] = used_size
    return vg_info


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_valid_altdisk(module, action, vios, vios_dict, vios_key, altdisk_op_tab, err_label):
    """
    Check a valid alternate disk that
    - exists,
    - is an alternate disk
    and so can be used.

    sets the altdisk_op_tab acordingly:
        altdisk_op_tab[vios_key] = "FAILURE-ALTDC[12] <error message>"
        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"

    return:
        0 if alternat disk is found
        1 otherwise
    """
    global NIM_NODE
    global OUTPUT

    logging.debug('action: {}, vios: {}, vios_dict[{}]: {}, vios_key: {}'
                  .format(action, vios, vios, vios_dict[vios], vios_key))

    OUTPUT.append('    Check the alternate disk {} on {}'.format(vios_dict[vios], vios))
    pvs = {}

    pvs = get_pvs(module, vios)
    if (pvs is None) or (not pvs):
        altdisk_op_tab[vios_key] = "{} to get the list of PVs on {}"\
                                   .format(err_label, vios)
        return 1

    if vios_dict[vios] != "":
        if vios_dict[vios] in pvs and pvs[vios_dict[vios]]['vg'] == 'altinst_rootvg':
            return 0
        else:
            altdisk_op_tab[vios_key] = "{} disk {} is not an alternate install rootvg on {}"\
                                       .format(err_label, vios_dict[vios], vios)
            OUTPUT.append('    Specified disk {} is not an alternate install rootvg on {}'
                          .format(vios_dict[vios], vios))
            logging.error('Specified disk {} is not an alternate install rootvg on {}'
                          .format(vios_dict[vios], vios))
            return 1
    else:
        # check there is one and only one alternate install rootvg
        for hdisk in pvs.keys():
            if pvs[hdisk]['vg'] == 'altinst_rootvg':
                if vios_dict[vios]:
                    altdisk_op_tab[vios_key] = "{} there are several alternate"\
                                               " install rootvg on {}"\
                                               .format(err_label, vios)
                    OUTPUT.append('    There are several alternate install rootvg on {}: {} and {}'
                                  .format(vios, vios_dict[vios], hdisk))
                    logging.error('There are several alternate install rootvg on {}: {} and {}'
                                  .format(vios, vios_dict[vios], hdisk))
                    vios_dict[vios] = ""    # reset previously set hdisk
                    return 1
                else:
                    vios_dict[vios] = hdisk
        if vios_dict[vios]:
            return 0
        else:
            OUTPUT.append('    There is no alternate install rootvg on {}'.format(vios))
            logging.error('There is no alternate install rootvg on {}'.format(vios))
            return 1


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

    logging.debug('vios: {}, vios_dict[{}]: {}, vios_key: {}'
                  .format(vios, vios, vios_dict[vios], vios_key))
    logging.info('Waiting completion of alt_disk copy {} on {}...'
                 .format(vios_dict[vios], vios))
    wait_time = 0

    # if there is no progress in nim operation "info" attribute for more than
    # 30 minutes we time out: 180 * 10s = 30 min
    check_count = 0
    nim_info_prev = "___"   # this info should not appears in nim info attribute
    while check_count <= 180:
        time.sleep(10)
        wait_time += 10

        cmd = ['lsnim', '-Z', '-a', 'Cstate', '-a', 'info',
               '-a', 'Cstate_result', vios]
        (ret, std_out) = exec_cmd(cmd, module, debug_data=False)

        if ret != 0:
            altdisk_op_tab[vios_key] = "{} to get the NIM state for {}".format(err_label, vios)
            OUTPUT.append('    Failed to get the NIM state for {}: {}'
                          .format(vios, std_out))
            logging.error('Failed to get the NIM state for {}: {}'
                          .format(vios, std_out))
            break

        # info attribute (that appears in 3rd possition) can be empty. So stdout looks like:
        # #name:Cstate:info:Cstate_result:
        # <viosName>:ready for a NIM operation:success
        # <viosName>:alt_disk_install operation is being performed:
        #                 Creating logical volume alt_hd2.:success:
        # <viosName>:ready for a NIM operation:0505-126 alt_disk_install- target disk hdisk2 has
        #                 a volume group assigned to it.:failure:
        nim_status = std_out.split('\n')[1].rstrip().split(':')
        nim_Cstate = nim_status[1]
        if len(nim_status) == 4 and (string.lower(nim_status[2]) == "success"
           or string.lower(nim_status[2].lower()) == "failure"):
            nim_result = string.lower(nim_status[2])
        else:
            nim_info = nim_status[2]
            nim_result = string.lower(nim_status[3])

        if nim_Cstate == "ready for a NIM operation":
            logging.info('alt_disk copy operation on {} ended with nim_result: {}'
                         .format(vios, nim_result))
            if nim_result != "success":
                altdisk_op_tab[vios_key] = "{} to perform alt_disk copy on {} {}"\
                                           .format(err_label, vios, nim_info)
                OUTPUT.append('    Failed to perform alt_disk copy on {}: {}'
                              .format(vios, nim_info))
                logging.error('Failed to perform alt_disk copy on {}: {}'
                              .format(vios, nim_info))
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
            logging.info('Waiting completion of alt_disk copy {} on {}... {} minute(s)'
                         .format(vios_dict[vios], vios, wait_time / 60))

    # timed out before the end of alt_disk_install
    altdisk_op_tab[vios_key] = "{} alternate disk copy of {} blocked on {}: NIM operation blocked"\
                               .format(err_label, vios, nim_info)
    OUTPUT.append('    Alternate disk copy of {} blocked on {}: {}'
                  .format(vios_dict[vios], vios, nim_info))
    logging.error('Alternate disk copy of {} blocked on {}: {}'
                  .format(vios_dict[vios], vios, nim_info))

    return -1


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def alt_disk_action(module, action, targets, vios_status, time_limit):
    """
    alt_disk_copy / alt_disk_clean operation

    For line VIOS tuple,
    - retrieve the previous status if any (looking for SUCCESS-HC and SUCCESS-UPDT)
    - for each VIOS of the tuple, check the rootvg, find and valid the hdisk for the operation
    - unmirror rootvg if necessary
    - perform the alt disk copy or cleanup operation
    - wait for the copy to finish
    - mirror rootvg if necessary

    return: dictionary containing the altdisk status for each vios tuple
        altdisk_op_tab[vios_key] = "FAILURE-NO-PREV-STATUS"
        altdisk_op_tab[vios_key] = "FAILURE-ALTDC[12] <error message>"
        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"
    """
    global NIM_NODE
    global OUTPUT
    global CHANGED

    logging.debug('action: {}, targets: {}, vios_status: {}'
                  .format(action, targets, vios_status))

    rootvg_info = {}
    altdisk_op_tab = {}
    vios_key = []
    for target_tuple in targets:
        logging.debug('action: {} for target_tuple: {}'
                      .format(action, target_tuple))

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
                OUTPUT.append("    {} vioses skiped (no previous status found)"
                              .format(vios_key))
                logging.warn("{} vioses skiped (no previous status found)"
                             .format(vios_key))
                continue

            elif vios_status[vios_key] != 'SUCCESS-HC' and vios_status[vios_key] != 'SUCCESS-UPDT':
                altdisk_op_tab[vios_key] = vios_status[vios_key]
                OUTPUT.append("    {} vioses skiped ({})"
                              .format(vios_key, vios_status[vios_key]))
                logging.warn("{} vioses skiped ({})"
                             .format(vios_key, vios_status[vios_key]))
                continue

        # check if there is time to handle this tuple
        if not (time_limit is None) and time.localtime(time.time()) >= time_limit:
            altdisk_op_tab[vios_key] = "SKIPPED-TIMEDOUT"
            time_limit_str = time.strftime("%m/%d/%Y %H:%M", time_limit)
            OUTPUT.append("    Time limit {} reached, no further operation"
                          .format(time_limit_str))
            logging.info('Time limit {} reached, no further operation'
                         .format(time_limit_str))
            continue

        altdisk_op_tab[vios_key] = "SUCCESS-ALTDC"

        if action == 'alt_disk_copy':
            for vios in vios_dict:
                rootvg_info[vios] = check_rootvg(module, vios)

            ret = find_valid_altdisk(module, action, vios_dict, vios_key,
                                     rootvg_info, altdisk_op_tab)
            if ret != 0:
                continue

        for vios in vios_dict:

            # set the error label to be used in sub routines
            if action == 'alt_disk_copy':
                err_label = "FAILURE-ALTDCOPY1"
                if vios != vios1:
                    err_label = "FAILURE-ALTDCOPY2"
            elif action == 'alt_disk_clean':
                err_label = "FAILURE-ALTDCLEAN1"
                if vios != vios1:
                    err_label = "FAILURE-ALTDCLEAN2"

            OUTPUT.append('    Using {} as alternate disk on {}'.format(vios_dict[vios], vios))
            logging.info('Using {} as alternate disk on {}'.format(vios_dict[vios], vios))

            if action == 'alt_disk_copy':
                # unmirror the vg if necessary
                # check mirror

                copies_h = rootvg_info[vios]["copy_dict"]
                nb_copies = len(copies_h.keys())

                if nb_copies > 1:
                    OUTPUT.append('    Stop mmirroring on {}'.format(vios))
                    logging.warn('Stop mirror on {}'.format(vios))

                    ret = 0
                    std_out = ''
                    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
                           NIM_NODE['nim_vios'][vios]['vios_ip'],
                           '"LC_ALL=C; /usr/sbin/unmirrorvg rootvg 2>&1; echo $?"']
                    (ret, std_out) = exec_cmd(cmd, module)

                    if ret != 0:  # c_rsh command Failed
                        altdisk_op_tab[vios_key] = "{} to unmirror rootvg on {}"\
                                                   .format(err_label, vios)
                        OUTPUT.append('    Failed to unmirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        logging.error('Failed to unmirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        break
                    elif std_out.find('rootvg successfully unmirrored') == -1:
                        # unmirror command Failed
                        altdisk_op_tab[vios_key] = "{} to unmirror rootvg on {}"\
                                                   .format(err_label, vios)
                        OUTPUT.append('    Failed to unmirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        logging.error('Failed to unmirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        break
                    else:
                        # unmirror command OK
                        OUTPUT.append('    Unmirror rootvg on {} successful'
                                      .format(vios))
                        logging.info('Unmirror rootvg on {} successful'
                                     .format(vios))

                OUTPUT.append('    Alternate disk copy on {}'.format(vios))

                # alt_disk_copy
                ret_altdc = 0
                std_out = ''
                cmd = ['/usr/sbin/nim', '-o', 'alt_disk_install',
                       '-a', 'source=rootvg', '-a', 'disk={}'.format(vios_dict[vios]),
                       '-a', 'set_bootlist=no', '-a', 'boot_client=no', vios]
                (ret_altdc, std_out) = exec_cmd(cmd, module)

                if ret_altdc != 0:
                    altdisk_op_tab[vios_key] = "{} to copy {} on {}"\
                                               .format(err_label,
                                                       vios_dict[vios], vios)
                    OUTPUT.append('    Failed to copy {} on {}: {}'
                                  .format(vios_dict[vios], vios, std_out))
                    logging.error('Failed to copy {} on {}: {}'
                                  .format(vios_dict[vios], vios, std_out))
                else:
                    # wait till alt_disk_install ends
                    ret_altdc = wait_altdisk_install(module, vios, vios_dict,
                                                     vios_key, altdisk_op_tab,
                                                     err_label)

                # restore the mirroring if necessary
                if nb_copies > 1:
                    OUTPUT.append('    Restore mirror on {}'.format(vios))
                    logging.info('Restore mirror on {}'.format(vios))
                    ret = 0
                    std_out = ''
                    mirror_cmd = "LC_ALL=C; /usr/sbin/mirrorvg -m -c {} rootvg {} "\
                                 .format(nb_copies, copies_h[2])
                    if nb_copies > 2:
                        mirror_cmd += copies_h[3]
                    mirror_cmd += " 2>&1; echo $?"

                    cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
                           NIM_NODE['nim_vios'][vios]['vios_ip'], mirror_cmd]

                    (ret, std_out) = exec_cmd(cmd, module)

                    if ret != 0:  # c_rsh command Failed
                        altdisk_op_tab[vios_key] = "{} to mirror rootvg on {}"\
                                                   .format(err_label, vios)
                        OUTPUT.append('    Failed to mirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        logging.error('Failed to mirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        break
                    elif std_out.find('Failed to mirror the volume group') == -1:
                        # mirror command OK
                        OUTPUT.append('    Mirror rootvg on {} successful'
                                      .format(vios))
                        logging.info('Mirror rootvg on {} successful'
                                     .format(vios))
                    else:
                        # mirror command failed
                        altdisk_op_tab[vios_key] = "{} to mirror rootvg on {}"\
                                                   .format(err_label, vios)
                        OUTPUT.append('    Failed to mirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        logging.error('Failed to mirror rootvg on {}: {}'
                                      .format(vios, std_out))
                        break

                if ret_altdc != 0:
                    # timed out or an error occured, continue with next target_tuple
                    break

                CHANGED = True

            elif action == 'alt_disk_clean':
                OUTPUT.append('    Alternate disk clean on {}'.format(vios))

                ret = check_valid_altdisk(module, action, vios, vios_dict, vios_key,
                                          altdisk_op_tab, err_label)
                if ret != 0:
                    continue
                else:
                    OUTPUT.append('    Using {} as alternate disk on {}'
                                  .format(vios_dict[vios], vios))
                    logging.info('Using {} as alternate disk on {}'
                                 .format(vios_dict[vios], vios))

                # First remove the alternate VG
                OUTPUT.append('    Remove altinst_rootvg from {} of {}'
                              .format(vios_dict[vios], vios))
                ret = 0
                std_out = ''
                cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
                       NIM_NODE['nim_vios'][vios]['vios_ip'],
                       '"/usr/sbin/alt_rootvg_op -X altinst_rootvg; echo $?"']
                (ret, std_out) = exec_cmd(cmd, module)

                if ret != 0:
                    altdisk_op_tab[vios_key] = "{} to remove altinst_rootvg on {}"\
                                               .format(err_label, vios)
                    OUTPUT.append('    Failed to remove altinst_rootvg on {}: {}'
                                  .format(vios, std_out))
                    logging.error('Failed to remove altinst_rootvg on {}: {}'
                                  .format(vios, std_out))
                    continue

                # Clear the hdisk PVID and the LVM info on the disk itself
                OUTPUT.append('    Clean the PVID and LVM info of {} on {}'
                              .format(vios_dict[vios], vios))
                ret = 0
                std_out = ''
                cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh',
                       NIM_NODE['nim_vios'][vios]['vios_ip'],
                       '"/usr/sbin/chpv -C {}; echo $?"'
                       .format(vios_dict[vios])]
                (ret, std_out) = exec_cmd(cmd, module)

                if ret != 0:
                    altdisk_op_tab[vios_key] = "{} to clean PVID of {} on {}"\
                                               .format(err_label, vios_dict[vios], vios)
                    OUTPUT.append('    Failed to clean PVID of {} on {}: {}'
                                  .format(vios_dict[vios], vios, std_out))
                    logging.error('Failed to clean PVID of {} on {}: {}'
                                  .format(vios_dict[vios], vios, std_out))
                    continue

                OUTPUT.append('    Clean of {} Success'.format(vios_dict[vios]))
                CHANGED = True

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
    VARS = {}

    module = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            action=dict(required=True,
                        choices=['alt_disk_copy', 'alt_disk_clean'],
                        type='str'),
            time_limit=dict(required=False, type='str'),
            vars=dict(required=False, type='dict'),
            vios_status=dict(required=False, type='dict'),
            nim_node=dict(required=False, type='dict'),
            disk_size_policy=dict(required=False,
                                  choice=['minimize', 'upper', 'lower', 'nearest'],
                                  type='str'),
        ),
        supports_check_mode=True
    )

    # =========================================================================
    # Get Module params
    # =========================================================================
    action = module.params['action']
    targets = module.params['targets']

    if module.params['description']:
        description = module.params['description']
    else:
        description = "Perform an alternate disk operation: {} request".format(action)

    if module.params['disk_size_policy']:
        disk_size_policy = module.params['disk_size_policy']
    else:
        disk_size_policy = 'nearest'

    PARAMS['action'] = action
    PARAMS['targets'] = targets
    PARAMS['Description'] = description
    PARAMS['disk_size_policy'] = disk_size_policy

    if module.params['time_limit']:
        time_limit = module.params['time_limit']

    # Handle playbook variables
    if module.params['vars']:
        VARS = module.params['vars']
    if VARS is not None and 'log_file' not in VARS:
        VARS['log_file'] = '/tmp/ansible_vios_alt_disk_debug.log'

    # Open log file
    DEBUG_DATA.append('Log file: {}'.format(VARS['log_file']))
    logging.basicConfig(
        filename="{}".format(VARS['log_file']),
        format='[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s',
        level=logging.DEBUG)

    logging.debug('*** START VIOS {} ***'.format(action.upper()))

    OUTPUT.append('VIOS Alternate disk operation for {}'.format(targets))
    logging.info('action {} for {} targets'.format(action, targets))

    vios_status = {}
    targets_altdisk_status = {}
    target_list = []

    # =========================================================================
    # build nim node info
    # =========================================================================
    if module.params['nim_node']:
        NIM_NODE = module.params['nim_node']
    else:
        build_nim_node(module)

    if module.params['vios_status']:
        vios_status = module.params['vios_status']
    else:
        vios_status = None

    # build a time structurei for time_limit attribute,
    time_limit = None
    if module.params['time_limit']:
        match_key = re.match(r"^\s*\d{2}/\d{2}/\d{4} \S*\d{2}:\d{2}\s*$",
                             module.params['time_limit'])
        if match_key:
            time_limit = time.strptime(module.params['time_limit'], '%m/%d/%Y %H:%M')
        else:
            msg = 'Malformed time limit "{}", please use mm/dd/yyyy hh:mm format.'\
                  .format(module.params['time_limit'])
            module.fail_json(msg=msg)

    # =========================================================================
    # Perfom check and operation
    # =========================================================================
    ret = check_vios_targets(targets)
    if (ret is None) or (not ret):
        OUTPUT.append('    Warning: Empty target list')
        logging.warn('Empty target list: "{}"'.format(targets))
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
