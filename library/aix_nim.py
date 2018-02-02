#!/usr/bin/python
#
# Copyright 2016, International Business Machines Corporation
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
"""AIX NIM: server setup, install packages, update SP or TL"""

import re
import subprocess
import threading
import logging
# Ansible module 'boilerplate'
# pylint: disable=wildcard-import,unused-wildcard-import,redefined-builtin
from ansible.module_utils.basic import *


DOCUMENTATION = """
---
module: aix_nim
author: "Alain Poncet, Patrice Jacquin"
version_added: "1.0.0"
requirements: [ AIX ]

"""


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def run_oslevel_cmd(machine, result):
    """
    Run command function, command to be 'threaded'.

    The thread then store the outpout in the dedicated slot of the result
    dictionnary.

    arguments:
        machine (str): The name machine
        result  (dict): The result of the command
    """
    if machine == 'master':
        cmd = ['/usr/bin/oslevel', '-s']

    else:
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine,
               '/usr/bin/oslevel -s']

    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE,
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

    logging.debug('exec command:{}'.format(cmd))
    try:
        std_out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
               format(cmd, exc.cmd, exc.output, exc.returncode)
        module.fail_json(msg=msg)
    except Exception as exc:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
               format(cmd, exc.args, std_out, std_err)
        module.fail_json(msg=msg)

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    DEBUG_DATA.append('exec command:{}'.format(cmd))
    DEBUG_DATA.append('exec command Error:{}'.format(std_err))
    logging.debug('exec command Error:{}'.format(std_err))
    logging.debug('exec command output:{}'.format(std_out))
    # --------------------------------------------------------

    return (0, std_out)


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_clients_info(module):
    """
    Get the list of the standalones defined on the nim master, and get their
    cstate.

    return the list of the name of the standlone objects defined on the
           nim master and their associated cstate value
    """
    std_out = ''
    std_err = ''
    info_hash = {}

    cmd = ['lsnim', '-t', 'standalone', '-l']

    try:
        proc = subprocess.Popen(cmd, shell=False, stdin=None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = proc.communicate()
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    # client name and associated Cstate
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
            info_hash[obj_key] = {}
        else:
            match_cstate = re.match(r"^\s+Cstate\s+=\s+(.*)$", line)
            if match_cstate:
                cstate = match_cstate.group(1)
                info_hash[obj_key]['cstate'] = cstate

    return info_hash


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_master_info(module):
    """
    Get the cstate.of the nim master
    """
    std_out = ''
    std_err = ''
    cstate = ''

    cmd = ['lsnim', '-l', 'master']

    try:
        proc = subprocess.Popen(cmd, shell=False, stdin=None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = proc.communicate()
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    # client name and associated Cstate
    for line in std_out.rstrip().split('\n'):
        match_cstate = re.match(r"^\s+Cstate\s+=\s+(.*)$", line)
        if match_cstate:
            cstate = match_cstate.group(1)

    return cstate


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_clients_oslevel():
    """
    Get the oslevel of the standalones defined on the nim master.

    return a hash of the standlone oslevel
    """

    # =========================================================================
    # Launch threads to collect information on targeted nim clients
    # =========================================================================
    threads = []
    clients_oslevel = {}

    for machine in NIM_NODE['nim_clients']:
        process = threading.Thread(target=run_oslevel_cmd,
                                   args=(machine, clients_oslevel))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

    return clients_oslevel


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_master_oslevel():
    """
    Get the oslevel of the nim master.
    """

    master_oslevel = {}
    run_oslevel_cmd('master', master_oslevel)

    return master_oslevel['master']


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_lpp_source(module):
    """
    Get the list of the lpp_source defined on the nim master.

    arguments:
        None

    return:
        ret code: 0 - OK
                  1 - CalledProcessError exception
                  2 - other exception
        std_out of the command or stderr in case of error
    """
    std_out = ''
    # std_err = ''
    lpp_source_list = {}

    cmd = ['lsnim', '-t', 'lpp_source', '-l']

    ret, std_out = exec_cmd(cmd, module)

    if ret != 0:
        return ret, std_out

    # lpp_source list
    for line in std_out.rstrip().split('\n'):
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
        else:
            match_loc = re.match(r"^\s+location\s+=\s+(\S+)$", line)
            if match_loc:
                loc = match_loc.group(1)
                lpp_source_list[obj_key] = loc

    return 0, lpp_source_list


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def build_nim_node(module):
    """
    build the nim node containing the nim client info and the lpp source
    info.

    arguments:
        None

    return:
        None
    """

    global NIM_NODE

    # =========================================================================
    # build nim lpp_source list
    # =========================================================================
    nim_lpp_sources = {}
    ret, nim_lpp_sources = get_nim_lpp_source(module)
    if ret != 0:
        logging.error('NIM - Error getting the lpp_source list - rc:{}, error:{}'
                      .format(ret, nim_lpp_sources))
        module.fail_json(msg="NIM Error getting th lpp_source list - rc:{}, error:{}"
                         .format(ret, nim_lpp_sources))

    NIM_NODE['lpp_source'] = nim_lpp_sources
    logging.debug('lpp source list: {}'.format(nim_lpp_sources))

    # =========================================================================
    # Build nim_clients info list
    # =========================================================================
    nim_clients = {}
    nim_clients = get_nim_clients_info(module)

    NIM_NODE['nim_clients'] = nim_clients
    logging.debug('NIM Clients: {}'.format(nim_clients))

    # =========================================================================
    # get the oslevel of each client
    # =========================================================================
    clients_oslevel = {}
    clients_oslevel = get_nim_clients_oslevel()

    for (k, val) in clients_oslevel.items():
        NIM_NODE['nim_clients'][k]['oslevel'] = val
    logging.debug('NIM Clients: {}'.format(nim_clients))

    # =========================================================================
    # Build master info list
    # =========================================================================
    cstate = get_nim_master_info(module)

    NIM_NODE['master'] = {}
    NIM_NODE['master']['cstate'] = cstate
    logging.debug('NIM master: Cstate = {}'.format(cstate))

    # =========================================================================
    # get the oslevel of the nim master
    # =========================================================================
    oslevel = get_nim_master_oslevel()

    NIM_NODE['master']['oslevel'] = oslevel
    logging.debug('NIM master: oslevel = {}'.format(oslevel))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def expand_targets(targets):
    """
    Expand the list of the targets.

    a taget name could be of the following form:
        target*       all the nim client machines whose name starts
                          with 'target'
        target[n1:n2] where n1 and n2 are numeric: target<n1> to target<n2>
        * or ALL      all the nim client machines
        client_name   the nim client named 'client_name'
        master        the nim master

        sample:  target[1:5] target12 other_target*

    arguments:
        machine (str): The name machine
        result  (dict): The result of the command

    return: the list of the existing machines matching the target list
    """

    clients = []
    targets_list = targets.split(' ')

    # ===========================================
    # Build targets list
    # ===========================================
    for target in targets_list:

        # -----------------------------------------------------------
        # Build target(s) from: range i.e. quimby[7:12]
        # -----------------------------------------------------------
        rmatch = re.match(r"(\w+)\[(\d+):(\d+)\]", target)
        if rmatch:

            name = rmatch.group(1)
            start = rmatch.group(2)
            end = rmatch.group(3)

            for i in range(int(start), int(end) + 1):
                # target_results.append('{0}{1:02}'.format(name, i))
                curr_name = name + str(i)
                if curr_name in NIM_NODE['nim_clients']:
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: val*. i.e. quimby*
        # -----------------------------------------------------------
        rmatch = re.match(r"(\w+)\*$", target)
        if rmatch:

            name = rmatch.group(1)

            for curr_name in NIM_NODE['nim_clients']:
                if re.match(r"^%s\.*" % name, curr_name):
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: all or *
        # -----------------------------------------------------------
        if target.upper() == 'ALL' or target == '*':
            clients = list(NIM_NODE['nim_clients'])
            continue

        # -----------------------------------------------------------
        # Build target(s) from: quimby05 quimby08 quimby12
        # -----------------------------------------------------------
        if (target in NIM_NODE['nim_clients']) or (target == 'master'):
            clients.append(target)

    return list(set(clients))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def print_node_by_columns():
    """
    Build an array with the oslevel and the Cstate of each nim client

    return: the strings array
    """

    # -----------------------------------------------------------------
    # Print node in column format
    #
    #    +---------+-----------------+---------------------------+
    #    | machine |     oslevel     |          Cstate           |
    #    +---------+-----------------+---------------------------+
    #    | client1 | 7100-01-04-1216 | ready for a NIM operation |
    #    | client2 | 7100-03-01-1341 | ready for a NIM operation |
    #    | client3 | 7100-04-00-0000 | ready for a NIM operation |
    #    | master  | 7200-01-00-0000 |                           |
    #    +---------+-----------------+---------------------------+
    #

    widths = {}
    result = ''
    widths['machine'] = 7
    widths['oslevel'] = 7
    widths['cstate'] = 6

    # get the longest string size for each column
    for (k, val) in NIM_NODE['nim_clients'].items():
        if widths['machine'] < len(k):
            widths['machine'] = len(k)

        if widths['oslevel'] < len(val['oslevel']):
            widths['oslevel'] = len(val['oslevel'])

        if widths['cstate'] < len(val['cstate']):
            widths['cstate'] = len(val['cstate'])

    widths['machine'] += 2
    widths['oslevel'] += 2
    widths['cstate'] += 2

    # build the array
    sep = '\n' + '+' + '-' * widths['machine'] + '+' + \
          '-' * widths['oslevel'] + '+' + '-' * widths['cstate'] + '+'

    head = '\n' + \
           '|' + '{:^{wid}}'.format('machine', wid=widths['machine']) + \
           '|' + '{:^{wid}}'.format('oslevel', wid=widths['oslevel']) + \
           '|' + '{:^{wid}}'.format('Cstate', wid=widths['cstate']) + '|'

    result = sep + head + sep

    for (k, val) in NIM_NODE['nim_clients'].items():
        line = '\n' + \
               '|' + '{0:^{1}}'.format(k, widths['machine']) + \
               '|' + '{0:^{1}}'.format(val['oslevel'], widths['oslevel']) + \
               '|' + '{0:^{1}}'.format(val['cstate'], widths['cstate']) + '|'
        result += line

    # master
    line = '\n' + \
           '|' + '{0:^{1}}'.format('master', widths['machine']) + \
           '|' + '{0:^{1}}'.format(NIM_NODE['master']['oslevel'], widths['oslevel']) + \
           '|' + '{0:^{1}}'.format(NIM_NODE['master']['cstate'], widths['cstate']) + '|'
    result += line

    result += sep

    return result


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def perform_async_customization(module, lpp_source, targets):
    """
    Perform an asynchronous customization of the given targets clients,
    applying the given lpp_source

    stdout and stderr are outputed in log file at info level

    return: the return code of the command.
    """

    global NIM_OUTPUT

    logging.debug('NIM - perform_async_customization - lpp_spource: {}, targets: {} '
                  .format(lpp_source, targets))

    cmde = '/usr/sbin/nim -o cust -a lpp_source={} -a fixes=update_all '\
           '-a accept_licenses=yes -a async=yes {}'.format(lpp_source, targets)

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('Start updating machine(s) {} to {}'
                      .format(targets, lpp_source))

    do_not_error = False

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))
    NIM_OUTPUT.append('{}'.format(stderr))

    for line in stdout.rstrip().split('\n'):
        line = line.rstrip()
        matched = re.match(r"Either the software is already at the same level as on the media, or",
                           line)
        if matched:
            do_not_error = True

    NIM_OUTPUT.append('NIM - Finish updating {} asynchronously.'
                      .format(targets))
    if ret != 0 or do_not_error:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        NIM_OUTPUT.append('NIM - Error: Command {} returns above error!'
                          .format(cmde))

    logging.info("Done nim customize operation {}".format(cmde))

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def perform_sync_customization(module, lpp_source, targets):
    """
    Perform a synchronous customization of the given targets clients,
    applying the given lpp_source

    stdout and stderr are outputed in log file at info level

    return: the return code of the command.
    """

    global NIM_OUTPUT

    logging.debug(
        'NIM - perform_sync_customization - lpp_spource: {}, targets: {} '
        .format(lpp_source, targets))

    cmde = '/usr/sbin/nim -o cust -a lpp_source={} -a fixes=update_all '\
           '-a accept_licenses=yes -a async=no {}'.format(lpp_source, targets)

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('Start updating machine(s) {} to {}'
                      .format(targets, lpp_source))

    do_not_error = False

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    for line in stdout.rstrip().split('\n'):
        NIM_OUTPUT.append('{}'.format(line))
        line = line.rstrip()
        matched = re.match(r"^Filesets processed:.*?[0-9]+ of [0-9]+", line)
        if matched:
            NIM_OUTPUT.append('\033[2K\r{}'.format(line))
            continue
        matched = re.match(r"^Finished processing all filesets.", line)
        if matched:
            NIM_OUTPUT.append('\033[2K\r{}'.format(line))
            continue

    for line in stderr.rstrip().split('\n'):
        line = line.rstrip()
        matched = re.match(r"^Either the software is already at the same level as on the media, or",
                           line)
        if matched:
            do_not_error = True

    NIM_OUTPUT.append('NIM - Finish updating {} synchronously.'.format(targets))
    if ret != 0 or do_not_error:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        NIM_OUTPUT.append('NIM - Error: Command {} returns above error!'
                          .format(cmde))

    logging.info("Done nim customize operation {}".format(cmde))

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def list_fixes(target, module):
    """
    Get the list of the interim fixes for a specified nim client

    return: a return code (0 if ok)
            the list of the fixes
    """

    global NIM_OUTPUT

    fixes = []
    if target == 'master':
        cmde = '/usr/sbin/emgr -l'
    else:
        cmde = '/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} \"/usr/sbin/emgr -l\"'\
               .format(target)
    logging.debug('EMGR list - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    for line in stdout.rstrip().split('\n'):
        line = line.rstrip()
        line_array = line.split(' ')
        matched = re.match(r"[0-9]", line_array[0])
        if matched:
            logging.debug('EMGR list - adding fix {} to fixes list'
                          .format(line_array[2]))
            fixes.append(line_array[2])

    NIM_OUTPUT.append('{}'.format(stderr))

    if ret != 0:
        logging.error("Error: Command: {} failed with return code {}"
                      .format(cmde, ret))
        NIM_OUTPUT.append('EMGR list - Error: Command {} returns above error!'
                          .format(cmde))

    return(ret, fixes)


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def remove_fix(target, fix, module):
    """
    Remove an interim fixe for a specified nim client

    return: the return code of the command.
    """

    global NIM_OUTPUT

    if target == 'master':
        cmde = '/usr/sbin/emgr -r -L {}'.format(fix)
    else:
        cmde = '/usr/lpp/bos.sysmgt/nim/methods/c_rsh {} \"/usr/sbin/emgr -r -L {}\"'\
               .format(target, fix)
    logging.debug('EMGR remove - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))
    NIM_OUTPUT.append('{}'.format(stderr))

    if ret != 0:
        logging.error("Error: Command: {} failed with return code {}"
                      .format(cmde, ret))
        NIM_OUTPUT.append('EMGR remove - Error: Command {} returns above error!'
                          .format(cmde))

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def find_resource_by_client(lpp_type, lpp_time, oslevel_elts):
    """
    Retrieve the good SP or TL resource to associate to the nim client oslevel

    parameters: lpp_typs   SP or TL
                lpp_time   next or latest

    return: the lpp_sourec found or the current oslevel in not found
    """

    logging.debug('NIM - find resource: {} {}'.format(lpp_time, lpp_type))

    lpp_source = ''
    lpp_source_list = sorted(NIM_NODE['lpp_source'].keys())

    if lpp_type == 'tl':
        # reading lpp_source table until we have found the good tl
        for lpp in lpp_source_list:
            lpp_elts = lpp.split('-')
            if lpp_elts[0] != oslevel_elts[0] or lpp_elts[1] <= oslevel_elts[1]:
                continue
            lpp_source = lpp
            if lpp_time == 'next':
                break

    if lpp_type == 'sp':
        # reading lpp_source table until we have found the good sp
        for lpp in lpp_source_list:
            lpp_elts = lpp.split('-')
            if lpp_elts[0] != oslevel_elts[0] or \
               lpp_elts[1] != oslevel_elts[1] or lpp_elts[2] <= oslevel_elts[2]:
                continue
            lpp_source = lpp
            if lpp_time == 'next':
                break

    if (lpp_source is None) or (not lpp_source.strip()):
        # setting lpp_source to current oslevel if not found
        lpp_source = '{}-{}-{}-{}-lpp_source'.format(oslevel_elts[0], oslevel_elts[1],
                                                     oslevel_elts[2], oslevel_elts[3])
        logging.debug('NIM - find resource: server already to the {} {}, or no lpp_source were '
                      'found, {} will be utilized'.format(lpp_time, lpp_type, lpp_source))
    else:
        logging.debug('NIM - find resource: found the {} lpp_source, {} will be utilized'
                      .format(lpp_time, lpp_source))

    return lpp_source


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_update(module):
    """
    Update nim clients (targets) with a specified lpp_source

    In case of updating to the latest TL or SP the synchronous mode is forced
    Interim fixes that could block the install are removed

    return: a return code (O if Ok)
    """

    global NIM_CHANGED

    lpp_source = NIM_PARAMS['lpp_source']
    async_update = 'no'

    if NIM_PARAMS['async'] == 'true':
        async_update = 'yes'
        log_async = 'asynchronous'
    else:
        log_async = 'synchronous'

    logging.info('NIM - {} update operation on {} with {} lpp_source'
                 .format(log_async, NIM_PARAMS['targets'], lpp_source))

    if NIM_PARAMS['async'] == 'true' and \
       (lpp_source == 'latest_tl' or lpp_source == 'latest_sp' or
        lpp_source == 'next_tl' or lpp_source == 'next_sp'):
        logging.warning('Force customization synchronously')
        async_update = 'no'

    target_list = expand_targets(NIM_PARAMS['targets'])
    logging.debug('NIM - Target list: {}'.format(target_list))

    # force interim fixes automatic removal
    if NIM_PARAMS['force'] == 'true':
        for target in target_list:
            (ret, fixes) = list_fixes(target, module)
            if ret != 0:
                logging.info("Continue to remove as many interim fixes we can")
            for fix in fixes:
                remove_fix(target, fix, module)
                logging.warning("Interim fix {} has been automatically removed from {}"
                                .format(fix, target))

    if async_update == 'yes':   # async update
        if lpp_source not in NIM_NODE['lpp_source']:
            logging.error('NIM - Error: cannot find lpp_source {}'
                          .format(lpp_source))
            module.fail_json(msg="NIM - Error: cannot find lpp_source {}"
                             .format(NIM_NODE['lpp_sources']))
        else:
            logging.info('NIM - perform asynchronous software customization for client(s) {} '
                         'with resource {}'.format(' '.join(target_list), lpp_source))
            perform_async_customization(module, lpp_source, ' '.join(target_list))

    else:    # synchronous update
        for target in target_list:
            # get current oslevel
            cur_oslevel = ''
            if target == 'master':
                cur_oslevel = NIM_NODE['master']['oslevel']
            else:
                cur_oslevel = NIM_NODE['nim_clients'][target]['oslevel']
            logging.debug('NIM - current oslevel: {}'.format(cur_oslevel))
            if (cur_oslevel is None) or (not cur_oslevel.strip()):
                logging.warning('Cannot get oslevel for machine {}'.format(target))
                continue
            cur_oslevel_elts = cur_oslevel.split('-')

            # get lpp source
            new_lpp_source = ''
            if (lpp_source == 'latest_tl') or (lpp_source == 'latest_sp') or \
               (lpp_source == 'next_tl') or (lpp_source == 'next_sp'):
                lpp_source_array = lpp_source.split('_')
                lpp_time = lpp_source_array[0]
                lpp_type = lpp_source_array[1]
                new_lpp_source = find_resource_by_client(lpp_type, lpp_time,
                                                         cur_oslevel_elts)
                logging.debug('NIM - new_lpp_source: {}'.format(new_lpp_source))
            else:
                if lpp_source not in NIM_NODE['lpp_source']:
                    logging.error('NIM - Error: cannot find lpp_source {}'
                                  .format(lpp_source))
                    module.fail_json(msg="NIM - Error: cannot find lpp_source {}"
                                     .format(NIM_NODE['lpp_source']))
                else:
                    new_lpp_source = lpp_source

            # extract oslevel from lpp source
            oslevel_elts = []
            matched = re.match(r"^([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})-lpp_source$",
                               new_lpp_source)
            if matched:
                oslevel_elts = matched.group(1).split('-')
            else:
                logging.warning('Cannot get oslevel from lpp source name {}'
                                .format(new_lpp_source))
                continue

            if cur_oslevel_elts[0] != oslevel_elts[0]:
                logging.warning('Machine {} has different release than {}'
                                .format(target, oslevel_elts[0]))
                continue
            elif cur_oslevel_elts[1] > oslevel_elts[1] or \
                 cur_oslevel_elts[1] == oslevel_elts[1] and \
                 cur_oslevel_elts[2] >= oslevel_elts[2]:
                logging.warning('Machine {} is already at same or higher level than {}'
                                .format(target, '-'.join(oslevel_elts)))
                continue
            else:
                logging.info('Machine {} needs upgrade from {} to {}'
                             .format(target, cur_oslevel, '-'.join(oslevel_elts)))

            logging.info('NIM - perform synchronous software customization for client(s) {} '
                         'with resource {}'.format(target, new_lpp_source))
            perform_sync_customization(module, new_lpp_source, target)

    NIM_CHANGED = True
    return


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_master_setup(module):
    """
    Setup a nim master

    parameter: the device (directory) where to find the lpp source to install

    return: a return code (O if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - master setup operation using {} device'
                 .format(NIM_PARAMS['device']))

    cmde = 'nim_master_setup -B -a mk_resource=no -a device={}'\
           .format(NIM_PARAMS['device'])

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(msg="NIM Command: {} failed with return code {} => Error :{}"
                         .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_check():
    """
    Output an array containing the oslevel and the Cstate of each nim client

    return: a return code (0)
    """

    global NIM_OUTPUT

    logging.info('NIM - check operation')

    out = print_node_by_columns()

    NIM_OUTPUT.append('check update status:')
    NIM_OUTPUT.append(out.split('\n'))

    return 0


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_compare(module):
    """
    Compare installation inventory of the nim clients

    return: a return code (0)
    """
    global NIM_OUTPUT

    logging.info('NIM - installation inventory comparison for {} clients'
                 .format(NIM_PARAMS['targets']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    cmde = 'niminv -o invcmp -a targets={} -a base=any'\
           .format(','.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_OUTPUT.append('compare installation inventory:')
    NIM_OUTPUT.append(stdout.split('\n'))

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_script(module):
    """
    Apply a script to customize nim client targets

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    async_script = ''
    if NIM_PARAMS['async'] == 'true':
        async_script = 'yes'
        log_async = 'asynchronous'
    else:
        async_script = 'no'
        log_async = 'synchronous'

    logging.info('NIM - {} customize operation on {} with {} script'
                 .format(log_async, NIM_PARAMS['targets'], NIM_PARAMS['script']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    cmde = 'nim -o cust -a script={} -a async={} {}'\
           .format(NIM_PARAMS['script'], async_script, ' '.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_allocate(module):
    """
    Allocate a resource to specified nim clients

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - alloacte operation on {} for {} lpp source'
                 .format(NIM_PARAMS['targets'], NIM_PARAMS['lpp_source']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    cmde = 'nim -o allocate -a lpp_source={} {}'\
           .format(NIM_PARAMS['lpp_source'], ' '.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_deallocate(module):
    """
    Deallocate a resource for specified nim clients

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - dealloacte operation on {} for {} lpp source'
                 .format(NIM_PARAMS['targets'], NIM_PARAMS['lpp_source']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    cmde = 'nim -o deallocate -a lpp_source={} {}'\
           .format(NIM_PARAMS['lpp_source'], ' '.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_bos_inst(module):
    """
    Install a given list of nim clients.
    A specified group of resource (resource) is used to install the nim
        clients (targets).
        If specified a script is applied to customized the installation.

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - bos_inst operation on {} using {} resource group'
                 .format(NIM_PARAMS['targets'], NIM_PARAMS['group']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    if NIM_PARAMS['script'] and NIM_PARAMS['script'].strip():
        script = '-a script={}'.format(NIM_PARAMS['script'])
    else:
        script = ''

    cmde = 'nim -o bos_inst -a source=mksysb -a group={} {} {}'\
           .format(NIM_PARAMS['group'], script, ' '.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_define_script(module):
    """
    Define a script nim resource
    A script resource is defined using the specified script location

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info(
        'NIM - define script operation for {} ressource with location {}'
        .format(NIM_PARAMS['resource'], NIM_PARAMS['location']))

    cmde = 'nim -o define -t script -a location={} -a server=master {}'\
           .format(NIM_PARAMS['location'], NIM_PARAMS['resource'])

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_remove(module):
    """
    Remove a specified nim resource
    Remove a nim resource from the nim data base. The location of the
        resource is not destroyed.

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - remove operation on {} ressource'
                 .format(NIM_PARAMS['resource']))

    cmde = 'nim -o remove {}'.format(NIM_PARAMS['resource'])

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_reset(module):
    """
    Reset the Cstate of a nim client.
    If the Cstate of the nim client is already in ready state, a warning is
        issued an no operation is made for this client.

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    ret = 0
    logging.info('NIM - reset operation on {} ressource'
                 .format(NIM_PARAMS['targets']))

    logging.debug('NIM - force is {}'.format(NIM_PARAMS['force']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    force = ''
    if NIM_PARAMS['force'] == 'true':
        force = '-F'

    # remove from the list the targets that are already in "ready' state
    targets_to_reset = []
    targets_discarded = []
    for target in target_list:
        if NIM_NODE['nim_clients'][target]['cstate'] != 'ready for a NIM operation':
            targets_to_reset.append(target)
        else:
            targets_discarded.append(target)

    if targets_discarded:
        logging.warning('The following targets are already in a correct state: {}'
                        .format(','.join(targets_discarded)))

    if targets_to_reset:
        cmde = 'nim {} -o reset {}'.format(force, ' '.join(targets_to_reset))

        logging.debug('NIM - Command:{}'.format(cmde))
        NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

        ret, stdout, stderr = module.run_command(cmde)

        logging.info("[RC] {}".format(ret))
        logging.info("[STDOUT] {}".format(stdout))
        logging.info("[STDERR] {}".format(stderr))

        if ret != 0:
            logging.error("Error: NIM Command: {} failed with return code {}"
                          .format(cmde, ret))
            module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

        NIM_CHANGED = True

    return ret


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_reboot(module):
    """
    Reboot the given nim clients if they are running

    return: a return code (0 if Ok)
    """

    global NIM_CHANGED
    global NIM_OUTPUT

    logging.info('NIM - reboot operation on {}'.format(NIM_PARAMS['targets']))

    target_list = expand_targets(NIM_PARAMS['targets'])

    logging.debug('NIM - Target list: {}'.format(target_list))

    if 'master' in target_list:
        logging.warning('master can not be rebooted, master is discarded from the target list')
        target_list.remove('master')

    cmde = 'nim -o reboot {}'.format(' '.join(target_list))

    logging.debug('NIM - Command:{}'.format(cmde))
    NIM_OUTPUT.append('NIM - Command:{}'.format(cmde))

    ret, stdout, stderr = module.run_command(cmde)

    logging.info("[RC] {}".format(ret))
    logging.info("[STDOUT] {}".format(stdout))
    logging.info("[STDERR] {}".format(stderr))

    if ret != 0:
        logging.error("Error: NIM Command: {} failed with return code {}"
                      .format(cmde, ret))
        module.fail_json(
               msg="NIM Command: {} failed with return code {} => Error :{}"
               .format(cmde, ret, stderr.split('\n')))

    NIM_CHANGED = True
    return ret


################################################################################

if __name__ == '__main__':

    DEBUG_DATA = []
    NIM_OUTPUT = []
    NIM_PARAMS = {}
    NIM_NODE = {}
    NIM_CHANGED = False

    MODULE = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),
            lpp_source=dict(required=False, type='str'),
            targets=dict(required=False, type='str'),
            async=dict(choices=['true', 'false'], default='false', type='str'),
            device=dict(required=False, type='str'),
            script=dict(required=False, type='str'),
            resource=dict(required=False, type='str'),
            location=dict(required=False, type='str'),
            group=dict(required=False, type='str'),
            force=dict(choices=['true', 'false'], default='false', type='str'),
            action=dict(choices=['update', 'master_setup', 'check', 'compare',
                                 'script', 'allocate', 'deallocate',
                                 'bos_inst', 'define_script', 'remove',
                                 'reset', 'reboot'], type='str'),
        ),
        required_if=[
            ['action', 'update', ['lpp_source', 'targets']],
            ['action', 'master_setup', ['device']],
            ['action', 'compare', ['targets']],
            ['action', 'script', ['targets', 'script']],
            ['action', 'allocate', ['targets', 'lpp_source']],
            ['action', 'deallocate', ['targets', 'lpp_source']],
            ['action', 'bos_inst', ['targets', 'group']],
            ['action', 'define_script', ['resource', 'location']],
            ['action', 'remove', ['resource']],
            ['action', 'reset', ['targets']],
            ['action', 'reboot', ['targets']]
        ],
        supports_check_mode=True
    )

    # Open log file
    logging.basicConfig(filename='/tmp/ansible_nim_debug.log',
                        format='[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s',
                        level=logging.DEBUG)
    logging.debug('*** START ***')

    # =========================================================================
    # Get Module params
    # =========================================================================
    lpp_source = MODULE.params['lpp_source']
    targets = MODULE.params['targets']
    async_par = MODULE.params['async']
    device = MODULE.params['device']
    script = MODULE.params['script']
    resource = MODULE.params['resource']
    location = MODULE.params['location']
    group = MODULE.params['group']
    force = MODULE.params['force']
    action = MODULE.params['action']

    if MODULE.params['description']:
        description = MODULE.params['description']
    else:
        description = "NIM operation: {} request".format(action)

    NIM_PARAMS['Description'] = description
    NIM_PARAMS['action'] = action

    # =========================================================================
    # build nim node info
    # =========================================================================
    build_nim_node(MODULE)

    logging.info('NIM - action {}'.format(action))

    if action == 'update':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['lpp_source'] = lpp_source
        NIM_PARAMS['async'] = async_par
        NIM_PARAMS['force'] = force
        nim_update(MODULE)

    elif action == 'master_setup':
        NIM_PARAMS['device'] = device
        nim_master_setup(MODULE)

    elif action == 'check':
        nim_check()

    elif action == 'compare':
        NIM_PARAMS['targets'] = targets
        nim_compare(MODULE)

    elif action == 'script':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['script'] = script
        NIM_PARAMS['async'] = async_par
        nim_script(MODULE)

    elif action == 'allocate':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['lpp_source'] = lpp_source
        nim_allocate(MODULE)

    elif action == 'deallocate':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['lpp_source'] = lpp_source
        nim_deallocate(MODULE)

    elif action == 'bos_inst':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['group'] = group
        NIM_PARAMS['script'] = script
        nim_bos_inst(MODULE)

    elif action == 'define_script':
        NIM_PARAMS['resource'] = resource
        NIM_PARAMS['location'] = location
        nim_define_script(MODULE)

    elif action == 'remove':
        NIM_PARAMS['resource'] = resource
        nim_remove(MODULE)

    elif action == 'reset':
        NIM_PARAMS['targets'] = targets
        NIM_PARAMS['force'] = force
        ret = nim_reset(MODULE)

    elif action == 'reboot':
        NIM_PARAMS['targets'] = targets
        ret = nim_reboot(MODULE)

    else:
        logging.error('NIM - Error: Unknowned action {}'.format(action))
        MODULE.fail_json(msg='NIM - Error: Unknowned action {}'.format(action))

    # ==========================================================================
    # Exit
    # ==========================================================================
    MODULE.exit_json(
        changed=NIM_CHANGED,
        msg="NIM {} completed successfully".format(action),
        debug_output=DEBUG_DATA,
        nim_output=NIM_OUTPUT)
