#!/usr/bin/python
#
# Copyright (c) 2017, IBM Corp
#
# AIX SUMA module for Ansible :
# https://github.com/ansible-aix/patch_mgmt
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

import os
import re
import glob
import shutil
import subprocess
import threading
import logging

"""
module: aix_suma
author: "Cyril Bouhallier, Patrice Jacquin"
version_added: "1.0.0"
requirements: [ AIX ]
"""

SUMA_OUTPUT = []
PARAMS = {}

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def min_oslevel(dic):
    """Find the minimun value of a dictionnary.

    arguments:
        dict - Dictionnary {machine: oslevel}
    return:
        minimun oslevel from the dictionnary
    """
    oslevel_min = None

    for key, value in iter(dic.items()):
        if oslevel_min is None or value < oslevel_min:
            oslevel_min = value

    return oslevel_min


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def max_oslevel(dic):
    """Find the maximum value of a the oslevel dictionary.

    arguments:
        dic - Dictionnary {client: oslevel}
    return:
        maximum oslevel from the dictionnary
    """
    oslevel_max = None

    for key, value in iter(dic.items()):
        if oslevel_max is None or value > oslevel_max:
            oslevel_max = value

    return oslevel_max


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def run_cmd(machine, result):
    """Run command function, command to be 'threaded'.

    The thread then store the outpout in the dedicated slot of the result
    dictionnary.

    arguments:
        machine (str): The name machine
        result  (dict): The result of the command
    """
    if machine == 'master':
        cmd = ['/usr/bin/oslevel -s']

    else:
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine,
               '/usr/bin/oslevel -s']

    proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, \
                         stderr=subprocess.PIPE)

    # return stdout only ... stripped!
    result[machine] = proc.communicate()[0].rstrip()


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def expand_targets(targets_list, nim_clients):
    """Expand the list of the targets.

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
                if curr_name in nim_clients:
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: val*. i.e. quimby*
        # -----------------------------------------------------------
        rmatch = re.match(r"(\w+)\*$", target)
        if rmatch:

            name = rmatch.group(1)

            for curr_name in nim_clients:
                if re.match(r"^%s\.*" % name, curr_name):
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: all or *
        # -----------------------------------------------------------
        if target.upper() == 'ALL' or target == '*':
            clients = nim_clients
            continue

        # -----------------------------------------------------------
        # Build target(s) from: quimby05 quimby08 quimby12
        # -----------------------------------------------------------
        if (target in nim_clients) or (target == 'master'):
            clients.append(target)

    return list(set(clients))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd):
    """Execute a command.

    arguments:
        cmd (str): The command to be executed

    return:
        ret code: 0 - OK
                  1 - CalledProcessError exception
                  2 - other exception
        std_out of the command or stderr in case of error
    """

    std_out = ''
    std_err = ''
    msg = ''

    logging.debug('exec command:{}'.format(cmd))
    try:
        std_out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.cmd, excep.output, excep.returncode)
        return 1, msg
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        return 2, msg

    logging.debug('exec command Error:{}'.format(std_err))
    logging.debug('exec command output:{}'.format(std_out))

    return 0, std_out


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_clients(module):
    """
    Get the list of the standalones defined on the nim master.

    return the list of the name of the standlone objects defined on the
           nim master.
    """
    std_out = ''
    std_err = ''
    clients_list = []

    cmd = ['lsnim', '-t', 'standalone']

    try:
        proc = subprocess.Popen(cmd, shell=False, stdin=None,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = proc.communicate()
    except Exception as excep:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
                format(cmd, excep.args, std_out, std_err)
        module.fail_json(msg=msg)

    # nim_clients list
    for line in std_out.rstrip().split('\n'):
        clients_list.append(line.split()[0])

    return clients_list


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_lpp_source():
    """Get the list of the lpp_source defined on the nim master.

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

    ret, std_out = exec_cmd(cmd)

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
def compute_rq_type(oslevel):
    """Compute rq_type.

    Compute the suma rq_type from the given target oslevel

    return:
        Latest when oslevel is blank or latest (not case sensitive)
        TL     when oslevel is xxxx-xx(-00-0000)
        SP     when oslevel is xxxx-xx-xx(-xxxx)
        ERROR  when oslevel is not recognized
    """
    if (oslevel is None) or (not oslevel.strip()) or \
                            (oslevel.upper() == 'LATEST'):
        return 'Latest'
    if re.match(r"^([0-9]{4}-[0-9]{2})(|-00|-00-0000)$", oslevel):
        return 'TL'
    if re.match(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(|-[0-9]{4})$", oslevel):
        return 'SP'

    logging.debug("Error: oslevel is not recognized")

    return 'ERROOR'


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def compute_rq_name(rq_type, oslevel, clients_oslevel):
    """Compute rq_name.

    Compute the suma rq_name
        - for Latest: return a SP value in the form xxxx-xx-xx-xxxx
        - for TL: return the TL value in the form xxxx-xx-00-0000
        - for SP: return the SP value in the form xxxx-xx-xx-xxxx

    arguments:
        rq_type
        oslevel          requested oslevel
        clients_oslevel  oslevel of each client

    return:
       return code : 0 - OK
                     1 - CalledProcessError exception
                     2 - other exception
       rq_name value or stderr in case of error
    """
    metadata_dir = "/tmp/ansible/metadata"  # <TODO> get env variable for that
    rq_name = ''
    if rq_type == 'Latest':
        oslevel_max = re.match( \
                     r"^([0-9]{4}-[0-9]{2})(|-[0-9]{2}|-[0-9]{2}-[0-9]{4})$", \
                     max_oslevel(clients_oslevel)).group(1)
        oslevel_min = re.match( \
                     r"^([0-9]{4}-[0-9]{2})(|-[0-9]{2}|-[0-9]{2}-[0-9]{4})$", \
                     min_oslevel(clients_oslevel)).group(1)

        if re.match(r"^([0-9]{4})", oslevel_min).group(1) != \
           re.match(r"^([0-9]{4})", oslevel_max).group(1):
            logging.warning("Error: Release level mismatch, " \
                            "only AIX {} SP/TL will be downloaded\n\n". \
                            format(oslevel_max[0:2]))

        metadata_filter_ml = oslevel_max

        if not metadata_filter_ml:
            logging.error(
               "Error: cannot discover filter ml based on the list of targets")
            raise Exception(
               "Error: cannot discover filter ml based on the list of targets")

        if not os.path.exists(metadata_dir):
            os.makedirs(metadata_dir)

        # Build suma command to get metadata
        suma_filterml = 'FilterML={}'.format(metadata_filter_ml)
        suma_dltarget = 'DLTarget={}'.format(metadata_dir)
        suma_display = 'DisplayName={}'.format(PARAMS['Description'])

        cmd = ['/usr/sbin/suma', '-x', '-a', 'Action=Metadata', \
               '-a', 'RqType=Latest', '-a', suma_filterml, \
               '-a', suma_dltarget, '-a', suma_display]

        logging.debug('SUMA command:{}'.format(cmd))

        ret, stdout = exec_cmd(cmd)
        if ret != 0:
            logging.error(
                'SUMA command error rc:{}, error: {}'.format(ret, stdout))
            return ret, stdout

        logging.debug('SUMA command rc:{}'.format(ret))

        # find latest SP for highest TL
        v_max = None
        file_name = metadata_dir + "/installp/ppc/" + \
                    metadata_filter_ml + "*.xml"
        logging.debug("searched files: {}".format(file_name))
        files = glob.glob(file_name)
        logging.debug("found files: {}".format(files))
        for cur_file in files:
            logging.debug("open file: {}".format(cur_file))
            fic = open(cur_file, "r")
            for line in fic:
                logging.debug("line: {}".format(line))
                match_item = re.match(
                    r"^<SP name=\"([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})\">$",
                    line)
                if match_item:
                    version = match_item.group(1)
                    if v_max is None or version > v_max:
                        v_max = version
                    break

        rq_name = v_max
        shutil.rmtree(metadata_dir)

    elif rq_type == 'TL':
        rq_name = re.match(r"^([0-9]{4}-[0-9]{2})(|-00|-00-0000)$",
                           oslevel).group(1) + "-00-0000"

    elif rq_type == 'SP':
        if re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$", oslevel):
            rq_name = oslevel
        elif re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", oslevel):
            metadata_filter_ml = re.match(r"^([0-9]{4}-[0-9]{2})-[0-9]{2}$",
                                          oslevel).group(1)

            if not os.path.exists(metadata_dir):
                os.makedirs(metadata_dir)

            # =================================================================
            # Build suma command to get metadata
            # =================================================================
            suma_filterml = 'FilterML={}'.format(metadata_filter_ml)
            suma_dltarget = 'DLTarget={}'.format(metadata_dir)
            suma_display = 'DisplayName={}'.format(PARAMS['Description'])

            cmd = ['/usr/sbin/suma', '-x', '-a', 'Action=Metadata', \
                   '-a', 'RqType=Latest', '-a', suma_filterml, \
                   '-a', suma_dltarget, '-a', suma_display]

            logging.debug('suma command:{}'.format(cmd))

            ret, stdout = exec_cmd(cmd)
            if ret != 0:
                logging.error('SUMA command error rc:{}, error: {}'. \
                              format(ret, stdout))
                return ret, stdout

            # find SP build number
            cur_file = metadata_dir + "/installp/ppc/" + oslevel + ".xml"
            fic = open(cur_file, "r")
            for line in fic:
                match_item = re.match( \
                    r"^<SP name=\"([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})\">$", \
                    line)
                if match_item:
                    version = match_item.group(1)
                    break

            rq_name = version
            shutil.rmtree(metadata_dir)

    return 0, rq_name


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def compute_filter_ml(clients_oslevel, rq_type):
    """Compute the suma filter ML.

    returns the filter ML value for the suma command, depending on the
    oslevel of the target clients
    i.e. the minimum oslevel of the target for a specified rq_type.
    For a rq_type equals to latest it corresponds to the minimum oslevel of
    the target machines at the highest version (xxxx.OO.OO.OOO)
    """
    minimum_oslevel = None

    if rq_type == 'Latest':
        vers_max = re.match(r"^([0-9]{4})",
                            max_oslevel(clients_oslevel)).group(1)

        for key, value in iter(clients_oslevel.items()):
            if re.match(r"^([0-9]{4})", value).group(1) == vers_max and \
               (minimum_oslevel is None or value < min_oslevel):
                minimum_oslevel = value
    else:
        minimum_oslevel = min_oslevel(clients_oslevel)

    minimum_oslevel = minimum_oslevel[:7]

    return minimum_oslevel


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def compute_lpp_source_name(location, rq_name):
    """Compute lpp source name based on the location.

    When no location is specified or the location is a path the
        lpp_source_name is the <rq_name>-lpp-source
    else le lpp_source_name is the location value

    return: the name of the lpp_source
    """
    loc = ''
    if not location or not location.strip() or location[0] == '/':
        loc = "{}-lpp_source".format(rq_name)
    else:
        loc = location.rstrip('/')

# <TODO> - What about if location containes a relative path (error ?)

    return loc


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def compute_dl_target(location, lpp_source, nim_lpp_sources):
    """Compute suma DL target based on lpp source name.

     When the location is empty, set the location path to
         /usr/sys/inst.images
     Check if a lpp_source nim resource already exist and check the path is
         the same
     When the location is not a path, check that a nim lpp_source corresponding
         to the location value exists and returns the location path of this
         nim ressource.

    return:
       return code : 0 - OK
                     1 - if error
       dl_target value or msg in case of error
    """
    if not location or not location.strip():
        loc = "/usr/sys/inst.images"
    else:
        loc = location.rstrip('/')

    if loc[0] == '/':
        dl_target = "{}/{}".format(loc, lpp_source)
        if (lpp_source in nim_lpp_sources) and \
           (nim_lpp_sources[lpp_source] != dl_target):
            return 1, "Error: lpp source location mismatch"
    else:
        if loc not in nim_lpp_sources:
            return 1, "Error: cannot find lpp_source {} from nim info". \
                      format(loc)

        dl_target = nim_lpp_sources[loc]

    return 0, dl_target


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def suma_command(module, action):
    """run a suma command.

    parameters
        action   preview or download

    return:
       ret     suma command return code
       stdout  suma command output
    """
    suma_cmd = '/usr/sbin/suma -x -a RqType=SP '
    suma_action = '-a Action={} '.format(action)
    suma_filterml = '-a FilterML={} '.format(PARAMS['FilterMl'])
    suma_dltarget = '-a DLTarget={} '.format(PARAMS['DLTarget'])
    suma_rqname = '-a RqName={} '.format(PARAMS['RqName'])
    suma_display = '-a DisplayName={} '.format(PARAMS['Description'])

    suma_params = ''.join((suma_cmd, suma_action, suma_rqname, suma_filterml,
                           suma_dltarget, suma_display))

    logging.debug('SUMA - Command:{}'.format(suma_params))
    SUMA_OUTPUT.append('SUMA - Command:{}'.format(suma_params))

    ret, stdout, stderr = module.run_command(suma_params)

    if ret != 0:
        logging.error("Error: suma {} command failed with return code {}".\
                      format(action, ret))
        module.fail_json(msg="SUMA Command: {} => Error :{}". \
                         format(suma_params, stderr.split('\n')))

    return ret, stdout


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_command(module):
    """run a nim -o define command

    parameters
        action

    return:
       ret     nim command return code
       stdout  nim command output
    """
    nim_cmd = '/usr/sbin/nim  -o define  -t lpp_source  -a server=master '
    nim_location = '-a location={} '.format(PARAMS['DLTarget'])
    nim_package = '-a packages=all {} '.format(PARAMS['LppSource'])

    nim_params = ''.join((nim_cmd, nim_location, nim_package))

    logging.info('NIM - Command:{}'.format(nim_params))
    SUMA_OUTPUT.append('NIM command:{}'.format(nim_params))


    ret, stdout, stderr = module.run_command(nim_params)

    if ret != 0:
        logging.error("NIM Command: {}".format(nim_params))
        logging.error("NIM operation failed - rc:{}".format(rc))
        logging.error("{}".format(stderr))
        SUMA_OUTPUT.append('NIM operation failed - rc:{}'.format(rc))
        module.fail_json(msg="NIM Master Command: {} => Error :{}". \
                         format(nim_params, stderr.split('\n')))

    return ret, stdout


# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():

    module = AnsibleModule(
        argument_spec=dict(
            oslevel=dict(required=True, type='str'),
            location=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            action=dict(required=False,
                        choices=['download', 'preview'],
                        type='str', default='preview'),
            description=dict(required=False, type='str'),

        ),
        supports_check_mode=True
    )

    # Open log file - <TODO> - get file name from env
    suma_changed = False
    logging.basicConfig(filename='/tmp/ansible_suma_debug.log', format= \
        '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s', \
        level=logging.DEBUG)
    logging.debug('*** START ***')

    # Get Module params
    if module.params['oslevel']:
        req_oslevel = module.params['oslevel']
    else:
        raise Exception("Error: OS level field is empty")

    location = ''
    if module.params['location']:
        location = module.params['location']

    if module.params['targets']:
        targets = module.params['targets']
    else:
        raise Exception("Error: Targets field is empty")

    if module.params['action']:
        action = module.params['action']
    else:
        action = 'preview'

    if module.params['description']:
        description = module.params['description']
    else:
        description = "{} request for oslevel {}".format(action, req_oslevel)


    PARAMS['Description'] = description

    # =========================================================================
    # build nim lpp_source list
    # =========================================================================
    nim_lpp_sources = {}
    ret, nim_lpp_sources = get_nim_lpp_source()
    if ret != 0:
        logging.error( \
               'SUMA Error getting the lpp_source list - rc:{}, error:{}'. \
               format(ret, nim_lpp_sources))
        module.fail_json( \
               msg="SUMA Error getting th lpp_source list - rc:{}, error:{}". \
               format(ret, nim_lpp_sources))

    logging.debug('lpp source list: {}'.format(nim_lpp_sources))

    # ===========================================
    # Build nim_clients list
    # ===========================================
    nim_clients = []
    nim_clients = get_nim_clients(module)

    logging.debug('NIM Clients: {}'.format(nim_clients))

    # ===========================================
    # Build targets list
    # ===========================================
    targets_list = targets.split(' ')
    target_clients = []
    target_clients = expand_targets(targets_list, nim_clients)

    logging.info('SUMA - Target list: {}'.format(target_clients))
    SUMA_OUTPUT.append('SUMA - Target list: {}'.format(target_clients))

    # =========================================================================
    # Launch threads to collect information on targeted nim clients
    # =========================================================================
    threads = []
    clients_oslevel = {}

    for machine in target_clients:
        process = threading.Thread(target=run_cmd,
                                   args=(machine, clients_oslevel))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

    logging.debug('oslevel unclean dict: {}'.format(clients_oslevel))

    # =========================================================================
    # Delete empty value of dictionnary
    # =========================================================================
    removed_oslevel = []

    for key in [k for (k, v) in clients_oslevel.items() if not v]:
        removed_oslevel.append(key)
        del clients_oslevel[key]

    logging.debug('oslevel cleaned dict: {}'.format(clients_oslevel))
    logging.warn('SUMA - unavailable client list: {}'.format(removed_oslevel))

    # =========================================================================
    # compute suma request type based on oslevel property
    # =========================================================================
    rq_type = compute_rq_type(req_oslevel)
    if rq_type == 'ERROR':
        logging.error('SUMA Error computing the request type: {}'. \
                      format(req_oslevel))
        module.fail_json(msg='SUMA Error computing the request type: {}'. \
                         format(req_oslevel))

    PARAMS['RqType'] = rq_type

    logging.debug('Suma req Type: {}'.format(rq_type))

    # =========================================================================
    # Compute the filter_ml i.e. the min oslevel from the clients_oslevel
    # =========================================================================
    filter_ml = compute_filter_ml(clients_oslevel, rq_type)
    PARAMS['FilterMl'] = filter_ml

    logging.debug('{} <= Min Oslevel'.format(filter_ml))

    # =========================================================================
    # compute suma request name based on metadata info
    # =========================================================================
    ret, rq_name = compute_rq_name(rq_type, req_oslevel, clients_oslevel)
    if ret != 0:
        logging.error('SUMA Error compute_rq_name - rc:{}, error:{}'. \
                      format(ret, nim_lpp_sources))
        module.fail_json(msg="SUMA Error compute_rq_name - rc:{}, error:{}". \
                         format(ret, nim_lpp_sources))

    PARAMS['RqName'] = rq_name

    logging.debug('Suma req Name: {}'.format(rq_name))

    # =========================================================================
    # metadata does not match any fixes
    # =========================================================================
    if not rq_name or not rq_name.strip():
        logging.error("SUMA - Error: oslevel {} doesn't match any fixes".\
                      format(req_oslevel))
        module.fail_json( \
                      msg="SUMA - Error:oslevel {} doesn't match any fixes".\
                      format(req_oslevel))

    logging.debug('Suma req Name: {}'.format(rq_name))

    # =========================================================================
    # compute lpp source name based on request name
    # =========================================================================
    lpp_source = compute_lpp_source_name(location, rq_name)
    PARAMS['LppSource'] = lpp_source

    logging.debug('Lpp source name: {}'.format(lpp_source))

    # =========================================================================
    # compute suma dl target based on lpp source name
    # =========================================================================
    ret, dl_target = compute_dl_target(location, lpp_source, nim_lpp_sources)
    if ret != 0:
        logging.error('SUMA Error compute_dl_target - {}'.format(dl_target))
        module.fail_json(msg='SUMA Error compute_dl_target - {}'. \
                         format(dl_target))

    PARAMS['DLTarget'] = dl_target

    logging.debug('DL target: {}'.format(dl_target))

    # =========================================================================
    # Make lpp_source_dir='/usr/sys/inst.images/{}-lpp_source'.format(rq_name)
    # =========================================================================
    if not os.path.exists(dl_target):
        os.makedirs(dl_target)

    logging.debug('mkdir command:{}'.format(dl_target))

    # =========================================================================
    # suma command for preview
    # =========================================================================
    ret, stdout = suma_command(module, 'Preview')
    logging.debug('suma preview stdout:{}'.format(stdout))

    # parse output to see if there is something to download
    downloaded = 0
    failed = 0
    skipped = 0
    for line in stdout.rstrip().split('\n'):
        line = line.rstrip()
        matched = re.match(r"^\s+(\d+)\s+downloaded$", line)
        if matched:
            downloaded = int(matched.group(1))
            continue
        matched = re.match(r"^\s+(\d+)\s+failed$", line)
        if matched:
            failed = int(matched.group(1))
            continue
        matched = re.match(r"^\s+(\d+)\s+skipped$", line)
        if matched:
            skipped = int(matched.group(1))

    logging.info('Preview summary : {} to download, {} failed, {} skipped'. \
                 format(downloaded, failed, skipped))
    SUMA_OUTPUT.append( \
                'Preview summary : {} to download, {} failed, {} skipped'. \
                format(downloaded, failed, skipped))

    # =========================================================================
    # If action is preview or nothing is available to download, we are done
    # else dowload what is found and create associated nim objects
    # =========================================================================
    if action == 'download':
        if downloaded != 0:

            # =================================================================
            # suma command for download
            # =================================================================
            ret, stdout = suma_command(module, 'Download')
            logging.debug('suma dowload stdout:{}'.format(stdout))

            # parse output to see if there is something downloaded
            downloaded = 0
            failed = 0
            skipped = 0
            for line in stdout.rstrip().split('\n'):
                line = line.rstrip()
                matched = re.match(r"^\s+(\d+)\s+downloaded$", line)
                if matched:
                    downloaded = int(matched.group(1))
                    continue
                matched = re.match(r"^\s+(\d+)\s+failed$", line)
                if matched:
                    failed = int(matched.group(1))
                    continue
                matched = re.match(r"^\s+(\d+)\s+skipped$", line)
                if matched:
                    skipped = int(matched.group(1))

            logging.info( \
                  'Download summary : {} downloaded, {} failed, {} skipped'. \
                  format(downloaded, failed, skipped))
            SUMA_OUTPUT.append( \
                  'Download summary : {} downloaded, {} failed, {} skipped'. \
                  format(downloaded, failed, skipped))

            if downloaded != 0:
                suma_changed = True

        # =====================================================================
        # Create the associated nim resource if necessary
        # =====================================================================
        if lpp_source not in nim_lpp_sources:

            # =================================================================
            # nim -o define command
            # =================================================================
            ret, stdout = nim_command(module)

            suma_changed = True

            logging.info('NIM operation succeeded - output:{}'.format(stdout))
            SUMA_OUTPUT.append('NIM operation succeeded - output:{}'. \
                               format(stdout))

    # =========================================================================
    # Exit
    # =========================================================================
    module.exit_json(
        changed=suma_changed,
        msg="Suma {} completed successfully".format(action),
        suma_output=SUMA_OUTPUT,
        lpp_source_name=lpp_source,
        target_list=target_clients)

###############################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
