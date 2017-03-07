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

DOCUMENTATION = '''
---
module: aix_suma
author: "Cyril Bouhallier"
version_added: "1.0.0"
requirements: [ AIX ]

'''

import os
import re
import glob
import shutil
import subprocess
import threading
import logging

debug_data = []
params = {}
nim_changed = False

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def min_oslevel(dic):
    """
    Find the minimun value of a dictionnary

    args:
        dictionnary - Dictionnary {machine: oslevel}
    return:
        minimun oslevel from the dictionnary
    """

    min_oslevel = None

    for key, value in iter(dic.items()):
        if min_oslevel is None or value < min_oslevel:
            min_oslevel = value

    return min_oslevel


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def max_oslevel(dic):
    """
    Find the maximum value of a the oslevel dictionary

    args:
        dic - Dictionnary {client: oslevel}
    return:
        maximum oslevel from the dictionnary
    """

    max_oslevel = None

    for key, value in iter(dic.items()):
        if max_oslevel is None or value > max_oslevel:
            max_oslevel = value

    return max_oslevel


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def run_cmd(machine, result):
    """
    Run command function, command to be 'threaded'
    The thread then store the outpout in the dedicated slot of the result dictionnary.

    args:
        machine (str): The name machine
        result  (dict): The result of the command
    """

    rsh_cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/usr/bin/oslevel -s']

    p = subprocess.Popen(rsh_cmd,
                        shell=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)

    # return stdout only ... stripped!
    result[machine] = p.communicate()[0].rstrip()


# ----------------------------------------------------------------
# Expand the target machine list parameter
#
#    "*" should be specified as target to apply an operation on all
#        the machines
#    If target parameter is empty or not present operation is
#        performed locally
#
#    raise InvalidTargetsProperty in case of error
#    - cannot contact the target machines
# ----------------------------------------------------------------
def expand_targets(targets_list, nim_clients):

    clients = []

    for target in targets_list:

        #------------------------------------------------------------
        # Build target(s) from: range i.e. quimby[7:12]
        #------------------------------------------------------------

        m = re.match(r"(\w+)\[(\d+):(\d+)\]", target)
        if m:

            name  = m.group(1)
            start = m.group(2)
	    end   = m.group(3)

            for i in range(int(start), int(end) + 1):
                # target_results.append('{0}{1:02}'.format(name, i))
		curr_name = name + str(i)
		if curr_name in nim_clients:
		    clients.append(curr_name)

            continue

        #------------------------------------------------------------
        # Build target(s) from: val*. i.e. quimby*
        #------------------------------------------------------------

        m = re.match(r"(\w+)\*$", target)
        if m:

            name  = m.group(1)

            for curr_name in nim_clients:
	        if re.match(r"^%s\.*" % name, curr_name):
		    clients.append(curr_name)

            continue

        #------------------------------------------------------------
        # Build target(s) from: all or *
        #------------------------------------------------------------

        if target.upper() == 'ALL' or target == '*':
            clients = nim_clients
            continue

        #------------------------------------------------------------
        # Build target(s) from: quimby05 quimby08 quimby12
        #------------------------------------------------------------

        clients.append(target)

    return list(set(clients))


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_clients():
    """
        Get the list of the standalones defined on the nim master
    """

    std_out = ''
    std_err = ''
    clients_list = []

    cmd = ['lsnim', '-t', 'standalone']

    try:
        p = subprocess.Popen(cmd, shell=False, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = p.communicate()
    except Exception as e:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'.format(cmd, e.args, std_out, std_err)
        module.fail_json(msg=msg)

    # nim_clients list
    for line in std_out.rstrip().split('\n'):
        clients_list.append(line.split()[0])

    return clients_list


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd):

    std_out = ''
    std_err = ''

    logging.debug('exec command:{}'.format(cmd))
    try:
        std_out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'.format(cmd, e.cmd, e.output, e.returncode)
        module.fail_json(msg=msg)
    except Exception as e:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'.format(cmd, e.args, std_out, std_err)
        module.fail_json(msg=msg)

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('exec command:{}'.format(cmd))
    debug_data.append('exec command Error:{}'.format(std_err))
    logging.debug('exec command Error:{}'.format(std_err))
    logging.debug('exec command output:{}'.format(std_out))
    #--------------------------------------------------------

    return std_out


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_nim_lpp_source():
    """
        Get the list of the lpp_source defined on the nim master
    """

    std_out = ''
#    std_err = ''
    lpp_source_list = {}

    cmd = ['lsnim', '-t', 'lpp_source', '-l']

#    try:
#        p = subprocess.Popen(cmd, shell=False, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#        (std_out, std_err) = p.communicate()
#    except Exception as e:
#        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'.format(cmd, e.args, std_out, std_err)
#        module.fail_json(msg=msg)

    std_out = exec_cmd(cmd)

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

    return lpp_source_list


# ----------------------------------------------------------------
# compute_rq_type
#
#    Compute the suma rq_type from the given target oslevel
#
#    return:
#        Latest when oslevel is blank or latest (not case sensitive)
#        TL     when oslevel is xxxx-xx(-00-0000)
#        SP     when oslevel is xxxx-xx-xx(-xxxx)
#
#    raise Error in cae of error
# ----------------------------------------------------------------
def compute_rq_type(oslevel):

    if (oslevel == None) or (not oslevel.strip()) or (oslevel.upper() == 'LATEST'):
        return 'Latest'
    if re.match(r"^([0-9]{4}-[0-9]{2})(|-00|-00-0000)$", oslevel):
        return 'TL'
    if re.match(r"^([0-9]{4}-[0-9]{2}-[0-9]{2})(|-[0-9]{4})$", oslevel):
        return 'SP' 

    logging.debug("Error: oslevel is not recognized")

    raise Exception("Error: oslevel is not recognized")


# ----------------------------------------------------------------
# compute_rq_name
#
#    Compute the suma rq_name
#
#    -for Latest: return 
#    -for TL: return the TL value in the forme xxxx-xx-00-0000
#    -for SP: <PJPJ> TO BE UPDATED
#
#    return:
#        rq_name value
# ----------------------------------------------------------------
def compute_rq_name(rq_type, oslevel, clients_oslevel):

    metadata_dir = "/tmp/ansible/metadata" # <TODO> get an env variable for that
    rq_name = ''
    if rq_type == 'Latest':
        oslevel_max = re.match(r"^([0-9]{4}-[0-9]{2})(|-[0-9]{2}|-[0-9]{2}-[0-9]{4})$", max_oslevel(clients_oslevel)).group(1)
        oslevel_min = re.match(r"^([0-9]{4}-[0-9]{2})(|-[0-9]{2}|-[0-9]{2}-[0-9]{4})$", min_oslevel(clients_oslevel)).group(1)
        
        if re.match(r"^([0-9]{4})", oslevel_min).group(1) != \
           re.match(r"^([0-9]{4})", oslevel_max).group(1):
            debug_data.append("Error: Release level mismatch, only AIX {} SP/TL will be downloaded\n\n".format(oslevel_max[0:2]))
            logging.warning("Error: Release level mismatch, only AIX {} SP/TL will be downloaded\n\n".format(oslevel_max[0:2]))

        metadata_filter_ml = oslevel_max

        if not metadata_filter_ml:
            logging.error("Error: cannot discover filter ml based on the list of targets")
            raise Exception("Error: cannot discover filter ml based on the list of targets")

#        cmd = ['/bin/mkdir', '-p', metadata_dir]
#        std_out = exec_cmd(cmd)
        if not os.path.exists(metadata_dir):
            os.makedirs(metadata_dir)

        # ==========================================================================
        # Build suma command to get metadata
        # ==========================================================================
        suma_filterml = 'FilterML={}'.format(metadata_filter_ml)
        suma_dltarget = 'DLTarget={}'.format(metadata_dir)
        suma_display = 'DisplayName={}'.format(params['Description'])

        cmd = ['/usr/sbin/suma', '-x', '-a', 'Action=Metadata', \
               '-a', 'RqType=Latest', '-a', suma_filterml, \
               '-a', suma_dltarget,  '-a', suma_display]

        stdout = exec_cmd(cmd)

        #########################################################
        # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
        #########################################################
        debug_data.append('suma command:{}'.format(cmd))
        #--------------------------------------------------------

        # find latest SP for highest TL
        v_max = None
        file_name = metadata_dir + "/installp/ppc/" + metadata_filter_ml + "*.xml"
        logging.debug("searched files: {}".format(file_name))
        files = glob.glob(file_name)
        logging.debug("found files: {}".format(files))
        for file in files:
            logging.debug("open file: {}".format(file))
            fd = open(file, "r")
            for line in fd:
                logging.debug("line: {}".format(line))
                match_item = re.match(r"^<SP name=\"([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})\">$", line)
                if match_item:
                    version = match_item.group(1)
                    if v_max is None or version > v_max:
                        v_max = version
                    break

        rq_name = v_max
        shutil.rmtree(metadata_dir)

    elif rq_type == 'TL':
        rq_name = re.match(r"^([0-9]{4}-[0-9]{2})(|-00|-00-0000)$", oslevel).group(1) + "-00-0000"

    elif rq_type == 'SP':
        if re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$", oslevel):
            rq_name = oslevel
        elif re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", oslevel):
            metadata_filter_ml = re.match(r"^([0-9]{4}-[0-9]{2})-[0-9]{2}$", oslevel).group(1)

#            cmd = ['/bin/mkdir', '-p', metadata_dir]
#            std_out = exec_cmd(cmd)
            if not os.path.exists(metadata_dir):
                os.makedirs(metadata_dir)

            # ==========================================================================
            # Build suma command to get metadata
            # ==========================================================================
            suma_filterml = 'FilterML={}'.format(metadata_filter_ml)
            suma_dltarget = 'DLTarget={}'.format(metadata_dir)
            suma_display = 'DisplayName={}'.format(params['Description'])

            cmd = ['/usr/sbin/suma', '-x', '-a', 'Action=Metadata', \
                   '-a', 'RqType=Latest', '-a', suma_filterml, \
                   '-a', suma_dltarget,  '-a', suma_display]

            stdout = exec_cmd(cmd)

            #########################################################
            # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
            #########################################################
            debug_data.append('suma command:{}'.format(cmd))
            #--------------------------------------------------------

            # find SP build number
            file = metadata_dir + "/installp/ppc/" + oslevel + ".xml"
            fd = open(file, "r")
            for line in fd:
                match_item = re.match(r"^<SP name=\"([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})\">$", line)
                if match_item:
                    version = match_item.group(1)
                    break

            rq_name = version
            shutil.rmtree(metadata_dir)

    return rq_name


# ----------------------------------------------------------------
# compute_filter_ml
# ----------------------------------------------------------------
def compute_filter_ml(clients_oslevel, rq_type):

    minimum_oslevel = None
    
    if rq_type == 'Latest':
        vers_max = re.match(r"^([0-9]{4})", max_oslevel(clients_oslevel)).group(1)
    
        for key, value in iter(clients_oslevel.items()):
            if re.match(r"^([0-9]{4})", value).group(1) == vers_max and \
               (minimum_oslevel is None or value < min_oslevel):
                minimum_oslevel = value
    else:
        minimum_oslevel = min_oslevel(clients_oslevel)

    minimum_oslevel = minimum_oslevel[:7]

    return minimum_oslevel


# ----------------------------------------------------------------
# compute lpp source name based on the location
# ----------------------------------------------------------------
def compute_lpp_source_name(location, rq_name):

    loc = ''
    if not location or not location.strip() or location[0] == '/':
        loc = "{}-lpp_source".format(rq_name)
    else:
        loc = location.rstrip('/')

# <TODO> - What about if location containes a relative path (error ?)

    return loc


# ----------------------------------------------------------------
# compute suma DL target based on lpp source name
# ----------------------------------------------------------------
def compute_dl_target(location, lpp_source, nim_lpp_sources):

    if not location or not location.strip():
        loc = "/usr/sys/inst.images"
    else:
        loc = location.rstrip('/')

    if loc[0] == '/':
        dl_target = "{}/{}".format(loc, lpp_source)
        if (lpp_source in nim_lpp_sources) and \
           (nim_lpp_sources[lpp_source] != dl_target):
            raise Exception("Error: lpp source location mismatch")
    else:
        if (loc not in nim_lpp_sources):
            raise Exception("Error: cannot find lpp_source {} from nim info".format(loc))

        dl_target = nim_lpp_sources[loc]

    return dl_target
    

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():

    module = AnsibleModule(
        argument_spec=dict(
            oslevel=dict(required=True, type='str'),
            location=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            action=dict(choices=['download', 'preview'], type='str'),
            description=dict(required=False, type='str'),
            
        ),
        supports_check_mode=True
    )

    # Open log file <TODO> - to be changed
    logging.basicConfig(filename='/tmp/ansibletest.log',level=logging.DEBUG) 

    # Get Module params
    if module.params['oslevel']:
        req_oslevel = module.params['oslevel']
    else:
        raise Exception("Error: OS level field is empty")

    location = ''
    if module.params['location']:
        location = module.params['location']
    # else:
    #     raise Exception("Error: Location field is empty")

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


    params['Description'] = description

    # ==========================================================================
    # build nim lpp_source list
    # ==========================================================================
    nim_lpp_sources = {}
    nim_lpp_sources = get_nim_lpp_source()

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('lpp source list: {}'.format(nim_lpp_sources))
    logging.debug('lpp source list: {}'.format(nim_lpp_sources))
    #--------------------------------------------------------

    # ===========================================
    # Build nim_clients list
    # ===========================================
    nim_clients = []
    nim_clients = get_nim_clients()

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('NIM Clients: {}'.format(nim_clients))
    logging.debug('NIM Clients: {}'.format(nim_clients))
    #--------------------------------------------------------

    # Build targets list
    targets_list = targets.split(' ')

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Targets List: {}'.format(targets_list))
    logging.debug('Targets List: {}'.format(targets_list))
    #--------------------------------------------------------

    target_clients = []
    target_clients = expand_targets(targets_list, nim_clients)

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Target Clients: {}'.format(target_clients))
    logging.debug('Target Clients: {}'.format(target_clients))
    #--------------------------------------------------------

    # ==========================================================================
    # Launch threads to collect information on targeted nim clients
    # ==========================================================================

    threads = []
    clients_oslevel = {}

    for machine in target_clients:
        process = threading.Thread(target=run_cmd, args=(machine, clients_oslevel))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('oslevel unclean dict: {}'.format(clients_oslevel))
    logging.debug('oslevel unclean dict: {}'.format(clients_oslevel))
    #--------------------------------------------------------

    # ==========================================================================
    # Delete empty value of dictionnary
    # ==========================================================================

    removed_oslevel = []

    for key in [ k for (k,v) in clients_oslevel.items() if not v ]:
        removed_oslevel.append(key)
        del clients_oslevel[key]
    
    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('oslevel cleaned dict: {}'.format(clients_oslevel))
    debug_data.append('unavailable client list: {}'.format(removed_oslevel))
    logging.debug('oslevel cleaned dict: {}'.format(clients_oslevel))
    logging.debug('unavailable client list: {}'.format(removed_oslevel))


    # compute suma request type based on oslevel property
    rq_type = compute_rq_type(req_oslevel)
    params['RqType'] = rq_type

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Suma req Type: {}'.format(rq_type))
    logging.debug('Suma req Type: {}'.format(rq_type))
    #--------------------------------------------------------

    # ==========================================================================
    # Compute the filter_ml i.e. the min oslevel of the target clients
    # ==========================================================================

    # Min oslevel from the clients_oslevel
    filter_ml = compute_filter_ml(clients_oslevel, rq_type)
    params['FilterMl'] = filter_ml

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('{} <= Min Oslevel'.format(filter_ml))
    logging.debug('{} <= Min Oslevel'.format(filter_ml))
    #--------------------------------------------------------

    # compute suma request name based on metadata info
    rq_name = compute_rq_name(rq_type, req_oslevel, clients_oslevel)
    params['RqName'] = rq_name

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Suma req Name: {}'.format(rq_name))
    logging.debug('Suma req Name: {}'.format(rq_name))
    #--------------------------------------------------------

    # metadata does not match any fixes
    if not rq_name or not rq_name.strip():
        logging.error("Error: SUMA oslevel {} doesn't match any fixes".format(oslevel))
        module.fail_json(msg="SUMA oslevel {} doesn't match any fixes".format(oslevel))
        # raise Exception("Error: oslevel doesn't match any fixes")
        # <PJPJ> - TO BE CONFIRMED

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Suma req Name: {}'.format(rq_name))
    logging.debug('Suma req Name: {}'.format(rq_name))
    #--------------------------------------------------------

    # compute lpp source name based on request name
    lpp_source = compute_lpp_source_name(location, rq_name)
    params['LppSource'] = lpp_source

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Lpp source name: {}'.format(lpp_source))
    logging.debug('Lpp source name: {}'.format(lpp_source))
    #--------------------------------------------------------

    # compute suma dl target based on lpp source name
    dl_target = compute_dl_target(location, lpp_source, nim_lpp_sources)
    params['DLTarget'] = dl_target

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('DL target: {}'.format(dl_target))
    logging.debug('DL target: {}'.format(dl_target))
    #--------------------------------------------------------

    # ==========================================================================
    # Make dir
    # ==========================================================================

    # lpp_source_dir = '/usr/sys/inst.images/{}-lpp_source'.format(rq_name)
    if not os.path.exists(dl_target):
        os.makedirs(dl_target)

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('mkdir command:{}'.format(dl_target))
    logging.debug('mkdir command:{}'.format(dl_target))
    #--------------------------------------------------------

    # ==========================================================================
    # Build suma command for preview
    # ==========================================================================
    suma_cmd = '/usr/sbin/suma -x '
    suma_rqtype = '-a RqType=SP '
    suma_filterml = '-a FilterML={} '.format(filter_ml)
    suma_dltarget = '-a DLTarget={} '.format(dl_target)
    suma_rqname = '-a RqName={} '.format(rq_name)
    suma_action = '-a Action=Preview '
    suma_display = '-a DisplayName={} '.format('description')

    # suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget, suma_display))
    suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('suma command:{}'.format(suma_params))
    logging.debug('suma command:{}'.format(suma_params))
    #--------------------------------------------------------

    rc, stdout, stderr = module.run_command(suma_params)

    if rc != 0:
        logging.error("Error: suma preview command failed with return code {}".format(rc))
        module.fail_json(msg="SUMA Command: {} => Error :{}".format(suma_params, stderr.split('\n')))

    logging.debug('suma preview stdout:{}'.format(stdout))

    # parse output to see if there is something to download
    downloaded = 0
    failed     = 0
    skipped    = 0
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

    logging.info('Preview summary : {} to download, {} failed, {} skipped'.format(downloaded, failed, skipped))

    # ==========================================================================
    # If action is preview or nothing is available to download, we are done
    # else dowload what is found and create associated nim objects
    # ==========================================================================
    if action == 'download':
        if downloaded != 0:
        
            # ==========================================================================
            # Build suma command for download 
            # ==========================================================================
            suma_cmd = '/usr/sbin/suma -x '
            suma_rqtype = '-a RqType=SP '
            suma_filterml = '-a FilterML={} '.format(filter_ml)
            suma_dltarget = '-a DLTarget={} '.format(dl_target)
            suma_rqname = '-a RqName={} '.format(rq_name)
            suma_action = '-a Action=Download '
            suma_display = '-a DisplayName={} '.format('description')

            # suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget, suma_display))
            suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget))

            #########################################################
            # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
            #########################################################
            debug_data.append('suma command:{}'.format(suma_params))
            logging.debug('suma command:{}'.format(suma_params))
            #--------------------------------------------------------

            rc, stdout, stderr = module.run_command(suma_params)

            if rc != 0:
                logging.error("Error: suma dowload command failed with return code {}".format(rc))
                logging.error("{}".format(stderr))
                module.fail_json(msg="SUMA Command: {} => Error :{}".format(suma_params, stderr.split('\n')))

            logging.debug('suma dowload stdout:{}'.format(stdout))
            debug_data.append('suma command output:{}'.format(stdout))

            # parse output to see if there is something to download
            downloaded = 0
            failed     = 0
            skipped    = 0
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

            logging.info('Download summary : {} downloaded, {} failed, {} skipped'.format(downloaded, failed, skipped))
            debug_data.append('Download summary : {} downloaded, {} failed, {} skipped'.format(downloaded, failed, skipped))

            if failed != 0:
                logging.error('Suma download failed')
                debug_data.append('Suma download failed')
                module.fail_json(msg="SUMA Command: {} => Error :{}".format(suma_params, stderr.split('\n')))

        # ==========================================================================
        # Create the associated nim resource if necessary
        # ==========================================================================
        if lpp_source not in nim_lpp_sources:

            # ==========================================================================
            # Build nim command
            # ==========================================================================
            nim_cmd = '/usr/sbin/nim '
            nim_operation = '-o define '
            nim_type = '-t lpp_source '
            nim_location = '-a location={} '.format(dl_target)
            nim_server = '-a server=master '
            nim_package = '-a packages=all {} '.format(lpp_source)

            nim_params = ''.join((nim_cmd, nim_operation, nim_type, nim_location, nim_server, nim_package))

            #########################################################
            # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
            #########################################################
            debug_data.append('nim command:{}'.format(nim_params))
            logging.debug('nim command:{}'.format(nim_params))
            #--------------------------------------------------------

            rc, stdout, stderr = module.run_command(nim_params)

            if rc != 0:
                logging.error("Error: nim -o define failed with return code {}".format(rc))
                logging.error("NIM Command: {}".format(nim_params))
                logging.error("{}".format(stderr))
                module.fail_json(msg="NIM Master Command: {} => Error :{}".format(nim_params, stderr.split('\n')))

            logging.debug('nim -o define stdout:{}'.format(stdout))
            debug_data.append('nim -o define output:{}'.format(stdout))

    # ==========================================================================
    # Exit
    # ==========================================================================
    module.exit_json(
        changed = True,
        msg="Suma {} completed successfully".format(action),
        debug_res = debug_data,
        lpp_source_name = lpp_source,
        target_list = target_clients)

###########################################################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
