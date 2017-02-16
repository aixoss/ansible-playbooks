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

import re
import subprocess
import threading


def min_oslevel(dictionnary):
    """
    Find the minimun value of a dictionnary"

    args:
        dictionnary - Dictionnary {machine: oslevel}
    return:
        minimun oslevel from the dictionnary
    """

    min_oslevel = None

    for key, value in iter(dictionnary.items()):
        if min_oslevel is None or value < min_oslevel:
            min_oslevel = value

    return min_oslevel


# TODO (CGB) Add function and test
# def remove_empty_keys(dictionnary):

    # clean_dictionnary = {k:v for k,v in dictionnary.items() if v}

#     return clean_dictionnary



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


def main():

    module = AnsibleModule(
        argument_spec=dict(
            oslevel=dict(required=False, type='str'),
            location=dict(required=False, type='str'),
            targets=dict(required=False, type='str'),
            action=dict(choices=['download', 'preview'], type='str'),
        ),
        supports_check_mode=True
    )

    # ===========================================
    # Get Module params
    # ===========================================

    if module.params['oslevel']:
        oslevel = module.params['oslevel']
    else:
        raise Exception("Error: OS level field is empty")

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
        raise Exception("Error: Action field is empty")

    debug_data = []

    # ===========================================
    # Build nim_clients list
    # ===========================================

    std_out = ''
    std_err = ''
    nim_clients = []

    cmd = ['lsnim', '-t', 'standalone']

    try:
        p = subprocess.Popen(cmd, shell=False, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (std_out, std_err) = p.communicate()
    except Exception as e:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'.format(cmd, e.args, std_out, std_err)
        module.fail_json(msg=msg)

    # nim_clients list
    for line in std_out.rstrip().split('\n'):
        nim_clients.append(line.split()[0])

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('NIM Clients: {}'.format(nim_clients))
    #--------------------------------------------------------

    # ==========================================================================
    # Launch threads
    # ==========================================================================

    threads = []
    oslevel_list = {}

    for machine in nim_clients:
        process = threading.Thread(target=run_cmd, args=(machine, oslevel_list))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('oslevel Dict: {}'.format(oslevel_list))
    #--------------------------------------------------------

    # ==========================================================================
    # Build targets list
    # ==========================================================================

    target_results = []
    targets_list = targets.split(' ')

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Targets List: {}'.format(targets_list))
    #--------------------------------------------------------

    for target in targets_list:

        #------------------------------------------------------------
        # Build target(s) from: range i.e. quimby[7:12]
        #------------------------------------------------------------

        m = re.search('(\w+)\[(\d+):(\d+)\]', target)
        if m:

            name, indices = targets[:-1].split('[')
            start, end = indices.split(':')

            for i in range(int(start), int(end)+1):
                target_results.append('{0}{1:02}'.format(name, i))

        #------------------------------------------------------------
        # Build target(s) from: all
        #------------------------------------------------------------

        m = re.search('[Aa][Ll][Ll]', target)
        if m:
            target_results = nim_clients

        #------------------------------------------------------------
        # Build target(s) from: *
        #------------------------------------------------------------

        m = re.search('[*]', target)
        if m:
            target_results = nim_clients

    # Join two lists WITHOUT duplicate
    clients = list(set(target_results) & set(nim_clients))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Targets Range: {}'.format(clients))
    #--------------------------------------------------------

    # ==========================================================================
    # Generate oslevel dictionnary from 'nim clients' on target machines
    # ==========================================================================

    targets_oslevel = {}

    for client in clients:
        if client in oslevel_list:
            targets_oslevel[client] = oslevel_list[client]

    # ==========================================================================
    # Select current oslevel and min oslevel
    # ==========================================================================

    # Min oslevel from the targets_oslevel
    mininum_oslevel = min_oslevel(targets_oslevel)[:7]

    if oslevel:
        current_oslevel = oslevel

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('{} <= Min Oslevel'.format(mininum_oslevel))
    #--------------------------------------------------------

    # ==========================================================================
    # Make dir
    # ==========================================================================

    # mkdir <DLTarget>/7100-04-01-1543-lpp_source => /usr/sys/inst.images/7100-04-01-1543-lpp_source

    mkdir_cmd = 'mkdir '
    mkdir_path = '/usr/sys/inst.images/'
    mkdir_oslevel = '{}-lpp_source '.format(current_oslevel)

    mkdir_params = ''.join((mkdir_cmd, mkdir_path, mkdir_oslevel))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('mkdir command:{}'.format(mkdir_params))
    #--------------------------------------------------------

    rc, stdout, stderr = module.run_command(mkdir_params)

    # ==========================================================================
    # Build suma command
    # ==========================================================================

    suma_cmd = '/usr/sbin/suma -x '
    suma_rqtype = '-a RqType=SP '
    suma_filterml = '-a FilterML={} '.format(mininum_oslevel)
    suma_dltarget = '-a DLTarget=/usr/sys/inst.images/{}-lpp_source '.format(current_oslevel)
    suma_rqname = '-a RqName={} '.format(current_oslevel)

    if action == 'download':
        suma_action = '-a Action=Download '
        suma_display = '-a DisplayName="Download SP" '
    elif action == 'preview':
        suma_action = '-a Action=Preview '
        suma_display = '-a DisplayName="Preview SP" '

    # suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget, suma_display))
    suma_params = ''.join((suma_cmd, suma_action, suma_rqtype, suma_rqname, suma_filterml, suma_dltarget))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('suma command:{}'.format(suma_params))
    #--------------------------------------------------------

    rc, stdout, stderr = module.run_command(suma_params)

    if rc == 0:
        # module.exit_json(
        #     changed=False,
        #     message="SUMA Command: {}".format(suma_params),
        #     debug_targets=stdout.split('\n'))

        debug_data.append('suma command output:{}'.format(stdout))

    # m_fail = re.search('\s+\d+\sfailed', debug_data)

    # if m_fail:
    #     debug_data.append('regex fail string:{}'.format( m_fail.group() ))

    # 'Summary:', '        207 downloaded', '        0 failed', '        1 skipped', ''

    # else:
    #     if stderr:
    #         module.fail_json(msg="SUMA Command: {} => Error :{}".format(suma_params, stderr.split('\n')))
    #     else:
    #         module.fail_json(msg="SUMA Command: {} => Output :{}".format(suma_params, stdout.split('\n')))

    # ==========================================================================
    # Build nim command
    # ==========================================================================

    nim_cmd = '/usr/sbin/nim '
    nim_operation = '-o define '
    nim_type = '-t lpp_source '
    nim_location = '-a location=/usr/sys/inst.images/{}-lpp_source '.format(current_oslevel)
    nim_server = '-a server=master '
    nim_package = '-a packages=all {}-lpp_source '.format(current_oslevel)

    nim_params = ''.join((nim_cmd, nim_operation, nim_type, nim_location, nim_server, nim_package))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('nim command:{}'.format(nim_params))
    #--------------------------------------------------------

    # rc, stdout, stderr = module.run_command(nim_params)

    # if rc == 0:
    #     module.exit_json(
    #         changed=False,
    #         message="NIM Command: {}".format(nim_params),
    #         debug_targets=debug_data)
    # else:
    #     if stderr:
    #         module.fail_json(msg="NIM Master Command: {} => Error :{}".format(nim_params, stderr.split('\n')))
    #     else:
    #         module.fail_json(msg="NIM Master Command: {} => Output :{}".format(nim_params, stdout.split('\n')))

###########################################################################################################

    module.exit_json(
        changed=False,
        msg="Command: {} => Data: {}".format(nim_params, stdout.split('\n') ),
        # msg="Debug Data: {}".format(targets_oslevel),
        debug_targets=debug_data)

###########################################################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
