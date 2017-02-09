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
            targets=dict(required=False, type='str'),
        ),
        supports_check_mode=True
    )

    # ===========================================
    # Get Module params
    # ===========================================

    if module.params['targets']:
        targets = module.params['targets']
    else:
        raise Exception("Error: Targets field is empty")

    # TODO (CGB): Update

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

    # ==========================================================================
    # Build targets list
    # ==========================================================================

    target_results = []
    targets_list = targets.split(' ')

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Targets List: {}'.format(targets_list))

    for target in targets_list:

        # Build target(s) from: range i.e. quimby[7:12]
        #---------------------------------------------

        m = re.search('\[[0-9]+:[0-9]+\]', target)
        if m:
            name = target.split('[')[0]
            # List of Strings
            target_range = re.findall('[0-9]+', target)
            # Convert List of string to List of Integer
            target_range = [int(i) for i in target_range]
            for i in range(target_range[0], target_range[1] + 1):
                # Display number with leading zeros
                target_results.append(name + str(format(i, '02d')))

        # Build target(s) from: all
        #-----------------------------------------------

        m = re.search('[Aa][Ll][Ll]', target)
        if m:
            target_results = nim_clients

        # Build target(s) from: *
        #-----------------------------------------------

        m = re.search('[*]', target)
        if m:
            target_results = nim_clients

    # # Join two lists WITHOUT duplicate
    clients = list(set(target_results) & set(nim_clients))

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('Targets Range: {}'.format(clients))

    # ==========================================================================
    # Generate oslevel dictionnary from 'nim clients' on target machines
    # ==========================================================================

    targets_oslevel = {}

    for client in clients:
        if client in oslevel_list:
            targets_oslevel[client] = oslevel_list[client]

    # Min oslevel from the targets_oslevel
    min_oslvl=min_oslevel(targets_oslevel)[0:7]

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('{} <= Min Oslevel'.format(min_oslvl))

    # ==========================================================================
    # Build suma command
    # ==========================================================================

    # suma -x -a Action=Download
    #         -a DisplayName="Download SP"
    #         -a RqType=SP
    #         -a FilterML=7100-02
    #         -a RqName=7100-02-02-1316

    suma_action   = '-a Action=Download '
    suma_display  = '-a DisplayName="Download SP"'
    suma_rqtype   = '-a RqType=SP '
    suma_filterml = '-a FilterML={} '.format(min_oslvl)
    suma_rqname   = '-a RqName={} '.format(min_oslevel(targets_oslevel))

    suma_cmd = "/usr/sbin/suma -x " + suma_action + suma_rqtype + suma_filterml + suma_rqname

    #########################################################
    # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG # DEBUG #
    #########################################################
    debug_data.append('suma command:{}'.format(suma_cmd))


    rc, stdout, stderr = module.run_command(suma_cmd)

    if rc == 0:
        module.exit_json(
            changed=False,
            message="SUMA Execute: {}".format(suma_cmd),
            debug_targets=stdout.split('\n'))
    else:
        if stderr:
            module.fail_json(msg="SUMA Execute: {} => Error :{}".format(suma_cmd, stderr.split('\n')))
        else:
            module.fail_json(msg="SUMA Execute: {} => Output :{}".format(suma_cmd, stdout.split('\n')))

###########################################################################################################

    # module.exit_json(
    #     changed=False,
    #     msg="Command: {} => Data: {}".format(cmd, nim_clients),
    #     debug_targets=debug_data)
    #     # debug_targets=clients,

###########################################################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
