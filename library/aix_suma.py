#!/usr/bin/python
#
# Copyright (c) 2016, IBM Corp
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

import subprocess
import threading

# =============================================================================
# Module code.
# =============================================================================

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
        targets = []
        targets = module.params['targets'].lower()
    else:
        raise Exception("Error: Targets field is empty")

    # TODO (CGB): Update

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

    # ===========================================
    # Function : run_cmd
    # ===========================================

    def run_cmd(machine, result):

        """Run command function, command to be 'threaded'
           The thread then store its results in the dedicated slot of the result dictionnary.

        Args:
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

    # ===========================================
    # Launch threads
    # ===========================================

    threads = []
    results = {}

    for machine in nim_clients:
        process = threading.Thread(target=run_cmd, args=(machine, results))
        process.start()
        threads.append(process)

    for process in threads:
        process.join()

###########################################################################################################

    message = 'Command: {} => Data: {}'.format(cmd, nim_clients)
    module.exit_json(
        changed=False,
        message=message,
        debug_targets=results)

###########################################################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
