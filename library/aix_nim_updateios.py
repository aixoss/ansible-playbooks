#!/usr/bin/python
#
# Copyright (c) 2017, IBM Corp
#
# AIX NIM module for Ansible :
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

############################################################################

from ansible.module_utils.basic import *
import os
import glob
import subprocess
import logging
import re
import shutil
import threading
import time


DOCUMENTATION = """
---
module: update_ios
short_description: Update the ios
"""

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(module, cmd):
    """
    Execute the given command
        - module    the module variable
        - cmd       array of command parameters

    In case of error set an error message and fail the module

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
        return (1, " ")
    except Exception as exc:
        msg = 'Command: {} Exception.Args{} =>Data:{} ... Error :{}'. \
            format(cmd, exc.args, std_out, std_err)
            return (1, " ")

    # DEBUG
    DEBUG_DATA.append('exec command:{}'.format(cmd))
    DEBUG_DATA.append('exec command Error:{}'.format(std_err))
    logging.debug('exec command Error:{}'.format(std_err))
    logging.debug('exec command output:{}'.format(std_out))
    # --------------------------------------------------------

    return (0, std_out)

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_command(module):
    global OUTPUT

    cmd = ['nim', '-o', 'updateios']

    if module.params['lpp_source']:
        cmd += ['-a', 'lpp_source=%s' %(module.params['lpp_source'])]

    if module.params['accept_licenses']:
        cmd += ['-a', 'accept_licenses=%s' %(module.params['accept_licenses'])]
    else: #default
        cmd += ['-a', 'accept_licenses=yes']

    if module.params['updateios_flags']:
        cmd += ['-a', 'updateios_flags=%s' %(module.params['updateios_flags'])]

        if module.params['updateios_flags'] == "-remove":
            if module.params['filesets'] != "none":
                cmd += ['-a', 'filesets=%s' %(module.params['filesets'])]
            elif module.params['installp_bundle'] != "none":
                cmd += ['-a', 'installp_bundle=%s' %(module.params['installp_bundle'])]
        else:
            logging.info('VIO UPDATE - filesets {} and installp_bundle {} have been discarded'.format(module.params['filesets'], module.params['installp_bundle']))
            OUTPUT.append('Any installp_bundle or filesets have been discarded')

    if module.params['preview']:
        cmd += ['-a', 'preview=%s' %(module.params['preview'])]
    else: #default
        cmd += ['-a', 'preview=yes']

    cmd += [module.params['targets']]
    return cmd

# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_updateios(module):
    global CHANGED
    global OUTPUT

    cmd = get_command(module)
    ret, std_out = exec_cmd(module, cmd)

    logging.info('[RC] {}'.format(ret))
    logging.info('[STDOUT] {}'.format(std_out))

    if ret != 0:
        logging.error('Error: NIM Command: {} failed with return code {}'.format(cmd, ret))
        OUTPUT.append("FAILURE")

    OUTPUT.append("SUCCESS")
    CHANGED = True
    return ret


###################################################################################

if __name__ == '__main__':
    DEBUG_DATA = []
    OUTPUT = []
    CHANGED = False

    module = AnsibleModule(
        argument_spec=dict(
            targets=dict(required=True, type='str'),
            filesets=dict(required=False, type='str'),
            installp_bundle=dict(required=False, type='str'),
            lpp_source=dict(required=True, type='str'),
            accept_licenses=dict(required=False, type='str'),
            updateios_flags=dict(required=True, type='str'),
            preview=dict(required=False, type='str')
        )
    )

    # Open log file
    LOGNAME = '/tmp/ansible_updateios_debug.log'
    LOGFRMT = '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s'
    logging.basicConfig(filename=LOGNAME, format=LOGFRMT, level=logging.DEBUG)

    logging.debug('*** START VIO UPDATE OPERATION ***')
    nim_updateios(module)

    try:
        module.exit_json(
            changed = CHANGED,
            msg = "NIM VIO update operation completed successfully",
            targets = module.params['targets'],
            debug_output = DEBUG_DATA,
            output = OUTPUT)
    except:
        module.fail_json(msg="Something fatal happened")
