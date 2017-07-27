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

############################################################################

import os
import re
import glob
import shutil
import subprocess
import threading
import logging
import time

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *


DOCUMENTATION = """
---
module: update_ios
authors: Cynthia Wu, Marco Lugo
short_description: Perform a VIO update 

"""


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def exec_cmd(cmd):
    """
    Execute the given command
        - cmd       array of command parameters

    In case of error return (1, " ")

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
        return (1, " ")
    except Exception as exc:
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
def check_lpp_source(module, lpp_source):
    """
    Check to make sure lpp_source exists
        - module        the module variable
        - lpp_source    lpp_source param provided by module

    In case lpp_source does not exist fail the module 

    return
        - exists        True
    """

    # find location of lpp_source
    cmd = ['lsnim', '-a', 'location', lpp_source]
    ret, std_out = exec_cmd(cmd)
    if ret != 0:
        logging.error('NIM - Error: cannot find location of lpp_source {}'.format(lpp_source))
        module.fail_json(msg="NIM - Error: cannot find location of lpp_source {}".format(lpp_source))
    location = std_out.split()[3]

    # check to make sure path exists
    cmd = ['/bin/find/', location]
    ret, std_out = exec_cmd(cmd)
    if ret != 0:
        logging.error('NIM - Error: cannot find location of lpp_source {}'.format(lpp_source))
        module.fail_json(msg="NIM - Error: cannot find location of lpp_source {}".format(lpp_source))

    return True


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_targets(module, targets):
    """
    Check to make sure targets exist
        - module        the module variable 
        - targets       targets param provided by module

    In case target does not exist fail the module 

    return
        - exists        target exists
    """

    cmd = ['lsnim','-l', targets]
    ret, std_out = exec_cmd(cmd)
    if ret != 0:
        logging.error('NIM - Error: target {} cannot be found'.format(targets))
        module.fail_json(msg="NIM - Error: target {} cannot be found".format(targets))

    return True


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def check_updateios_flags(module, flag):
    """
    Check to make sure updateios_flags value is valid
        - module        the module variable
        - flag          updateios action

    return
        - valid         True
    """
    valid_flags = ['-install', '-commit', '-reject', '-cleanup', 'remove']
    if flag not in valid_flags:
        logging.error('NIM - Error: updateios_flags parameter {} invalid'.format(flag))
        module.fail_json(msg="NIM - Error: updateios_flags parameter {} invalid".format(flag))
    logging.info('Updateios action: {}'.format(flag))

    return True 


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def get_updateios_cmd(module):
    """
    Assemble the updateios command
        - module        the module variable 

    return
        - cmd           array of the command parameters
    """

    global OUTPUT

    cmd = ['nim', '-o', 'updateios']

    # lpp source
    if module.params['lpp_source']:
        if (check_lpp_source(module, module.params['lpp_source'])):
            cmd += ['-a', 'lpp_source=%s' %(module.params['lpp_source'])]

    # accept licenses
    if module.params['accept_licenses']:
        cmd += ['-a', 'accept_licenses=%s' %(module.params['accept_licenses'])]
    else: #default
        cmd += ['-a', 'accept_licenses=yes']

    # updateios flags
    if module.params['updateios_flags']:
        if (check_updateios_flags(module, module.params['updateios_flags'])):
            cmd += ['-a', 'updateios_flags=%s' %(module.params['updateios_flags'])]

            if module.params['updateios_flags'] == "-remove":
                if module.params['filesets'] != "none":
                    cmd += ['-a', 'filesets=%s' %(module.params['filesets'])]
                elif module.params['installp_bundle'] != "none":
                    cmd += ['-a', 'installp_bundle=%s' %(module.params['installp_bundle'])]
        else:
            logging.info('VIO UPDATE - filesets {} and installp_bundle {} have been discarded'.format(module.params['filesets'], module.params['installp_bundle']))
            OUTPUT.append('Any installp_bundle or filesets have been discarded')

    # preview mode
    if module.params['preview']:
        cmd += ['-a', 'preview=%s' %(module.params['preview'])]
    else: #default
        cmd += ['-a', 'preview=yes']

    # targets
    if module.params['targets']:
        if (check_targets(module, module.params['targets'])):
            cmd += [module.params['targets']]

    return cmd


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_updateios(module):
    """
    Execute the updateios command
        - module        the module variable

    return
        - ret           return code of nim updateios command 
    """
    global CHANGED
    global OUTPUT

    cmd = get_updateios_cmd(module)
    ret, std_out = exec_cmd(cmd)

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

    logging.info('Done with nim updateios operation')

    try:
        module.exit_json(
            changed = CHANGED,
            msg = "NIM VIO update operation completed successfully",
            targets = module.params['targets'],
            debug_output = DEBUG_DATA,
            output = OUTPUT)
    except:
        module.fail_json(msg="Something fatal happened")
