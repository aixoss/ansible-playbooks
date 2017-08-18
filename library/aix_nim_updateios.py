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
authors: Cynthia Wu, Marco Lugo, Patrice Jacquin
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
    DEBUG_DATA.append('exec command stderr:{}'.format(std_err))
    logging.debug('exec command stderr:{}'.format(std_err))
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

    cmd = ['lsnim','-l']
    for target in targets.split():
        cmd += [target]

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
def get_updateios_cmd(module, vios_status, update_op_tab, targets_list):
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

            for target in module.params['targets'].split():
                if not(vios_status is None):
                    if target not in vios_status:
                        logging.info('VIO UPDATE - target {} has been discarded (UNKNOWN)'.format(target))
                        OUTPUT.append('target {} has been discarded (UNKNOWN)'.format(target))
                        continue

                    elif vios_status[target] != 'SUCCESS-ALTDC':
                        update_op_tab[target] = vios_status[target]
                        logging.warn("VIO UPDATE - target {} has been discarded({})".format(target, vios_status[target].split()[0])) 
                        OUTPUT.append("{} target has been discarded ({})".format(target, vios_status[target].split()[0]))
                        continue

                targets_list.append(target)
                cmd += [target]

    return cmd


# ----------------------------------------------------------------
# ----------------------------------------------------------------
def nim_updateios(module, vios_status, update_op_tab, time_limit):
    """
    Execute the updateios command
        - module        the module variable
    return
        - ret           return code of nim updateios command 
    """
    global CHANGED
    global OUTPUT

    targets_list = []

    cmd = get_updateios_cmd(module, vios_status, update_op_tab, targets_list)

    # check if there is time to handle this tuple
    if not (time_limit is None) and time.localtime(time.time()) >= time_limit:
        for target in targets_list:
            update_op_tab[target] = 'SKIPPED-TIMEDOUT'
        time_limit_str = time.strftime("%m/%d/%Y %H:%M", time_limit)
        OUTPUT.append("Time limit {} reached, no further operation". \
                format(time_limit_str))
        logging.info('Time limit {} reached, no further operation'. \
                format(time_limit_str))
        return 0


    # TBC - Begin: For test only - should be removed
    # OUTPUT.append('NIM Command: {} '.format(cmd))
    # ret = 0
    # std_out = 'NIM Command: {} '.format(cmd)
    # TBC - End

    # TBC - should be commented for test !
    # ret, std_out = exec_cmd(cmd)
    ret, std_out = exec_cmd(cmd)

    if ret != 0:
        logging.error('Error: NIM Command: {} failed with return code {}'.format(cmd, ret))
        OUTPUT.append("FAILURE")
        for target in targets_list:
            update_op_tab[target] = 'FAILURE-UPDT1'
    else:
        OUTPUT.append("SUCCESS")
        for target in targets_list:
            update_op_tab[target] = 'SUCCESS-UPDT1' 

    CHANGED = True

    return ret


###################################################################################

if __name__ == '__main__':
    DEBUG_DATA = []
    OUTPUT = []
    CHANGED = False
    VARS = {}

    module = AnsibleModule(
        argument_spec=dict(
            description=dict(required=False, type='str'),
            targets=dict(required=True, type='str'),
            filesets=dict(required=False, type='str'),
            installp_bundle=dict(required=False, type='str'),
            lpp_source=dict(required=True, type='str'),
            accept_licenses=dict(required=False, type='str'),
            updateios_flags=dict(required=True, type='str'),
            preview=dict(required=False, type='str'),
            time_limit=dict(required=False, type='str'),
            vars=dict(required=False, type='dict'),
            vios_status=dict(required=False, type='dict')
        )
    )

    targets_update_status = {}
    vios_status = {}

    # =========================================================================
    # Get Module params
    # =========================================================================
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

    # Handle playbook variables
    LOGNAME = '/tmp/ansible_updateios_debug.log'
    if module.params['vars']:
        VARS = module.params['vars']
    if not VARS == None and not VARS.has_key('log_file'):
        VARS['log_file'] = LOGNAME

    # Open log file
    DEBUG_DATA.append('Log file: {}'.format(VARS['log_file']))
    LOGFRMT = '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s'
    logging.basicConfig(filename="{}".format(VARS['log_file']), \
            format=LOGFRMT, level=logging.DEBUG)


    # =========================================================================
    # Perfom the update
    # =========================================================================

    logging.debug('*** START NIM VIO UPDATE OPERATION ***')
    OUTPUT.append('VIO Update operation for {}'.format(module.params['targets']))

    ret = nim_updateios(module, vios_status, targets_update_status, time_limit)

    if len(targets_update_status) != 0:
        OUTPUT.append('NIM VIO update operation status:')
        logging.info('NIM VIO update operation status:')
        for vios_key in targets_update_status.keys():
            OUTPUT.append("    {} : {}".format(vios_key, targets_update_status[vios_key]))
            logging.info('    {} : {}'.format(vios_key, targets_update_status[vios_key]))

        logging.info('NIM VIO update operation result: {}'.format(targets_update_status))
    else:
        OUTPUT.append('NIM VIO update operation: Error getting the status')
        targets_update_status = vios_status

    # =========================================================================
    # Exit
    # =========================================================================
    module.exit_json(
        changed = CHANGED,
        msg = "NIM VIO update operation completed successfully",
        targets = module.params['targets'],
        debug_output = DEBUG_DATA,
        output = OUTPUT,
        status = targets_update_status)
