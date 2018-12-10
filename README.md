# Updates in a NIM environment

# AIX for Ansible

## Requirements

### Platforms

- AIX 6.1
- AIX 7.1
- AIX 7.2

### Ansible

- Requires Ansible 1.2 or newer

## Resources

### SUMA

Creates a task to automate the download of technology levels (TL) and service packs (SP) from a fix server.

Must be described in yaml format with the follwoing parameters:

```yaml
    aix_suma:
      oslevel:  required; specifies the OS level to update to;
                "latest" indicates the latest level of the higher TL among
                the target; based on the fix server, aix_suma will determine
                the actual oslevel necessary to update the targets
                and create the corresponding NIM resource on the NIM server;
                xxxx-xx(-00-0000): sepcifies a TL;
                xxxx-xx-xx-xxxx or xxxx-xx-xx: specifies a SP.
      location: required; if it is an absolute path, specifies the directory where the
                packages will be downloaded on the NIM server;
                if it is a filename, specifies the lpp_source_name
      targets:  required; specifies the NIM clients to update;
                "foo*": all the NIM clients with name starting by "foo";
                "foo[2:4]": designates the NIM clients among foo2, foo3 and foo4;
                "*" or "ALL": all the NIM clients.
      action:   required; specifies to action to be performed;
                possible values: "download" to download all the fixes and create
                                 the associated NIM resources;
                              or "preview" to execute all the checks without
                                 downloading the fixes.
```

### NIM

Creates a task to update targets.

Must be described in yaml format with the following parameters:

```yaml
    aix_nim:
      lpp_source: indicates the lpp_source to apply to the targets;
                  "latest_tl", "latest_sp", "next_tl" and "next_sp" can be specified;
                  based on the NIM server resources, aix_nim will determine
                  the actual oslevel necessary to update the targets.
      targets:    specifies the NIM clients to update;
                  "foo*" designates all the NIM clients with name starting by "foo";
                  "foo[2:4]" designates the NIM clients among foo2, foo3 and foo4;
                  "*" or "ALL" designates all the NIM clients.
      async:      boolean;
                  if set to "False" (default), a NIM client will be completely
                  installed before starting the installation of another NIM client;
                  if "lpp_source" is set to "latest_xx" or "next_xx", this parameter
                  is set to "false".
      action:     required; specifies the action to perform;
                  possible values: "update", "check" or "reboot";
                  "update" performs an updates of the targets;
                           requires "lpp_source" and "targets" to be specified;
                  "check" displays the oslevel of the targets and their NIM status;
                          requires "targets" to be specified;
                  "reboot" reboots the targets. "targets" must be specified.

```

### FLRTVC

Creates a task to check targets vulnerability against available fixes, and apply them necessary fixes

Must be described in yaml format with the following parameters:

```yaml
    aix_flrtvc:
      targets:      required; specifies the NIM clients to update;
                    "foo*" designates all the NIM clients with name starting by "foo";
                    "foo[2:4]" designates the NIM clients among foo2, foo3 and foo4;
                    "*" or "ALL" designates all tne NIM clients.
      path:         Working directory used for temporary files;
                    it will contain FLRTVC reports;
                    if not specified "/tmp/ansible" is used.
      apar:         type of apar to check or download;
                    "sec" security fixes;
                    "hiper" corrections to High Impact PERvasive threats;
                    "all" default value; both "sec" fixes and "hiper" fixes.
     filesets:      only fixes on the filesets specified will be checked and updated.
     csv:           path to a file containing the description of the "sec" and "hiper" fixes;
                    this file is usually transferred form the fix server;
                    this rather big transfer can be avoided by specifying
                    an already transferred file.
     check_only:    boolean;
                    if set to "True", only checks if fixes are already applied
                    on the targets.
     download_only: boolean;
                    if set to "True", performs "check_only" and downloads the fixes
                    (no update of the targets).
     clean:         boolean;
                    if set to "True", remove the working directory at the end of execution;
                    (default "False")
     force:         boolean;
                    if set to "True", remove currently installed ifix before running flrtvc;
                    (default "False")

```

### UPDATEIOS

Updates the Virtual I/O Server.

Must be described in yaml format with the following parameters:

```yaml
    aix_nim_updateios:
      targets:          required; a list of VIOS to act upon depending on the "action" specified;
                        to perform an update on dual VIOS, specify the list as a tuple
                        with the following format : "(gdrh9v1, gdrh9v2) (gdrh10v1, gdrh10v2)”;
                        to specify a single VIOS, use the following format : "(gdrh11v0)".
      lpp_source:       the resource that will provide the installation images;
                        required in case of "install".
      filesets:         a list of filesets to act upon on each of the targets
                        depending on the "action" specified.
      installp_bundle:  the resource that lists the filesets to act upon on each of the targets
                        depending on the "action" specified;
                        "filesets" and "installp_bundle" are mutually exclusive.
      accept_licenses:  specify whether the software licenses should be automatically accepted
                        during the installation;
                        default value: "yes".
      action:           required; the operation to perform on the VIOS;
                        possible values are : "install", "commit", "reject", "cleanup" and "remove";
                        "reject" is not supported by the latest version of updateios.
      preview:          specify that only a preview operation will be performed
                        (the action itself will not be performed);
                        default value: "yes".
      time_limit:       when this parameter is specified, before starting the updateios action
                        specified on a new VIOS in the "targets" list, the actual date is compared
                        to this parameter value; if it is greater then the task is stopped;
                        the format is mm/dd/yyyy hh:mm
      vios_status:      specify the result of previous operation. This allows to combine severals
                        tasks that depend on the result of previous operation.
      vars:             specify playbook's variables to use (log_file for example);
                        if myvars is the playbook hash, use vars: "{{ myvars }}"
      nim_node:         allows to pass along NIM node info from a task to another so that it
                        discovers NIM info only one time for all tasks;
                        if you use: "register: backup_result", you can specify the following
                        nim_node: "{{ backup_result.nim_node }}"
```

### VIOS HEALTH CHECK

Performs a health check of VIOS before updating.

Requires vioshc.py as a prerequisite.
vioshc.py is available on https://github.com/aixoss/vios-health-checker.

Must be described in yaml format with the following parameters:

```yaml
    aix_nim_vios_hc:
      targets:          required; a list of VIOS to act upon depending on the "action" specified;
                        to perform a health check on dual VIOS, specify the list as a tuple
                        with the following format : "(gdrh9v1, gdrh9v2) (gdrh10v1, gdrh10v2)”;
                        to specify a single VIOS, use the following format : "(gdrh11v0)".
      action:           required; the operation to perform on the VIOS;
                        must be set to "health_check".
      vars:             specify playbook's variables to use (log_file for example);
                        if myvars is the playbook hash, use vars: "{{ myvars }}"

```

### ALTERNATE DISK COPY on a VIOS

Performs alternate disk copy on a VIOS (before update).

Must be described in yaml format with the following parameters:

```yaml
    aix_nim_vios_alt_disk:
      targets:          required; a list of VIOS to act upon depending on the "action" specified;
                        use a tuple format with the 1st element the VIOS and the 2nd element
                        the disk used for the alternate disk copy;
                        for a dual VIOS, the format will look like : "(vios1,disk1,vios2,disk2)";
                        for a single VIOS, the format will look like : "(vios1,disk1)".
      action:           required; the operation to perform on the VIOS;
                        2 possible values : "alt_disk_copy" and "alt_disk_clean".
      disk_size_policy: specify how the choose the alternate disk if not specified;
                        4 possible values : "nearest" (default), "lower", "upper", "minimize".
      time_limit:       when this parameter is specified, before starting the altternate disk action
                        specified on a new VIOS in the "targets" list, the actual date is compared
                        to this parameter value; if it is greater then the task is stopped
                        the format is mm/dd/yyyy hh:mm
      force:            when set to "yes", any existing altinst_rootvg is cleaned before looking for
                        an alternate disk for the copy operation.
      vios_status:      specify the result of previous operation. This allows to combine severals
                        tasks that depend on the result of previous operation.
      vars:             specify playbook's variables to use (log_file for example);
                        if myvars is the playbook hash, use vars: "{{ myvars }}"
      nim_node:         allows to pass along NIM node info from a task to another so that it
                        discovers NIM info only one time for all tasks;
                        if you use: "register: backup_result", you can specify the following
                        nim_node: "{{ backup_result.nim_node }}"

```

### VIOSUPGRADE

Upgrades the Virtual I/O Server using NIM and viosupgrade perl tool.

Must be described in yaml format with the following parameters:

```yaml
    aix_nim_viosupgrade:
      targets:          required; type: list; specify the list of VIOS to act upon depending
                        on the "action" specified; to perform an action on dual or single VIOS,
                        specify the list of tuple with the following format:
                        ["vios1 vios2", "vios11 vios12", "vios21"];
                        each tuple is a string, a list of vios separated by ":" or "," or spaces
      action:           required; type: dictionary. Specify the operation to perform per VIOS;
                        possible values are : bosinst or altdisk.
                        syntax: {'vios1': 'bosinst', 'vios2': 'altdisk', 'all_vios': 'bosinst'}
                        the default value is specified by the "all_vios" key
      ios_mksysb:       required; type: dictionary; specify the NIM resource to use for the
                        installation per vios; use the following syntax:
                        {'vios1': 'ios_1844B_72M', 'all_vios': 'ios_1844B_72M'};
                        the default value is specified by the "all_vios" key
      alt_disk:         type: dictionary; if action is bosinst, it specify the disks
                        to clone rootvg; if action is altdisk, it specify the disks where the new
                        systm will be installed.
                        the disk names are specified for each vios using the following format
                        exemple: {'vios1': 'hdisk1: hdisk2', 'vios3': 'hdisk5 hdisk6'}
                        the disk names could be separated by collomn ":" or comma "," or spaces
                        the bosinst action requires one and only one of the both following conditions:
                        - an alt_inst_disk is specified for the vios
                        - an altinst_rootvg already exist on the vios
      force:            type: dictionary; specify for each vios
                        whether the vios will be installed or not in case the
                        ioslevel == ios_mksysb level
                        syntax: {'vios1': True, 'all_vios': False}
      user_res:         type: dictionary; specify for each vios the NIM resource name to use for
                        the VIOS installation;
                        exemple: {'vios1': 'script_name file_res_name', 'all_vios': 'resolv_conf_name'}
                        in this exemple the resources used for vios1 installation will be:
                        script_name, file_res_name and resolv_conf_name
                        the supported resource type are: resolv_conf, script, fb_script, file_res
                        image_data, log
                        the file_res type is not supported for altdisk installation
      vios_status:      specify the result of previous operation. This allows to combine
                        severals tasks that depend on the result of previous operation.
      vars:             specify playbook's variables to use (log_file for example);
                        if myvars is the playbook hash, use vars: "{{ myvars }}"
      nim_node:         allows to pass along NIM node info from a task to another so that it
                        discovers NIM info only one time for all tasks;
                        if you use: "register: backup_result", you can specify the following
                        nim_node: "{{ backup_result.nim_node }}"
```
