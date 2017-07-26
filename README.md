# patch_mgmt

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

...
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

...
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

...

### FLRTVC

Creates a task to check targets vulnerability against available fixes, and apply them necessary fixes

Must be described in yaml format with the following parameters:

...
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


...
