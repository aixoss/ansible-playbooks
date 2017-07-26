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

### suma

Crates a task to automate the download of technology levels (TL) and service packs (SP) from a fix server.

In the aix_suma module is:


```yaml
    aix_suma:
      oslevel:  specify the OS level
      location: specify the location
      targets:  specify the target name
      action:   specify to action to be performed
```

### updateios

Updates the Virtual I/O Server to the latest maintenace level.

In the aix_updateios module is:


```yaml
    aix_updateios:
      target:           specify the target VIOS
      lpp_source:       specify the resource that will provide the installation images
      filesets:         specify a list of file sets to remove from the target
      installp_bundle:  specify the resource that lists file sets to remove on the target
      accept_licenses:  specify whether the software licenses should be automatically accepted during the installation
      updateios_flag:   specify the flag that tells updateios what operation to perform on the VIOS
      preview:          specify a preview operation for the updateios operation
```
