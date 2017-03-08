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

In the aix_syma module is:


```yaml
    aix_suma:
      oslevel:  specify the OS level
      location: specify the location
      targets:  specify the target name
      action:   specify to action to be performed
```
