# ipa-devel-tools
Tools to simplify freeIPA development and testing

## ipa-vagrant-ci-topology-create.py
Creates a topology for CI tests by using vagrant.
This script creates new directory structure and configuration files for vagrant and IPA CI tests.

Basic usage:

```
$ python3 ipa-vagrant-ci-topology-create.py basic-test --replicas 1 --clients 1 --add-package={freeipa-server,freeipa-server-dns,freeipa-tests}
$ cd basic-test
$ vagrant up
$ vagrant ssh
$ IPATEST_YAML_CONFIG=/vagrant/ipa-test-config.yaml ipa-run-tests test_integration/test_simple_replication.py --verbose
<enjoy/>
$ logout
$ vagrant destroy
```

Persistent custom configuration changes can be made by editing configuration yaml file. The configuration file is not created by default, must be exported by using option --export-config first.

Exporting configuration:
```
$ python3 ipa-vagrant-ci-topology-create.py basic-test --export-config
```
Default location of configuration file  is '~/.ipa\_vagrant\_config.yaml'. Different location can be specified by --config-file option.


Showing current configuration:
```
$ python3 ipa-vagrant-ci-topology-create.py basic-test --show-config
```


## parallel-vagrant-up.sh
Not so smart bash script that runs vagrant provisioning in local directory in parallel way.
