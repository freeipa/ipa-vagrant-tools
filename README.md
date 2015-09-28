# ipa-devel-tools
Tools to simplify freeIPA development and testing

## ipa-vagrant-ci-topology-create.py
Creates a topology for CI tests by using vagrant.
This script creates new directory structure and configuration files for vagrant and IPA CI tests.

Basic usage:

```
$ python3 ipa-vagrant-ci-topology-create.py basic-test --replicas 1 --clients 1 --add-package={freeipa-server,freeipa-tests}
$ cd basic-test
$ vagrant up
$ vagrant ssh
$ IPATEST_YAML_CONFIG=/vagrant/ipa-test-config.yaml ipa-run-tests test_integration/test_simple_replication.py
<enjoy/>i
$ logout
$ vagrant destroy
```
