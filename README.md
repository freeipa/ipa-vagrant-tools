# ipa-devel-tools
Status: ![travis-ci status](https://travis-ci.org/bastiak/ipa-devel-tools.svg?branch=master)

Tools to simplify freeIPA development and testing

Installation:
```
$ sudo python3 setup.py install
```

## ipa-vagrant-ci-topology-create
Creates a topology for CI tests by using vagrant.
This script creates new directory structure and configuration files for vagrant and IPA CI tests.

Basic usage:

```
$ ipa-vagrant-ci-topology-create basic-test --replicas 1 --clients 1 --add-package={freeipa-server,freeipa-server-dns,freeipa-tests}
$ cd basic-test
    # to test own RPMs, please put them into rpm directory
$ vagrant up
$ vagrant ssh
$ IPATEST_YAML_CONFIG=/vagrant/ipa-test-config.yaml ipa-run-tests test_integration/test_simple_replication.py --verbose --logging-level=debug --pdb
<enjoy/>
$ logout
$ vagrant destroy
```

Persistent custom configuration changes can be made by editing configuration yaml file. The configuration file is not created by default, must be exported by using option --export-config first.

Exporting configuration:
```
$ ipa-vagrant-ci-topology-create basic-test --export-config
```
Default location of configuration file  is '~/.ipa\_vagrant\_config.yaml'. Different location can be specified by --config-file option.


Showing current configuration:
```
$ ipa-vagrant-ci-topology-create basic-test --show-config
```

## ipa-vagrant-ci-runner
Prepares topology and runs specified tests by using vagrant.
To test own RPM files, please put them into rpm directory created by --init option

Basic usage:
```
$ mkdir my-ci
$ cd my-ci
$ cp my-rpms-to-test*.rpm rpm/
$ ipa-vagrant-ci-runner simple_replication [test2 ...]
```

To get list of tests available please run:
```
$ ipa-vagrant-ci-runner --list-tests
```

test
