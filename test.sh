#!/usr/bin/env sh
# run all tests

# pylint does not like pytest (tests/ dir excluded from check)
pylint ipavagrant ipa-vagrant-ci-*

pep8 ipavagrant/* ipa-vagrant-ci-* tests/*

py.test tests/ --verbose

test
