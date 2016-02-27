#!/usr/bin/env sh

# run all tests

pylint ipavagrant ipa-vagrant-ci-*
PYLINT_RES=$?

pep8 ipavagrant/* ipa-vagrant-ci-*
PEP8_RES=$?

exit $PYLINT_RES || $PEP8_RES
