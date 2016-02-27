#!/usr/bin/env sh

# run all tests

# pylint does not like pytest (tests/ dir excluded from check)
pylint ipavagrant ipa-vagrant-ci-*
PYLINT_RES=$?

pep8 ipavagrant/* ipa-vagrant-ci-* tests/*
PEP8_RES=$?

py.test tests/ --verbose
PYTEST_RES=$?

exit $PYLINT_RES || $PEP8_RES || $PYTEST_RES
