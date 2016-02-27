#!/usr/bin/env sh

# run all tests

pylint ipavagrant ipa-vagrant-ci-*
PYLINT_RES=$?
if [[ $PYLINT_RES = 0 ]]; then
    echo "pylint: PASS"
fi

pep8 ipavagrant/* ipa-vagrant-ci-*
PEP8_RES=$?
if [[ $PEP8_RES = 0 ]]; then
    echo "PEP8: PASS"
fi

exit $PYLINT_RES || $PEP8_RES
