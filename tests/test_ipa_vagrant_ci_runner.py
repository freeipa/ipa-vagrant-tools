#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import shutil
import pytest

from ipavagrant.ipaci import IPACIRunner


@pytest.fixture(scope="module")
def runner():
    return IPACIRunner(['dnssec', 'simple_replication', 'backup_and_restore'],
                       dry_run=True)


def test_uninitialized1(runner):
    assert runner.is_initialized() is False


def test_uninitialized2(runner):
    with pytest.raises(RuntimeError):
        runner.run()


def test_initialize(runner):
    runner.initialize()


def test_run(runner):
    try:
        runner.run()
    finally:
        runner.destroy()
