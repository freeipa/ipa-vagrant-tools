#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import pytest

from ipavagrant.config import IPAVagrantConfig, IPATopoConfig
from ipavagrant.constants import (
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_TOPO_CONFIG_FILENAME
)


@pytest.fixture(scope="module")
def default_config():
    return IPAVagrantConfig()


@pytest.fixture(scope="module")
def default_topo_config():
    return IPATopoConfig()


def test_default_config_file(default_config):
    assert default_config.get_filename() == DEFAULT_CONFIG_FILENAME


def test_topo_default_config_file(default_topo_config):
    assert default_topo_config.get_filename() == DEFAULT_TOPO_CONFIG_FILENAME
