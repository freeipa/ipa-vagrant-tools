#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import copy
import io
import yaml

from .constants import (
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_FILENAME,
    DEFAULT_TOPO_CONFIG_FILENAME,
    DEFAULT_TEST_TOPO_CONFIG
)


class IPAVagrantConfig(object):

    def __init__(self, filename=None, **options):
        self.filename=filename
        self.config = copy.copy(DEFAULT_CONFIG)

        self.load_config_from_file()

        self.__replace_options(options)

    def __getattr__(self, item):
        try:
            return self.config[item]
        except KeyError:
            raise AttributeError()

    def __replace_options(self, options):
        """Check if any of configuration keyword is in options and
        update configuration.
        """
        for key in self.config.keys():
            try:
                val = options.get(key, None)
                if val is not None:
                    self.config[key] = val
            except KeyError:
                pass

    def load_config_from_file(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_CONFIG_FILENAME
            if not os.path.isfile(filename):
                return  # do not fail with default config

        with io.open(filename, "r") as f:
            res = yaml.safe_load(f)

        for key in res.keys():
            if key not in self.config:
                # all known options must be there, if not, please add missing
                # option to DEFAULT_CONFIG variable
                raise KeyError("Unknown option '{}'".format(key))
            elif not isinstance(res[key], type(self.config[key])):
                raise TypeError(
                    "{key} type: expected {expected}, got {got}".format(
                        key=key, expected=type(self.config[key]),
                        got=type(res[key])))
            else:
                self.config[key] = res[key]

    def export_config(self):
        filename = self.get_filename()

        with io.open(filename, "w") as f:
            yaml.safe_dump(self.config, f, default_flow_style=False)
            f.flush()

        return filename

    def get_filename(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_CONFIG_FILENAME

        return filename


class IPATopoConfig(object):

    def __init__(self, filename=None):
        self.topologies = DEFAULT_TEST_TOPO_CONFIG.get("topologies", dict())
        self.tests = DEFAULT_TEST_TOPO_CONFIG.get("tests", dict())

        self.filename = filename
        self.load_config_from_file()

    def load_config_from_file(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_TOPO_CONFIG_FILENAME
            if not os.path.isfile(filename):
                return  # do not fail with default config

        with io.open(filename, "r") as f:
            res = yaml.safe_load(f)

        self.tests.update(res.get("tests", dict()))
        self.topologies.update(res.get("topologies", dict()))

    def export_config(self):
        filename = self.get_filename()

        with io.open(filename, "w") as f:
            config = dict(tests=self.tests, topologies=self.topologies)
            yaml.safe_dump(config, f, default_flow_style=False)
            f.flush()

        return filename

    def get_filename(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_TOPO_CONFIG_FILENAME

        return filename
