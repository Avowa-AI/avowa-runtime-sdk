# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""Everything about the package is in pyproject.toml. This file exists for one thing pyproject
cannot express: placing `avowa_auto.pth` at the top of site-packages, where Python reads it at
start-up. That is what lets an app keep its usual start command."""
import os

from setuptools import setup
from setuptools.command.build_py import build_py


class build_py_with_hook(build_py):
    def run(self):
        super().run()
        self.mkpath(self.build_lib)
        self.copy_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "avowa_auto.pth"),
                       os.path.join(self.build_lib, "avowa_auto.pth"))


setup(cmdclass={"build_py": build_py_with_hook})
