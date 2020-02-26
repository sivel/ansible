# Copyright (c) 2020 Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.plugins.loader import module_loader

import json
import sys
import runpy

data = json.loads(sys.argv[1])

path = module_loader.find_plugin(data['module_name'], collection_list=data['collections'])
# Hack, ansible.module_utils.basic._load_params would treat this incorrectly
# with our sys.argv, reset to something that doesn't cause problems
sys.argv = [path]

runpy.run_path(path, init_globals=None, run_name='__main__')
