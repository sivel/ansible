#!/usr/bin/env python

from __future__ import annotations

import json
from importlib.resources import files

from ansible.module_utils.common.yaml import yaml_load


_TMPL = '''from __future__ import annotations

null = None
true = True
false = False

DATA = {data}
'''


config = files('ansible.config')
for yml_file in config.glob('*.yml'):
    with yml_file.open() as f:
        data = yaml_load(f)
    py_file = yml_file.with_suffix('.py')
    with py_file.open('w+') as f:
        f.write(
            _TMPL.format(
                data=json.dumps(data, indent=4, sort_keys=True)
            )
        )
