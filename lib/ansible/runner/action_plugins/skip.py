# Copyright 2014, Matt Martz <matt@sivel.net>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from ansible import utils
from ansible.callbacks import vv
from ansible.errors import AnsibleError
from ansible.runner.return_data import ReturnData


class ActionModule(object):
    """Skip specified number of tasks"""

    TRANSFERS_FILES = False

    def __init__(self, runner):
        self.runner = runner

    def run(self, conn, tmp, module_name, module_args, inject,
            complex_args=None, **kwargs):
        args = {}
        if complex_args:
            args.update(complex_args)
        args.update(utils.parse_kv(module_args))

        if 'count' in args and 'name' in args:
            raise AnsibleError('parameters are mutually exclusive: count,name')

        if 'name' in args:
            name = args['name']
            count = None
        else:
            count = args.get('count', 9999)
            if not count.isdigit() and count.lower() == 'all':
                count = 9999
            elif not count.isdigit():
                raise AnsibleError('count must be an integer or "all"')
            name = None
            count = int(count)

        vv("created 'skip' ActionModule: count=%s name=%s" % (count, name))

        result = dict(skip_to=name, skip_tasks=count)
        return ReturnData(conn=conn, result=result)
