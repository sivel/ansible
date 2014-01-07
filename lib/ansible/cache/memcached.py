# (c) 2014, Michael DeHaan <michael.dehaan@gmail.com>
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
import sys

from ansible import constants as C

try:
    import memcache
except ImportError:
    print 'python-memcached is required for the memcached fact cache'
    sys.exit(1)


class CacheModule(object):

    def __init__(self, *args, **kwargs):
        if C.CACHE_PLUGIN_CONNECTION:
            connection = C.CACHE_PLUGIN_CONNECTION.split(',')
        else:
            connection = ['127.0.0.1:11211']

        self._timeout = C.CACHE_PLUGIN_TIMEOUT
        self._cache = memcache.Client(connection, debug=0)

    def get(self, key, default):
        mc_key = 'ansible_fact_%s' % key
        value = self._cache.get(mc_key)
        if value is None:
            return default
        else:
            return value

    def set(self, key, value):
        mc_key = 'ansible_fact_%s' % key
        self._cache.set(mc_key, value, time=self._timeout)

