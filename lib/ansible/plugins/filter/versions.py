# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from functools import partial

from ansible import errors
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.compat.version import LooseVersion, StrictVersion
from ansible.utils.version import SemanticVersion


try:
    from packaging.version import Version as PEP440Version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False


VERSION_TYPE_MAP = {
    'loose': LooseVersion,
    'strict': StrictVersion,
    'semver': SemanticVersion,
    'semantic': SemanticVersion,
    'pep440': None,
}
if HAS_PACKAGING:
    VERSION_TYPE_MAP['pep440'] = PEP440Version


def _version(name, value):
    try:
        cls = VERSION_TYPE_MAP[name]
    except KeyError:
        if name == 'pep440' and not HAS_PACKAGING:
            raise errors.AnsibleFilterError("The pep440_version filter requires the Python 'packaging' library")
        raise

    try:
        return cls(to_text(value))
    except Exception as e:
        raise errors.AnsibleFilterError(f'Cannot parse version: {e}')


class FilterModule(object):
    def filters(self):
        return {
            'loose_version': partial(_version, 'loose'),
            'strict_version': partial(_version, 'strict'),
            'semver_version': partial(_version, 'semver'),
            'semantic_version': partial(_version, 'semantic'),
            'pep440_version': partial(_version, 'pep440'),
        }
