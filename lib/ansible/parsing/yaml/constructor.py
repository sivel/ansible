# (c) 2012-2014, Michael DeHaan <michael.dehaan@gmail.com>
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

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


from ansible.parsing.yaml.base_constructor import AnsibleBaseConstructor
from yaml.constructor import SafeConstructor, ConstructorError
from yaml.nodes import MappingNode

from ansible.module_utils._text import to_bytes, to_native
from ansible.parsing.yaml.objects import AnsibleMapping, AnsibleSequence, AnsibleUnicode
from ansible.parsing.yaml.objects import AnsibleVaultEncryptedUnicode
from ansible.utils.unsafe_proxy import wrap_var
from ansible.parsing.vault import VaultLib
from ansible.utils.display import Display


display = Display()


class AnsibleConstructor(AnsibleBaseConstructor):
    def __init__(self, file_name=None, vault_secrets=None):
        super(AnsibleConstructor, self).__init__(file_name=file_name)
        self._vaults = {}
        self.vault_secrets = vault_secrets or []
        self._vaults['default'] = VaultLib(secrets=self.vault_secrets)

    def construct_vault_encrypted_unicode(self, node):
        value = self.construct_scalar(node)
        b_ciphertext_data = to_bytes(value)
        # could pass in a key id here to choose the vault to associate with
        # TODO/FIXME: plugin vault selector
        vault = self._vaults['default']
        if vault.secrets is None:
            raise ConstructorError(context=None, context_mark=None,
                                   problem="found !vault but no vault password provided",
                                   problem_mark=node.start_mark,
                                   note=None)
        ret = AnsibleVaultEncryptedUnicode(b_ciphertext_data)
        ret.vault = vault
        return ret


AnsibleConstructor.add_constructor(
    u'!vault',
    AnsibleConstructor.construct_vault_encrypted_unicode)

AnsibleConstructor.add_constructor(u'!vault-encrypted', AnsibleConstructor.construct_vault_encrypted_unicode)
