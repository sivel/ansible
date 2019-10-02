# Copyright (c) 2019 Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# This file and below imports are for backwards compat
# new code should import these from their new locations
from ansible.module_utils._text import to_unsafe_bytes, to_unsafe_text
from ansible.module_utils.common.text.unsafe import AnsibleUnsafe, AnsibleUnsafeBytes, AnsibleUnsafeText, UnsafeProxy, wrap_var
