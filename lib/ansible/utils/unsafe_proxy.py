# PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2
# --------------------------------------------
#
# 1. This LICENSE AGREEMENT is between the Python Software Foundation
# ("PSF"), and the Individual or Organization ("Licensee") accessing and
# otherwise using this software ("Python") in source or binary form and
# its associated documentation.
#
# 2. Subject to the terms and conditions of this License Agreement, PSF hereby
# grants Licensee a nonexclusive, royalty-free, world-wide license to reproduce,
# analyze, test, perform and/or display publicly, prepare derivative works,
# distribute, and otherwise use Python alone or in any derivative version,
# provided, however, that PSF's License Agreement and PSF's notice of copyright,
# i.e., "Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
# 2011, 2012, 2013, 2014 Python Software Foundation; All Rights Reserved" are
# retained in Python alone or in any derivative version prepared by Licensee.
#
# 3. In the event Licensee prepares a derivative work that is based on
# or incorporates Python or any part thereof, and wants to make
# the derivative work available to others as provided herein, then
# Licensee hereby agrees to include in any such work a brief summary of
# the changes made to Python.
#
# 4. PSF is making Python available to Licensee on an "AS IS"
# basis.  PSF MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR
# IMPLIED.  BY WAY OF EXAMPLE, BUT NOT LIMITATION, PSF MAKES NO AND
# DISCLAIMS ANY REPRESENTATION OR WARRANTY OF MERCHANTABILITY OR FITNESS
# FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF PYTHON WILL NOT
# INFRINGE ANY THIRD PARTY RIGHTS.
#
# 5. PSF SHALL NOT BE LIABLE TO LICENSEE OR ANY OTHER USERS OF PYTHON
# FOR ANY INCIDENTAL, SPECIAL, OR CONSEQUENTIAL DAMAGES OR LOSS AS
# A RESULT OF MODIFYING, DISTRIBUTING, OR OTHERWISE USING PYTHON,
# OR ANY DERIVATIVE THEREOF, EVEN IF ADVISED OF THE POSSIBILITY THEREOF.
#
# 6. This License Agreement will automatically terminate upon a material
# breach of its terms and conditions.
#
# 7. Nothing in this License Agreement shall be deemed to create any
# relationship of agency, partnership, or joint venture between PSF and
# Licensee.  This License Agreement does not grant permission to use PSF
# trademarks or trade name in a trademark sense to endorse or promote
# products or services of Licensee, or any third party.
#
# 8. By copying, installing or otherwise using Python, Licensee
# agrees to be bound by the terms and conditions of this License
# Agreement.
#
# Original Python Recipe for Proxy:
# http://code.activestate.com/recipes/496741-object-proxying/
# Author: Tomer Filiba

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import functools

from ansible.module_utils._text import to_bytes, to_text
from ansible.module_utils.common._collections_compat import Mapping, MutableSequence, Set
from ansible.module_utils.six import string_types, binary_type, text_type


__all__ = ['AnsibleUnsafe', 'wrap_var']


_UNSAFE_METHODS = frozenset(('capitalize', 'casefold', 'center', 'expandtabs', 'format', 'format_map',
                             'join', 'ljust', 'lower', 'lstrip', 'partition', 'replace', 'rsplit', 'rpartition',
                             'rjust', 'rstrip', 'split', 'splitlines', 'strip', 'swapcase', 'title', 'translate',
                             'upper', 'zfill'))


def _rewrap_return(attr, func, cls):
    @functools.wraps(func)
    def inner(*args, **kwargs):
        if attr in ('format', 'format_map'):
            raise NotImplementedError('%s is not available on unsafe objects' % attr)
        elif attr in ('partition', 'rsplit', 'rpartition', 'split', 'splitlines'):
            return [cls(r) for r in func(*args, **kwargs)]
        return cls(func(*args, **kwargs))
    return inner


def _rewrap_unsafe_methods(cls):
    for attr in _UNSAFE_METHODS:
        try:
            func = getattr(cls, attr)
        except AttributeError:
            continue
        setattr(cls, attr, _rewrap_return(attr, func, cls))
    return cls


class AnsibleUnsafe(object):
    __UNSAFE__ = True


@_rewrap_unsafe_methods
class AnsibleUnsafeBytes(binary_type, AnsibleUnsafe):
    def decode(self, *args, **kwargs):
        """Wrapper method to ensure type conversions maintain unsafe context"""
        return AnsibleUnsafeText(super(AnsibleUnsafeBytes, self).decode(*args, **kwargs))


@_rewrap_unsafe_methods
class AnsibleUnsafeText(text_type, AnsibleUnsafe):
    def encode(self, *args, **kwargs):
        """Wrapper method to ensure type conversions maintain unsafe context"""
        return AnsibleUnsafeBytes(super(AnsibleUnsafeText, self).encode(*args, **kwargs))


class UnsafeProxy(object):
    def __new__(cls, obj, *args, **kwargs):
        from ansible.utils.display import Display
        Display().deprecated(
            'UnsafeProxy is being deprecated. Use wrap_var or AnsibleUnsafeBytes/AnsibleUnsafeText directly instead',
            version='2.13'
        )
        # In our usage we should only receive unicode strings.
        # This conditional and conversion exists to sanity check the values
        # we're given but we may want to take it out for testing and sanitize
        # our input instead.
        if isinstance(obj, AnsibleUnsafe):
            return obj

        if isinstance(obj, string_types):
            obj = AnsibleUnsafeText(to_text(obj, errors='surrogate_or_strict'))
        return obj


def _wrap_dict(v):
    for k in v.keys():
        if v[k] is not None:
            v[wrap_var(k)] = wrap_var(v[k])
    return v


def _wrap_list(v):
    for idx, item in enumerate(v):
        if item is not None:
            v[idx] = wrap_var(item)
    return v


def _wrap_set(v):
    return set(item if item is None else wrap_var(item) for item in v)


def wrap_var(v):
    if v is None or isinstance(v, AnsibleUnsafe):
        return v

    if isinstance(v, Mapping):
        v = _wrap_dict(v)
    elif isinstance(v, MutableSequence):
        v = _wrap_list(v)
    elif isinstance(v, Set):
        v = _wrap_set(v)
    elif isinstance(v, binary_type):
        v = AnsibleUnsafeBytes(v)
    elif isinstance(v, text_type):
        v = AnsibleUnsafeText(v)

    return v


def to_unsafe_bytes(*args, **kwargs):
    return wrap_var(to_bytes(*args, **kwargs))


def to_unsafe_text(*args, **kwargs):
    return wrap_var(to_text(*args, **kwargs))
