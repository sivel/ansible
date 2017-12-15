# Copyright (c), Matt Martz <matt@sivel.net> 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import datetime
import sys
import types

from collections import Set
from itertools import repeat


from ansible.module_utils.six import (
    binary_type,
    iteritems,
    text_type,
)
from ansible.module_utils._text import to_bytes, to_native, to_text


try:
    import json
    # Detect the python-json library which is incompatible
    # Look for simplejson if that's the case
    try:
        if not isinstance(json.loads, types.FunctionType) or not isinstance(json.dumps, types.FunctionType):
            raise ImportError
    except AttributeError:
        raise ImportError
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        print('\n{"msg": "Error: ansible requires the stdlib json or simplejson module, neither was found!", "failed": true}')
        sys.exit(1)
    except SyntaxError:
        print('\n{"msg": "SyntaxError: probably due to installed simplejson being for a different python version", "failed": true}')
        sys.exit(1)
    else:
        sj_version = json.__version__.split('.')
        if sj_version < ['1', '6']:
            # Version 1.5 released 2007-01-18 does not have the encoding parameter which we need
            print('\n{"msg": "Error: Ansible requires the stdlib json or simplejson >= 1.6.  Neither was found!", "failed": true}')


def json_dict_unicode_to_bytes(d, encoding='utf-8', errors='surrogate_or_strict'):
    ''' Recursively convert dict keys and values to byte str

        Specialized for json return because this only handles, lists, tuples,
        and dict container types (the containers that the json module returns)
    '''

    if isinstance(d, text_type):
        return to_bytes(d, encoding=encoding, errors=errors)
    elif isinstance(d, dict):
        return dict(map(json_dict_unicode_to_bytes, iteritems(d), repeat(encoding), repeat(errors)))
    elif isinstance(d, list):
        return list(map(json_dict_unicode_to_bytes, d, repeat(encoding), repeat(errors)))
    elif isinstance(d, tuple):
        return tuple(map(json_dict_unicode_to_bytes, d, repeat(encoding), repeat(errors)))
    else:
        return d


def json_dict_bytes_to_unicode(d, encoding='utf-8', errors='surrogate_or_strict'):
    ''' Recursively convert dict keys and values to byte str

        Specialized for json return because this only handles, lists, tuples,
        and dict container types (the containers that the json module returns)
    '''

    if isinstance(d, binary_type):
        # Warning, can traceback
        return to_text(d, encoding=encoding, errors=errors)
    elif isinstance(d, dict):
        return dict(map(json_dict_bytes_to_unicode, iteritems(d), repeat(encoding), repeat(errors)))
    elif isinstance(d, list):
        return list(map(json_dict_bytes_to_unicode, d, repeat(encoding), repeat(errors)))
    elif isinstance(d, tuple):
        return tuple(map(json_dict_bytes_to_unicode, d, repeat(encoding), repeat(errors)))
    else:
        return d


def _json_encode_fallback(obj):
    if isinstance(obj, Set):
        return list(obj)
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    raise TypeError("Cannot json serialize %s" % to_native(obj))


def jsonify(data, **kwargs):
    for encoding in ("utf-8", "latin-1"):
        try:
            return json.dumps(data, encoding=encoding, default=_json_encode_fallback, **kwargs)
        # Old systems using old simplejson module does not support encoding keyword.
        except TypeError:
            try:
                new_data = json_dict_bytes_to_unicode(data, encoding=encoding)
            except UnicodeDecodeError:
                continue
            return json.dumps(new_data, default=_json_encode_fallback, **kwargs)
        except UnicodeDecodeError:
            continue
    raise UnicodeError('Invalid unicode encoding encountered')
