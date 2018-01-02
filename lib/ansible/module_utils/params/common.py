# Copyright (c), Michael DeHaan <michael.dehaan@gmail.com>, 2012-2013
# Copyright (c), Toshio Kuratomi <tkuratomi@ansible.com> 2016
# Copyright (c), Matt Martz <matt@sivel.net> 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import os
import re
import sys

from collections import Mapping, Sequence

# Note: When getting Sequence from collections, it matches with strings.  If
# this matters, make sure to check for strings before checking for sequencetype
try:
    from collections.abc import KeysView
    SEQUENCETYPE = (Sequence, frozenset, KeysView)
except ImportError:
    SEQUENCETYPE = (Sequence, frozenset)


from ansible.module_utils.common.json import json, jsonify
from ansible.module_utils.pycompat24 import literal_eval
from ansible.module_utils.pycompat27 import NoneType
from ansible.module_utils.parsing.convert_bool import BOOLEANS_FALSE, BOOLEANS_TRUE, boolean
from ansible.module_utils.six import (
    binary_type,
    integer_types,
    string_types,
    text_type,
)
from ansible.module_utils._text import to_native
from ansible.module_utils.text.format import _lenient_lowercase, human_to_bytes

_NUMBERTYPES = tuple(list(integer_types) + [float])

# Deprecated compat.  Only kept in case another module used these names  Using
# ansible.module_utils.six is preferred

NUMBERTYPES = _NUMBERTYPES


FILE_COMMON_ARGUMENTS = dict(
    src=dict(),
    mode=dict(type='raw'),
    owner=dict(),
    group=dict(),
    seuser=dict(),
    serole=dict(),
    selevel=dict(),
    setype=dict(),
    follow=dict(type='bool', default=False),
    # not taken by the file module, but other modules call file so it must ignore them.
    content=dict(no_log=True),
    backup=dict(),
    force=dict(),
    remote_src=dict(),  # used by assemble
    regexp=dict(),  # used by assemble
    delimiter=dict(),  # used by assemble
    directory_mode=dict(),  # used by copy
    unsafe_writes=dict(type='bool'),  # should be available to any module using atomic_move
    attributes=dict(aliases=['attr']),
)


class AnsibleFallbackNotFound(Exception):
    pass


class AnsibleUnsupportedParams(Exception):
    pass


def return_values(obj):
    """ Return native stringified values from datastructures.

    For use with removing sensitive values pre-jsonification."""
    if isinstance(obj, (text_type, binary_type)):
        if obj:
            yield to_native(obj, errors='surrogate_or_strict')
        return
    elif isinstance(obj, SEQUENCETYPE):
        for element in obj:
            for subelement in return_values(element):
                yield subelement
    elif isinstance(obj, Mapping):
        for element in obj.items():
            for subelement in return_values(element[1]):
                yield subelement
    elif isinstance(obj, (bool, NoneType)):
        # This must come before int because bools are also ints
        return
    elif isinstance(obj, NUMBERTYPES):
        yield to_native(obj, nonstring='simplerepr')
    else:
        raise TypeError('Unknown parameter type: %s, %s' % (type(obj), obj))


def safe_eval(value, locals=None, include_exceptions=False):

    # do not allow method calls to modules
    if not isinstance(value, string_types):
        # already templated to a datavaluestructure, perhaps?
        if include_exceptions:
            return (value, None)
        return value
    if re.search(r'\w\.\w+\(', value):
        if include_exceptions:
            return (value, None)
        return value
    # do not allow imports
    if re.search(r'import \w+', value):
        if include_exceptions:
            return (value, None)
        return value
    try:
        result = literal_eval(value)
        if include_exceptions:
            return (result, None)
        else:
            return result
    except Exception as e:
        if include_exceptions:
            return (value, e)
        return value


def env_fallback(*args, **kwargs):
    ''' Load value from environment '''
    for arg in args:
        if arg in os.environ:
            return os.environ[arg]
    raise AnsibleFallbackNotFound


class AnsibleParamsValidator:
    def __init__(self, argument_spec, check_invalid_arguments=None, mutually_exclusive=None,
                 required_together=None, required_one_of=None, required_if=None,
                 add_file_common_args=False, bypass_checks=False):
        self.argument_spec = argument_spec
        self.check_invalid_arguments = check_invalid_arguments
        self.mutually_exclusive = mutually_exclusive
        self.required_together = required_together
        self.required_one_of = required_one_of
        self.required_if = required_if
        self.bypass_checks = bypass_checks

        self.params = None
        self.no_log_values = set()
        self.aliases = {}
        self._legal_inputs = []

        self._options_context = []

        if add_file_common_args:
            for k, v in FILE_COMMON_ARGUMENTS.items():
                if k not in self.argument_spec:
                    self.argument_spec[k] = v

    def __call__(self, param, check_invalid_arguments=True, spec=None, legal_inputs=None):
        # append to legal_inputs and then possibly check against them
        try:
            self.aliases = self._handle_aliases(param=param)
        except Exception as e:
            # Use exceptions here because it isn't safe to call fail_json until no_log is processed
            print('\n{"failed": true, "msg": "Module alias error: %s"}' % to_native(e))
            sys.exit(1)

        self._handle_no_log_values(param=param)

        self._syslog_facility = 'LOG_USER'
        unsupported_parameters = set()
        if spec is None:
            spec = self.argument_spec
        if legal_inputs is None:
            legal_inputs = self._legal_inputs

        for (k, v) in list(param.items()):
            if check_invalid_arguments and k not in legal_inputs:
                unsupported_parameters.add(k)

        if unsupported_parameters:
            msg = "Unsupported parameters: '%s'" % "', '".join(sorted(list(unsupported_parameters)))
            if self._options_context:
                msg += " found in %s." % " -> ".join(self._options_context)
            msg += ". Supported parameters include: %s" % (', '.join(sorted(spec.keys())))
            raise AnsibleUnsupportedParams(msg)

        # check exclusive early
        if not self.bypass_checks:
            self._check_mutually_exclusive(self.mutually_exclusive)

        self._set_defaults(pre=True, param=param)
        if not self.bypass_checks:
            self._check_required_arguments(param=param)
            self._check_argument_types(param=param)
            self._check_argument_values(param=param)
            self._check_required_together(self.required_together, param=param)
            self._check_required_one_of(self.required_one_of, param=param)
            self._check_required_if(self.required_if, param=param)

        self._set_defaults(pre=False, param=param)

        self._handle_options()

    def _handle_options(self, argument_spec=None, params=None):
        ''' deal with options to create sub spec '''
        if argument_spec is None:
            argument_spec = self.argument_spec
        if params is None:
            params = self.params

        for (k, v) in argument_spec.items():
            wanted = v.get('type', None)
            if wanted == 'dict' or (wanted == 'list' and v.get('elements', '') == 'dict'):
                spec = v.get('options', None)
                if spec is None or not params[k]:
                    continue

                self._options_context.append(k)

                if isinstance(params[k], dict):
                    elements = [params[k]]
                else:
                    elements = params[k]

                for param in elements:
                    if not isinstance(param, dict):
                        raise TypeError("value of %s must be of type dict or list of dict" % k)

                    self._set_fallbacks(spec, param)
                    options_aliases = self._handle_aliases(spec, param)

                    self._handle_no_log_values(spec, param)
                    options_legal_inputs = list(spec.keys()) + list(options_aliases.keys())

                    self(param, self.check_invalid_arguments, spec, options_legal_inputs)

                    # check exclusive early
                    if not self.bypass_checks:
                        self._check_mutually_exclusive(v.get('mutually_exclusive', None), param)

                    self._set_defaults(pre=True, spec=spec, param=param)

                    self._set_defaults(pre=True, spec=spec, param=param)

                    if not self.bypass_checks:
                        self._check_required_arguments(spec, param)
                        self._check_argument_types(spec, param)
                        self._check_argument_values(spec, param)

                        self._check_required_together(v.get('required_together', None), param)
                        self._check_required_one_of(v.get('required_one_of', None), param)
                        self._check_required_if(v.get('required_if', None), param)

                    self._set_defaults(pre=False, spec=spec, param=param)

                    # handle multi level options (sub argspec)
                    self._handle_options(spec, param)
                self._options_context.pop()

    def _set_defaults(self, pre=True, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        for (k, v) in spec.items():
            default = v.get('default', None)
            if pre is True:
                # this prevents setting defaults on required items
                if default is not None and k not in param:
                    param[k] = default
            else:
                # make sure things without a default still get set None
                if k not in param:
                    param[k] = default

    def _set_fallbacks(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        for (k, v) in spec.items():
            fallback = v.get('fallback', (None,))
            fallback_strategy = fallback[0]
            fallback_args = []
            fallback_kwargs = {}
            if k not in param and fallback_strategy is not None:
                for item in fallback[1:]:
                    if isinstance(item, dict):
                        fallback_kwargs = item
                    else:
                        fallback_args = item
                try:
                    param[k] = fallback_strategy(*fallback_args, **fallback_kwargs)
                except AnsibleFallbackNotFound:
                    continue

        # append to legal_inputs and then possibly check against them
        try:
            self.aliases = self._handle_aliases(param=param)
        except Exception as e:
            # Use exceptions here because it isn't safe to call fail_json until no_log is processed
            print('\n{"failed": true, "msg": "Module alias error: %s"}' % to_native(e))
            sys.exit(1)

    def _handle_aliases(self, spec=None, param=None):
        # this uses exceptions as it happens before we can safely call fail_json
        aliases_results = {}  # alias:canon
        if param is None:
            param = self.params

        if spec is None:
            spec = self.argument_spec
        for (k, v) in spec.items():
            self._legal_inputs.append(k)
            aliases = v.get('aliases', None)
            default = v.get('default', None)
            required = v.get('required', False)
            if default is not None and required:
                # not alias specific but this is a good place to check this
                raise Exception("internal error: required and default are mutually exclusive for %s" % k)
            if aliases is None:
                continue
            if not isinstance(aliases, SEQUENCETYPE) or isinstance(aliases, (binary_type, text_type)):
                raise Exception('internal error: aliases must be a list or tuple')
            for alias in aliases:
                self._legal_inputs.append(alias)
                aliases_results[alias] = k
                if alias in param:
                    param[k] = param[alias]

        return aliases_results

    def _handle_no_log_values(self, spec=None, param=None):
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        # Use the argspec to determine which args are no_log
        for arg_name, arg_opts in spec.items():
            if arg_opts.get('no_log', False):
                # Find the value for the no_log'd param
                no_log_object = param.get(arg_name, None)
                if no_log_object:
                    self.no_log_values.update(return_values(no_log_object))

            if arg_opts.get('removed_in_version') is not None and arg_name in param:
                self._deprecations.append({
                    'msg': "Param '%s' is deprecated. See the module docs for more information" % arg_name,
                    'version': arg_opts.get('removed_in_version')
                })

    def _count_terms(self, check, param=None):
        count = 0
        if param is None:
            param = self.params
        for term in check:
            if term in param:
                count += 1
        return count

    def _check_argument_types(self, spec=None, param=None):
        ''' ensure all arguments have the requested type '''

        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params

        for (k, v) in spec.items():
            wanted = v.get('type', None)
            if k not in param:
                continue

            value = param[k]
            if value is None:
                continue

            if not callable(wanted):
                if wanted is None:
                    # Mostly we want to default to str.
                    # For values set to None explicitly, return None instead as
                    # that allows a user to unset a parameter
                    if param[k] is None:
                        continue
                    wanted = 'str'
                try:
                    type_checker = getattr(self, '_type_%s' % wanted)
                except AttributeError:
                    raise ValueError("implementation error: unknown type %s requested for %s" % (wanted, k))
            else:
                # set the type_checker to the callable, and reset wanted to the callable's name (or type if it doesn't have one, ala MagicMock)
                type_checker = wanted
                wanted = getattr(wanted, '__name__', to_native(type(wanted)))

            try:
                param[k] = type_checker(value)
            except (TypeError, ValueError) as e:
                raise ValueError("argument %s is of type %s and we were unable to convert to %s: %s" %
                                 (k, type(value), wanted, to_native(e)))

    def _check_mutually_exclusive(self, spec, param=None):
        if spec is None:
            return
        for check in spec:
            count = self._count_terms(check, param)
            if count > 1:
                msg = "parameters are mutually exclusive: %s" % ', '.join(check)
                if self._options_context:
                    msg += " found in %s" % " -> ".join(self._options_context)
                raise ValueError(msg)

    def _check_required_one_of(self, spec, param=None):
        if spec is None:
            return
        for check in spec:
            count = self._count_terms(check, param)
            if count == 0:
                msg = "one of the following is required: %s" % ', '.join(check)
                if self._options_context:
                    msg += " found in %s" % " -> ".join(self._options_context)
                raise ValueError(msg)

    def _check_required_together(self, spec, param=None):
        if spec is None:
            return
        for check in spec:
            counts = [self._count_terms([field], param) for field in check]
            non_zero = [c for c in counts if c > 0]
            if len(non_zero) > 0:
                if 0 in counts:
                    msg = "parameters are required together: %s" % ', '.join(check)
                    if self._options_context:
                        msg += " found in %s" % " -> ".join(self._options_context)
                raise ValueError(msg)

    def _check_required_arguments(self, spec=None, param=None):
        ''' ensure all required arguments are present '''
        missing = []
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        for (k, v) in spec.items():
            required = v.get('required', False)
            if required and k not in param:
                missing.append(k)
        if len(missing) > 0:
            msg = "missing required arguments: %s" % ", ".join(missing)
            if self._options_context:
                msg += " found in %s" % " -> ".join(self._options_context)
            raise ValueError(msg)

    def _check_argument_values(self, spec=None, param=None):
        ''' ensure all arguments have the requested values, and there are no stray arguments '''
        if spec is None:
            spec = self.argument_spec
        if param is None:
            param = self.params
        for (k, v) in spec.items():
            choices = v.get('choices', None)
            if choices is None:
                continue
            if isinstance(choices, SEQUENCETYPE) and not isinstance(choices, (binary_type, text_type)):
                if k in param:
                    if param[k] not in choices:
                        # PyYaml converts certain strings to bools.  If we can unambiguously convert back, do so before checking
                        # the value.  If we can't figure this out, module author is responsible.
                        lowered_choices = None
                        if param[k] == 'False':
                            lowered_choices = _lenient_lowercase(choices)
                            overlap = BOOLEANS_FALSE.intersection(choices)
                            if len(overlap) == 1:
                                # Extract from a set
                                (param[k],) = overlap

                        if param[k] == 'True':
                            if lowered_choices is None:
                                lowered_choices = _lenient_lowercase(choices)
                            overlap = BOOLEANS_TRUE.intersection(choices)
                            if len(overlap) == 1:
                                (param[k],) = overlap

                        if param[k] not in choices:
                            choices_str = ", ".join([to_native(c) for c in choices])
                            msg = "value of %s must be one of: %s, got: %s" % (k, choices_str, param[k])
                            if self._options_context:
                                msg += " found in %s" % " -> ".join(self._options_context)
                            raise ValueError(msg)
            else:
                msg = "internal error: choices for argument %s are not iterable: %s" % (k, choices)
                if self._options_context:
                    msg += " found in %s" % " -> ".join(self._options_context)
                raise ValueError(msg)

    def _check_required_if(self, spec, param=None):
        ''' ensure that parameters which conditionally required are present '''
        if spec is None:
            return
        if param is None:
            param = self.params
        for sp in spec:
            missing = []
            max_missing_count = 0
            is_one_of = False
            if len(sp) == 4:
                key, val, requirements, is_one_of = sp
            else:
                key, val, requirements = sp

            # is_one_of is True at least one requirement should be
            # present, else all requirements should be present.
            if is_one_of:
                max_missing_count = len(requirements)
                term = 'any'
            else:
                term = 'all'

            if key in param and param[key] == val:
                for check in requirements:
                    count = self._count_terms((check,), param)
                    if count == 0:
                        missing.append(check)
            if len(missing) and len(missing) >= max_missing_count:
                msg = "%s is %s but %s of the following are missing: %s" % (key, val, term, ', '.join(missing))
                if self._options_context:
                    msg += " found in %s" % " -> ".join(self._options_context)
                raise ValueError(msg)

    @staticmethod
    def _type_str(value):
        if isinstance(value, string_types):
            return value
        # Note: This could throw a unicode error if value's __str__() method
        # returns non-ascii.  Have to port utils.to_bytes() if that happens
        return str(value)

    @staticmethod
    def _type_list(value):
        if isinstance(value, list):
            return value

        if isinstance(value, string_types):
            return value.split(",")
        elif isinstance(value, int) or isinstance(value, float):
            return [str(value)]

        raise TypeError('%s cannot be converted to a list' % type(value))

    @staticmethod
    def _type_dict(value):
        if isinstance(value, dict):
            return value

        if isinstance(value, string_types):
            if value.startswith("{"):
                try:
                    return json.loads(value)
                except Exception:
                    (result, exc) = safe_eval(value, dict(), include_exceptions=True)
                    if exc is not None:
                        raise TypeError('unable to evaluate string as dictionary')
                    return result
            elif '=' in value:
                fields = []
                field_buffer = []
                in_quote = False
                in_escape = False
                for c in value.strip():
                    if in_escape:
                        field_buffer.append(c)
                        in_escape = False
                    elif c == '\\':
                        in_escape = True
                    elif not in_quote and c in ('\'', '"'):
                        in_quote = c
                    elif in_quote and in_quote == c:
                        in_quote = False
                    elif not in_quote and c in (',', ' '):
                        field = ''.join(field_buffer)
                        if field:
                            fields.append(field)
                        field_buffer = []
                    else:
                        field_buffer.append(c)

                field = ''.join(field_buffer)
                if field:
                    fields.append(field)
                return dict(x.split("=", 1) for x in fields)
            else:
                raise TypeError("dictionary requested, could not parse JSON or key=value")

        raise TypeError('%s cannot be converted to a dict' % type(value))

    @staticmethod
    def _type_bool(value):
        if isinstance(value, bool):
            return value

        if isinstance(value, string_types) or isinstance(value, int):
            return boolean(value)

        raise TypeError('%s cannot be converted to a bool' % type(value))

    @staticmethod
    def _type_int(value):
        if isinstance(value, int):
            return value

        if isinstance(value, string_types):
            return int(value)

        raise TypeError('%s cannot be converted to an int' % type(value))

    @staticmethod
    def _type_float(value):
        if isinstance(value, float):
            return value

        if isinstance(value, (binary_type, text_type, int)):
            return float(value)

        raise TypeError('%s cannot be converted to a float' % type(value))

    @staticmethod
    def _type_path(value):
        value = AnsibleParamsValidator._type_str(value)
        return os.path.expanduser(os.path.expandvars(value))

    @staticmethod
    def _type_jsonarg(value):
        # Return a jsonified string.  Sometimes the controller turns a json
        # string into a dict/list so transform it back into json here
        if isinstance(value, (text_type, binary_type)):
            return value.strip()
        else:
            if isinstance(value, (list, tuple, dict)):
                return jsonify(value)
        raise TypeError('%s cannot be converted to a json string' % type(value))

    _type_json = _type_jsonarg

    @staticmethod
    def _type_raw(value):
        return value

    @staticmethod
    def _type_bytes(value):
        try:
            human_to_bytes(value)
        except ValueError:
            raise TypeError('%s cannot be converted to a Byte value' % type(value))

    @staticmethod
    def _type_bits(value):
        try:
            human_to_bytes(value, isbits=True)
        except ValueError:
            raise TypeError('%s cannot be converted to a Bit value' % type(value))
