# Copyright (c), Matt Martz <matt@sivel.net> 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

FILE_ATTRIBUTES = {
    'A': 'noatime',
    'a': 'append',
    'c': 'compressed',
    'C': 'nocow',
    'd': 'nodump',
    'D': 'dirsync',
    'e': 'extents',
    'E': 'encrypted',
    'h': 'blocksize',
    'i': 'immutable',
    'I': 'indexed',
    'j': 'journalled',
    'N': 'inline',
    's': 'zero',
    'S': 'synchronous',
    't': 'notail',
    'T': 'blockroot',
    'u': 'undelete',
    'X': 'compressedraw',
    'Z': 'compresseddirty',
}

# ansible modules can be written in any language.  To simplify
# development of Python modules, the functions available here can
# be used to do many common tasks

import locale
import os
import re
import shlex
import sys
import types  # noqa: F401
import shutil
import stat
import tempfile
import traceback
import grp
import pwd
import errno
from collections import Sequence
from itertools import chain, repeat  # noqa: F401

try:
    import syslog
    HAS_SYSLOG = True
except ImportError:
    HAS_SYSLOG = False

try:
    from systemd import journal
    has_journal = True
except ImportError:
    has_journal = False

# Note: When getting Sequence from collections, it matches with strings.  If
# this matters, make sure to check for strings before checking for sequencetype
try:
    from collections.abc import KeysView
    SEQUENCETYPE = (Sequence, frozenset, KeysView)
except ImportError:
    SEQUENCETYPE = (Sequence, frozenset)

from ansible.module_utils.pycompat24 import literal_eval
from ansible.module_utils.six import (
    PY2,
    PY3,
    binary_type,
    integer_types,
    string_types,
    text_type,
)
from ansible.module_utils.six.moves import map, shlex_quote
from ansible.module_utils._text import to_native, to_bytes, to_text
from ansible.module_utils.parsing.convert_bool import boolean
# TODO: Import selinux_enabled
from ansible.module_utils.common.file import HAVE_SELINUX
from ansible.module_utils.common.logging import heuristic_log_sanitize, remove_values
from ansible.module_utils.common.json import json, json_dict_unicode_to_bytes, jsonify
from ansible.module_utils.params.common import AnsibleUnsupportedParams


PASSWORD_MATCH = re.compile(r'^(?:.+[-_\s])?pass(?:[-_\s]?(?:word|phrase|wrd|wd)?)(?:[-_\s].+)?$', re.I)

_NUMBERTYPES = tuple(list(integer_types) + [float])

# Deprecated compat.  Only kept in case another module used these names  Using
# ansible.module_utils.six is preferred

NUMBERTYPES = _NUMBERTYPES

imap = map

try:
    # Python 2
    unicode
except NameError:
    # Python 3
    unicode = text_type

try:
    # Python 2.6+
    bytes
except NameError:
    # Python 2.4
    bytes = binary_type

try:
    # Python 2
    basestring
except NameError:
    # Python 3
    basestring = string_types

_literal_eval = literal_eval

# End of deprecated names

# Internal global holding passed in params.  This is consulted in case
# multiple AnsibleModules are created.  Otherwise each AnsibleModule would
# attempt to read from stdin.  Other code should not use this directly as it
# is an internal implementation detail
_ANSIBLE_ARGS = None

PASSWD_ARG_RE = re.compile(r'^[-]{0,2}pass[-]?(word|wd)?')


def _load_params():
    ''' read the modules parameters and store them globally.

    This function may be needed for certain very dynamic custom modules which
    want to process the parameters that are being handed the module.  Since
    this is so closely tied to the implementation of modules we cannot
    guarantee API stability for it (it may change between versions) however we
    will try not to break it gratuitously.  It is certainly more future-proof
    to call this function and consume its outputs than to implement the logic
    inside it as a copy in your own code.
    '''
    global _ANSIBLE_ARGS
    if _ANSIBLE_ARGS is not None:
        buffer = _ANSIBLE_ARGS
    else:
        # debug overrides to read args from file or cmdline

        # Avoid tracebacks when locale is non-utf8
        # We control the args and we pass them as utf8
        if len(sys.argv) > 1:
            if os.path.isfile(sys.argv[1]):
                fd = open(sys.argv[1], 'rb')
                buffer = fd.read()
                fd.close()
            else:
                buffer = sys.argv[1]
                if PY3:
                    buffer = buffer.encode('utf-8', errors='surrogateescape')
        # default case, read from stdin
        else:
            if PY2:
                buffer = sys.stdin.read()
            else:
                buffer = sys.stdin.buffer.read()
        _ANSIBLE_ARGS = buffer

    try:
        params = json.loads(buffer.decode('utf-8'))
    except ValueError:
        # This helper used too early for fail_json to work.
        print('\n{"msg": "Error: Module unable to decode valid JSON on stdin.  Unable to figure out what parameters were passed", "failed": true}')
        sys.exit(1)

    if PY2:
        params = json_dict_unicode_to_bytes(params)

    try:
        return params['ANSIBLE_MODULE_ARGS']
    except KeyError:
        # This helper does not have access to fail_json so we have to print
        # json output on our own.
        print('\n{"msg": "Error: Module unable to locate ANSIBLE_MODULE_ARGS in json data from stdin.  Unable to figure out what parameters were passed", '
              '"failed": true}')
        sys.exit(1)


class AnsibleModule(object):
    def __init__(self, argument_validator, bypass_checks=False, no_log=False, supports_check_mode=False):

        '''
        common code for quickly building an ansible module in Python
        (although you can write modules in anything that can return JSON)
        see library/* for examples
        '''

        self._name = os.path.basename(__file__)  # initialize name until we can parse from options
        self.supports_check_mode = supports_check_mode
        self.check_mode = False
        self.no_log = no_log
        self.cleanup_files = []
        self._debug = False
        self._diff = False
        self._socket_path = None
        self._shell = None
        self._verbosity = 0
        # May be used to set modifications to the environment for any
        # run_command invocation
        self.run_command_environ_update = {}
        self._warnings = []
        self._deprecations = []
        self._clean = {}

        self._syslog_facility = 'LOG_USER'

        params = self._load_params()
        self._set_attrs_from_params()

        if self.check_mode and not self.supports_check_mode:
            self.exit_json(skipped=True, msg="remote module (%s) does not support check mode" % self._name)

        if not callable(argument_validator):
            self.fail_json(msg='argument_validator must be a callable')

        self.validator = argument_validator

        # Save parameter values that should never be logged
        self.no_log_values = self.validator.no_log_values

        try:
            self.validator(params)
        except AnsibleUnsupportedParams as e:
            self.fail_json(msg='%s: %s' % (self._name, to_native(e)))
        except Exception as e:
            self.fail_json(msg=to_native(e))

        # check the locale as set by the current environment, and reset to
        # a known valid (LANG=C) if it's an invalid/unavailable locale
        self._check_locale()

        if not self.no_log:
            self._log_invocation()

        # finally, make sure we're in a sane working dir
        self._set_cwd()

    def warn(self, warning):

        if isinstance(warning, string_types):
            self._warnings.append(warning)
            self.log('[WARNING] %s' % warning)
        else:
            raise TypeError("warn requires a string not a %s" % type(warning))

    def deprecate(self, msg, version=None):
        if isinstance(msg, string_types):
            self._deprecations.append({
                'msg': msg,
                'version': version
            })
            self.log('[DEPRECATION WARNING] %s %s' % (msg, version))
        else:
            raise TypeError("deprecate requires a string not a %s" % type(msg))

    def add_path_info(self, kwargs):
        '''
        for results that are files, supplement the info about the file
        in the return path with stats about the file path.
        '''

        path = kwargs.get('path', kwargs.get('dest', None))
        if path is None:
            return kwargs
        b_path = to_bytes(path, errors='surrogate_or_strict')
        if os.path.exists(b_path):
            (uid, gid) = self.user_and_group(path)
            kwargs['uid'] = uid
            kwargs['gid'] = gid
            try:
                user = pwd.getpwuid(uid)[0]
            except KeyError:
                user = str(uid)
            try:
                group = grp.getgrgid(gid)[0]
            except KeyError:
                group = str(gid)
            kwargs['owner'] = user
            kwargs['group'] = group
            st = os.lstat(b_path)
            kwargs['mode'] = '0%03o' % stat.S_IMODE(st[stat.ST_MODE])
            # secontext not yet supported
            if os.path.islink(b_path):
                kwargs['state'] = 'link'
            elif os.path.isdir(b_path):
                kwargs['state'] = 'directory'
            elif os.stat(b_path).st_nlink > 1:
                kwargs['state'] = 'hard'
            else:
                kwargs['state'] = 'file'
            # TODO: Re-import selinux stuff for this
            if HAVE_SELINUX and self.selinux_enabled():
                kwargs['secontext'] = ':'.join(self.selinux_context(path))
            kwargs['size'] = st[stat.ST_SIZE]
        else:
            kwargs['state'] = 'absent'
        return kwargs

    def _check_locale(self):
        '''
        Uses the locale module to test the currently set locale
        (per the LANG and LC_CTYPE environment settings)
        '''
        try:
            # setting the locale to '' uses the default locale
            # as it would be returned by locale.getdefaultlocale()
            locale.setlocale(locale.LC_ALL, '')
        except locale.Error:
            # fallback to the 'C' locale, which may cause unicode
            # issues but is preferable to simply failing because
            # of an unknown locale
            locale.setlocale(locale.LC_ALL, 'C')
            os.environ['LANG'] = 'C'
            os.environ['LC_ALL'] = 'C'
            os.environ['LC_MESSAGES'] = 'C'
        except Exception as e:
            self.fail_json(msg="An unknown error was encountered while attempting to validate the locale: %s" %
                           to_native(e), exception=traceback.format_exc())

    def _set_attrs_from_params(self):
        for (k, v) in list(self.params.items()):

            if k == '_ansible_check_mode' and v:
                self.check_mode = True

            elif k == '_ansible_no_log':
                self.no_log = self.boolean(v)

            elif k == '_ansible_debug':
                self._debug = self.boolean(v)

            elif k == '_ansible_diff':
                self._diff = self.boolean(v)

            elif k == '_ansible_verbosity':
                self._verbosity = v

            elif k == '_ansible_selinux_special_fs':
                self._selinux_special_fs = v

            elif k == '_ansible_syslog_facility':
                self._syslog_facility = v

            elif k == '_ansible_version':
                self.ansible_version = v

            elif k == '_ansible_module_name':
                self._name = v

            elif k == '_ansible_socket':
                self._socket_path = v

            elif k == '_ansible_shell_executable' and v:
                self._shell = v

            # clean up internal params:
            if k.startswith('_ansible_'):
                del self.params[k]

    def _load_params(self):
        ''' read the input and set the params attribute.

        This method is for backwards compatibility.  The guts of the function
        were moved out in 2.1 so that custom modules could read the parameters.
        '''
        # debug overrides to read args from file or cmdline
        self.params = _load_params()
        return self.params

    def _log_to_syslog(self, msg):
        if HAS_SYSLOG:
            module = 'ansible-%s' % self._name
            facility = getattr(syslog, self._syslog_facility, syslog.LOG_USER)
            syslog.openlog(str(module), 0, facility)
            syslog.syslog(syslog.LOG_INFO, msg)

    def debug(self, msg):
        if self._debug:
            self.log('[debug] %s' % msg)

    def log(self, msg, log_args=None):

        if not self.no_log:

            if log_args is None:
                log_args = dict()

            module = 'ansible-%s' % self._name
            if isinstance(module, binary_type):
                module = module.decode('utf-8', 'replace')

            # 6655 - allow for accented characters
            if not isinstance(msg, (binary_type, text_type)):
                raise TypeError("msg should be a string (got %s)" % type(msg))

            # We want journal to always take text type
            # syslog takes bytes on py2, text type on py3
            if isinstance(msg, binary_type):
                journal_msg = remove_values(msg.decode('utf-8', 'replace'), self.no_log_values)
            else:
                # TODO: surrogateescape is a danger here on Py3
                journal_msg = remove_values(msg, self.no_log_values)

            if PY3:
                syslog_msg = journal_msg
            else:
                syslog_msg = journal_msg.encode('utf-8', 'replace')

            if has_journal:
                journal_args = [("MODULE", os.path.basename(__file__))]
                for arg in log_args:
                    journal_args.append((arg.upper(), str(log_args[arg])))
                try:
                    journal.send(u"%s %s" % (module, journal_msg), **dict(journal_args))
                except IOError:
                    # fall back to syslog since logging to journal failed
                    self._log_to_syslog(syslog_msg)
            else:
                self._log_to_syslog(syslog_msg)

    def _log_invocation(self):
        ''' log that ansible ran the module '''
        # TODO: generalize a separate log function and make log_invocation use it
        # Sanitize possible password argument when logging.
        log_args = dict()

        for param in self.params:
            # TODO: should this be how the validator exposes aliases?
            canon = self.validator.aliases.get(param, param)
            # TODO: argument_spec no longer lives here
            # arg_opts = self.argument_spec.get(canon, {})
            arg_opts = {}
            no_log = arg_opts.get('no_log', False)

            if self.boolean(no_log):
                log_args[param] = 'NOT_LOGGING_PARAMETER'
            # try to capture all passwords/passphrase named fields missed by no_log
            elif PASSWORD_MATCH.search(param) and arg_opts.get('type', 'str') != 'bool' and not arg_opts.get('choices', False):
                # skip boolean and enums as they are about 'password' state
                log_args[param] = 'NOT_LOGGING_PASSWORD'
                self.warn('Module did not set no_log for %s' % param)
            else:
                param_val = self.params[param]
                if not isinstance(param_val, (text_type, binary_type)):
                    param_val = str(param_val)
                elif isinstance(param_val, text_type):
                    param_val = param_val.encode('utf-8')
                log_args[param] = heuristic_log_sanitize(param_val, self.no_log_values)

        msg = ['%s=%s' % (to_native(arg), to_native(val)) for arg, val in log_args.items()]
        if msg:
            msg = 'Invoked with %s' % ' '.join(msg)
        else:
            msg = 'Invoked'

        self.log(msg, log_args=log_args)

    def _set_cwd(self):
        try:
            cwd = os.getcwd()
            if not os.access(cwd, os.F_OK | os.R_OK):
                raise Exception()
            return cwd
        except Exception:
            # we don't have access to the cwd, probably because of sudo.
            # Try and move to a neutral location to prevent errors
            for cwd in [os.path.expandvars('$HOME'), tempfile.gettempdir()]:
                try:
                    if os.access(cwd, os.F_OK | os.R_OK):
                        os.chdir(cwd)
                        return cwd
                except Exception:
                    pass
        # we won't error here, as it may *not* be a problem,
        # and we don't want to break modules unnecessarily
        return None

    def boolean(self, arg):
        ''' return a bool for the arg '''
        if arg is None:
            return arg

        try:
            return boolean(arg)
        except TypeError as e:
            self.fail_json(msg=to_native(e))

    def jsonify(self, data):
        try:
            return jsonify(data)
        except UnicodeError as e:
            self.fail_json(msg=to_text(e))

    def from_json(self, data):
        return json.loads(data)

    def add_cleanup_file(self, path):
        if path not in self.cleanup_files:
            self.cleanup_files.append(path)

    def do_cleanup_files(self):
        for path in self.cleanup_files:
            self.cleanup(path)

    def _return_formatted(self, kwargs):

        self.add_path_info(kwargs)

        if 'invocation' not in kwargs:
            kwargs['invocation'] = {'module_args': self.params}

        if 'warnings' in kwargs:
            if isinstance(kwargs['warnings'], list):
                for w in kwargs['warnings']:
                    self.warn(w)
            else:
                self.warn(kwargs['warnings'])

        if self._warnings:
            kwargs['warnings'] = self._warnings

        if 'deprecations' in kwargs:
            if isinstance(kwargs['deprecations'], list):
                for d in kwargs['deprecations']:
                    if isinstance(d, SEQUENCETYPE) and len(d) == 2:
                        self.deprecate(d[0], version=d[1])
                    else:
                        self.deprecate(d)
            else:
                self.deprecate(kwargs['deprecations'])

        if self._deprecations:
            kwargs['deprecations'] = self._deprecations

        kwargs = remove_values(kwargs, self.no_log_values)
        print('\n%s' % self.jsonify(kwargs))

    def exit_json(self, **kwargs):
        ''' return from the module, without error '''

        self.do_cleanup_files()
        self._return_formatted(kwargs)
        sys.exit(0)

    def fail_json(self, **kwargs):
        ''' return from the module, with an error message '''

        if 'msg' not in kwargs:
            raise AssertionError("implementation error -- msg to explain the error is required")
        kwargs['failed'] = True

        # add traceback if debug or high verbosity and it is missing
        # Note: badly named as exception, it is really always been 'traceback'
        if 'exception' not in kwargs and sys.exc_info()[2] and (self._debug or self._verbosity >= 3):
            kwargs['exception'] = ''.join(traceback.format_tb(sys.exc_info()[2]))

        self.do_cleanup_files()
        self._return_formatted(kwargs)
        sys.exit(1)

    def fail_on_missing_params(self, required_params=None):
        ''' This is for checking for required params when we can not check via argspec because we
        need more information than is simply given in the argspec.
        '''
        if not required_params:
            return
        missing_params = []
        for required_param in required_params:
            if not self.params.get(required_param):
                missing_params.append(required_param)
        if missing_params:
            self.fail_json(msg="missing required arguments: %s" % ', '.join(missing_params))

    def cleanup(self, tmpfile):
        if os.path.exists(tmpfile):
            try:
                os.unlink(tmpfile)
            except OSError as e:
                sys.stderr.write("could not cleanup %s: %s" % (tmpfile, to_native(e)))

    def preserved_copy(self, src, dest):
        """Copy a file with preserved ownership, permissions and context"""

        # shutil.copy2(src, dst)
        #   Similar to shutil.copy(), but metadata is copied as well - in fact,
        #   this is just shutil.copy() followed by copystat(). This is similar
        #   to the Unix command cp -p.
        #
        # shutil.copystat(src, dst)
        #   Copy the permission bits, last access time, last modification time,
        #   and flags from src to dst. The file contents, owner, and group are
        #   unaffected. src and dst are path names given as strings.

        shutil.copy2(src, dest)

        # Set the context
        if self.selinux_enabled():
            context = self.selinux_context(src)
            self.set_context_if_different(dest, context, False)

        # chown it
        try:
            dest_stat = os.stat(src)
            tmp_stat = os.stat(dest)
            if dest_stat and (tmp_stat.st_uid != dest_stat.st_uid or tmp_stat.st_gid != dest_stat.st_gid):
                os.chown(dest, dest_stat.st_uid, dest_stat.st_gid)
        except OSError as e:
            if e.errno != errno.EPERM:
                raise

        # Set the attributes
        current_attribs = self.get_file_attributes(src)
        current_attribs = current_attribs.get('attr_flags', '')
        self.set_attributes_if_different(dest, current_attribs, True)

    def _clean_args(self, args):

        if not self._clean:
            # create a printable version of the command for use in reporting later,
            # which strips out things like passwords from the args list
            to_clean_args = args
            if PY2:
                if isinstance(args, text_type):
                    to_clean_args = to_bytes(args)
            else:
                if isinstance(args, binary_type):
                    to_clean_args = to_text(args)
            if isinstance(args, (text_type, binary_type)):
                to_clean_args = shlex.split(to_clean_args)

            clean_args = []
            is_passwd = False
            for arg in (to_native(a) for a in to_clean_args):
                if is_passwd:
                    is_passwd = False
                    clean_args.append('********')
                    continue
                if PASSWD_ARG_RE.match(arg):
                    sep_idx = arg.find('=')
                    if sep_idx > -1:
                        clean_args.append('%s=********' % arg[:sep_idx])
                        continue
                    else:
                        is_passwd = True
                arg = heuristic_log_sanitize(arg, self.no_log_values)
                clean_args.append(arg)
            self._clean = ' '.join(shlex_quote(arg) for arg in clean_args)

        return self._clean
