# Copyright (c), Matt Martz <matt@sivel.net> 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import errno
import os
import stat
import re
import pwd
import grp
import time
import shutil
import tempfile
import traceback


from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.six import b, binary_type

try:
    import selinux
    HAVE_SELINUX = True
except ImportError:
    HAVE_SELINUX = False


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


# Used for parsing symbolic file perms
MODE_OPERATOR_RE = re.compile(r'[+=-]')
USERS_RE = re.compile(r'[^ugo]')
PERMS_RE = re.compile(r'[^rwxXstugo]')


PERM_BITS = 0o7777       # file mode permission bits
EXEC_PERM_BITS = 0o0111  # execute permission bits
DEFAULT_PERM = 0o0666    # default file permission bits


def is_executable(path):
    '''is the given path executable?

    Limitations:
    * Does not account for FSACLs.
    * Most times we really want to know "Can the current user execute this
      file"  This function does not tell us that, only if an execute bit is set.
    '''
    # These are all bitfields so first bitwise-or all the permissions we're
    # looking for, then bitwise-and with the file's mode to determine if any
    # execute bits are set.
    return ((stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) & os.stat(path)[stat.ST_MODE])


# TODO: Wrap in a class?
class DummyClass(object):
    def load_file_common_arguments(self, params):
        '''
        many modules deal with files, this encapsulates common
        options that the file module accepts such that it is directly
        available to all modules and they can share code.
        '''

        path = params.get('path', params.get('dest', None))
        if path is None:
            return {}
        else:
            path = os.path.expanduser(os.path.expandvars(path))

        b_path = to_bytes(path, errors='surrogate_or_strict')
        # if the path is a symlink, and we're following links, get
        # the target of the link instead for testing
        if params.get('follow', False) and os.path.islink(b_path):
            b_path = os.path.realpath(b_path)
            path = to_native(b_path)

        mode = params.get('mode', None)
        owner = params.get('owner', None)
        group = params.get('group', None)

        # selinux related options
        seuser = params.get('seuser', None)
        serole = params.get('serole', None)
        setype = params.get('setype', None)
        selevel = params.get('selevel', None)
        secontext = [seuser, serole, setype]

        if self.selinux_mls_enabled():
            secontext.append(selevel)

        default_secontext = self.selinux_default_context(path)
        for i in range(len(default_secontext)):
            if i is not None and secontext[i] == '_default':
                secontext[i] = default_secontext[i]

        attributes = params.get('attributes', None)
        return dict(
            path=path, mode=mode, owner=owner, group=group,
            seuser=seuser, serole=serole, setype=setype,
            selevel=selevel, secontext=secontext, attributes=attributes,
        )

    # Detect whether using selinux that is MLS-aware.
    # While this means you can set the level/range with
    # selinux.lsetfilecon(), it may or may not mean that you
    # will get the selevel as part of the context returned
    # by selinux.lgetfilecon().

    def selinux_mls_enabled(self):
        if not HAVE_SELINUX:
            return False
        if selinux.is_selinux_mls_enabled() == 1:
            return True
        else:
            return False

    def selinux_enabled(self):
        if not HAVE_SELINUX:
            seenabled = self.get_bin_path('selinuxenabled')
            if seenabled is not None:
                (rc, out, err) = self.run_command(seenabled)
                if rc == 0:
                    self.fail_json(msg="Aborting, target uses selinux but python bindings (libselinux-python) aren't installed!")
            return False
        if selinux.is_selinux_enabled() == 1:
            return True
        else:
            return False

    # Determine whether we need a placeholder for selevel/mls
    def selinux_initial_context(self):
        context = [None, None, None]
        if self.selinux_mls_enabled():
            context.append(None)
        return context

    # If selinux fails to find a default, return an array of None
    def selinux_default_context(self, path, mode=0):
        context = self.selinux_initial_context()
        if not HAVE_SELINUX or not self.selinux_enabled():
            return context
        try:
            ret = selinux.matchpathcon(to_native(path, errors='surrogate_or_strict'), mode)
        except OSError:
            return context
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context

    def selinux_context(self, path):
        context = self.selinux_initial_context()
        if not HAVE_SELINUX or not self.selinux_enabled():
            return context
        try:
            ret = selinux.lgetfilecon_raw(to_native(path, errors='surrogate_or_strict'))
        except OSError as e:
            if e.errno == errno.ENOENT:
                self.fail_json(path=path, msg='path %s does not exist' % path)
            else:
                self.fail_json(path=path, msg='failed to retrieve selinux context')
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context

    def user_and_group(self, path, expand=True):
        b_path = to_bytes(path, errors='surrogate_or_strict')
        if expand:
            b_path = os.path.expanduser(os.path.expandvars(b_path))
        st = os.lstat(b_path)
        uid = st.st_uid
        gid = st.st_gid
        return (uid, gid)

    def find_mount_point(self, path):
        path_is_bytes = False
        if isinstance(path, binary_type):
            path_is_bytes = True

        b_path = os.path.realpath(to_bytes(os.path.expanduser(os.path.expandvars(path)), errors='surrogate_or_strict'))
        while not os.path.ismount(b_path):
            b_path = os.path.dirname(b_path)

        if path_is_bytes:
            return b_path

        return to_text(b_path, errors='surrogate_or_strict')

    def is_special_selinux_path(self, path):
        """
        Returns a tuple containing (True, selinux_context) if the given path is on a
        NFS or other 'special' fs  mount point, otherwise the return will be (False, None).
        """
        try:
            f = open('/proc/mounts', 'r')
            mount_data = f.readlines()
            f.close()
        except Exception:
            return (False, None)
        path_mount_point = self.find_mount_point(path)
        for line in mount_data:
            (device, mount_point, fstype, options, rest) = line.split(' ', 4)

            if path_mount_point == mount_point:
                for fs in self._selinux_special_fs:
                    if fs in fstype:
                        special_context = self.selinux_context(path_mount_point)
                        return (True, special_context)

        return (False, None)

    def set_default_selinux_context(self, path, changed):
        if not HAVE_SELINUX or not self.selinux_enabled():
            return changed
        context = self.selinux_default_context(path)
        return self.set_context_if_different(path, context, False)

    def set_context_if_different(self, path, context, changed, diff=None):

        if not HAVE_SELINUX or not self.selinux_enabled():
            return changed
        cur_context = self.selinux_context(path)
        new_context = list(cur_context)
        # Iterate over the current context instead of the
        # argument context, which may have selevel.

        (is_special_se, sp_context) = self.is_special_selinux_path(path)
        if is_special_se:
            new_context = sp_context
        else:
            for i in range(len(cur_context)):
                if len(context) > i:
                    if context[i] is not None and context[i] != cur_context[i]:
                        new_context[i] = context[i]
                    elif context[i] is None:
                        new_context[i] = cur_context[i]

        if cur_context != new_context:
            if diff is not None:
                if 'before' not in diff:
                    diff['before'] = {}
                diff['before']['secontext'] = cur_context
                if 'after' not in diff:
                    diff['after'] = {}
                diff['after']['secontext'] = new_context

            try:
                if self.check_mode:
                    return True
                rc = selinux.lsetfilecon(to_native(path), ':'.join(new_context))
            except OSError as e:
                self.fail_json(path=path, msg='invalid selinux context: %s' % to_native(e),
                               new_context=new_context, cur_context=cur_context, input_was=context)
            if rc != 0:
                self.fail_json(path=path, msg='set selinux context failed')
            changed = True
        return changed

    def set_owner_if_different(self, path, owner, changed, diff=None, expand=True):
        b_path = to_bytes(path, errors='surrogate_or_strict')
        if expand:
            b_path = os.path.expanduser(os.path.expandvars(b_path))
        if owner is None:
            return changed
        orig_uid, orig_gid = self.user_and_group(b_path, expand)
        try:
            uid = int(owner)
        except ValueError:
            try:
                uid = pwd.getpwnam(owner).pw_uid
            except KeyError:
                path = to_text(b_path)
                self.fail_json(path=path, msg='chown failed: failed to look up user %s' % owner)

        if orig_uid != uid:
            if diff is not None:
                if 'before' not in diff:
                    diff['before'] = {}
                diff['before']['owner'] = orig_uid
                if 'after' not in diff:
                    diff['after'] = {}
                diff['after']['owner'] = uid

            if self.check_mode:
                return True
            try:
                os.lchown(b_path, uid, -1)
            except (IOError, OSError) as e:
                path = to_text(b_path)
                self.fail_json(path=path, msg='chown failed: %s' % (to_text(e)))
            changed = True
        return changed

    def set_group_if_different(self, path, group, changed, diff=None, expand=True):
        b_path = to_bytes(path, errors='surrogate_or_strict')
        if expand:
            b_path = os.path.expanduser(os.path.expandvars(b_path))
        if group is None:
            return changed
        orig_uid, orig_gid = self.user_and_group(b_path, expand)
        try:
            gid = int(group)
        except ValueError:
            try:
                gid = grp.getgrnam(group).gr_gid
            except KeyError:
                path = to_text(b_path)
                self.fail_json(path=path, msg='chgrp failed: failed to look up group %s' % group)

        if orig_gid != gid:
            if diff is not None:
                if 'before' not in diff:
                    diff['before'] = {}
                diff['before']['group'] = orig_gid
                if 'after' not in diff:
                    diff['after'] = {}
                diff['after']['group'] = gid

            if self.check_mode:
                return True
            try:
                os.lchown(b_path, -1, gid)
            except OSError:
                path = to_text(b_path)
                self.fail_json(path=path, msg='chgrp failed')
            changed = True
        return changed

    def set_mode_if_different(self, path, mode, changed, diff=None, expand=True):
        b_path = to_bytes(path, errors='surrogate_or_strict')
        if expand:
            b_path = os.path.expanduser(os.path.expandvars(b_path))
        path_stat = os.lstat(b_path)

        if mode is None:
            return changed

        if not isinstance(mode, int):
            try:
                mode = int(mode, 8)
            except Exception:
                try:
                    mode = self._symbolic_mode_to_octal(path_stat, mode)
                except Exception as e:
                    path = to_text(b_path)
                    self.fail_json(path=path,
                                   msg="mode must be in octal or symbolic form",
                                   details=to_native(e))

                if mode != stat.S_IMODE(mode):
                    # prevent mode from having extra info orbeing invalid long number
                    path = to_text(b_path)
                    self.fail_json(path=path, msg="Invalid mode supplied, only permission info is allowed", details=mode)

        prev_mode = stat.S_IMODE(path_stat.st_mode)

        prev_mode = stat.S_IMODE(path_stat.st_mode)

        if prev_mode != mode:

            if diff is not None:
                if 'before' not in diff:
                    diff['before'] = {}
                diff['before']['mode'] = '0%03o' % prev_mode
                if 'after' not in diff:
                    diff['after'] = {}
                diff['after']['mode'] = '0%03o' % mode

            if self.check_mode:
                return True
            # FIXME: comparison against string above will cause this to be executed
            # every time
            try:
                if hasattr(os, 'lchmod'):
                    os.lchmod(b_path, mode)
                else:
                    if not os.path.islink(b_path):
                        os.chmod(b_path, mode)
                    else:
                        # Attempt to set the perms of the symlink but be
                        # careful not to change the perms of the underlying
                        # file while trying
                        underlying_stat = os.stat(b_path)
                        os.chmod(b_path, mode)
                        new_underlying_stat = os.stat(b_path)
                        if underlying_stat.st_mode != new_underlying_stat.st_mode:
                            os.chmod(b_path, stat.S_IMODE(underlying_stat.st_mode))
            except OSError as e:
                if os.path.islink(b_path) and e.errno == errno.EPERM:  # Can't set mode on symbolic links
                    pass
                elif e.errno in (errno.ENOENT, errno.ELOOP):  # Can't set mode on broken symbolic links
                    pass
                else:
                    raise
            except Exception as e:
                path = to_text(b_path)
                self.fail_json(path=path, msg='chmod failed', details=to_native(e),
                               exception=traceback.format_exc())

            path_stat = os.lstat(b_path)
            new_mode = stat.S_IMODE(path_stat.st_mode)

            if new_mode != prev_mode:
                changed = True
        return changed

    def set_attributes_if_different(self, path, attributes, changed, diff=None, expand=True):

        if attributes is None:
            return changed

        b_path = to_bytes(path, errors='surrogate_or_strict')
        if expand:
            b_path = os.path.expanduser(os.path.expandvars(b_path))

        existing = self.get_file_attributes(b_path)

        if existing.get('attr_flags', '') != attributes:
            attrcmd = self.get_bin_path('chattr')
            if attrcmd:
                attrcmd = [attrcmd, '=%s' % attributes, b_path]
                changed = True

                if diff is not None:
                    if 'before' not in diff:
                        diff['before'] = {}
                    diff['before']['attributes'] = existing.get('attr_flags')
                    if 'after' not in diff:
                        diff['after'] = {}
                    diff['after']['attributes'] = attributes

                if not self.check_mode:
                    try:
                        rc, out, err = self.run_command(attrcmd)
                        if rc != 0 or err:
                            raise Exception("Error while setting attributes: %s" % (out + err))
                    except Exception as e:
                        self.fail_json(path=to_text(b_path), msg='chattr failed',
                                       details=to_native(e), exception=traceback.format_exc())
        return changed

    def get_file_attributes(self, path):
        output = {}
        attrcmd = self.get_bin_path('lsattr', False)
        if attrcmd:
            attrcmd = [attrcmd, '-vd', path]
            try:
                rc, out, err = self.run_command(attrcmd)
                if rc == 0:
                    res = out.split()
                    output['attr_flags'] = res[1].replace('-', '').strip()
                    output['version'] = res[0].strip()
                    output['attributes'] = format_attributes(output['attr_flags'])
            except Exception:
                pass
        return output

    @classmethod
    def _symbolic_mode_to_octal(cls, path_stat, symbolic_mode):
        """
        This enables symbolic chmod string parsing as stated in the chmod man-page

        This includes things like: "u=rw-x+X,g=r-x+X,o=r-x+X"
        """

        new_mode = stat.S_IMODE(path_stat.st_mode)

        # Now parse all symbolic modes
        for mode in symbolic_mode.split(','):
            # Per single mode. This always contains a '+', '-' or '='
            # Split it on that
            permlist = MODE_OPERATOR_RE.split(mode)

            # And find all the operators
            opers = MODE_OPERATOR_RE.findall(mode)

            # The user(s) where it's all about is the first element in the
            # 'permlist' list. Take that and remove it from the list.
            # An empty user or 'a' means 'all'.
            users = permlist.pop(0)
            use_umask = (users == '')
            if users == 'a' or users == '':
                users = 'ugo'

            # Check if there are illegal characters in the user list
            # They can end up in 'users' because they are not split
            if USERS_RE.match(users):
                raise ValueError("bad symbolic permission for mode: %s" % mode)

            # Now we have two list of equal length, one contains the requested
            # permissions and one with the corresponding operators.
            for idx, perms in enumerate(permlist):
                # Check if there are illegal characters in the permissions
                if PERMS_RE.match(perms):
                    raise ValueError("bad symbolic permission for mode: %s" % mode)

                for user in users:
                    mode_to_apply = cls._get_octal_mode_from_symbolic_perms(path_stat, user, perms, use_umask)
                    new_mode = cls._apply_operation_to_mode(user, opers[idx], mode_to_apply, new_mode)

        return new_mode

    @staticmethod
    def _apply_operation_to_mode(user, operator, mode_to_apply, current_mode):
        if operator == '=':
            if user == 'u':
                mask = stat.S_IRWXU | stat.S_ISUID
            elif user == 'g':
                mask = stat.S_IRWXG | stat.S_ISGID
            elif user == 'o':
                mask = stat.S_IRWXO | stat.S_ISVTX

            # mask out u, g, or o permissions from current_mode and apply new permissions
            inverse_mask = mask ^ PERM_BITS
            new_mode = (current_mode & inverse_mask) | mode_to_apply
        elif operator == '+':
            new_mode = current_mode | mode_to_apply
        elif operator == '-':
            new_mode = current_mode - (current_mode & mode_to_apply)
        return new_mode

    @staticmethod
    def _get_octal_mode_from_symbolic_perms(path_stat, user, perms, use_umask):
        prev_mode = stat.S_IMODE(path_stat.st_mode)

        is_directory = stat.S_ISDIR(path_stat.st_mode)
        has_x_permissions = (prev_mode & EXEC_PERM_BITS) > 0
        apply_X_permission = is_directory or has_x_permissions

        # Get the umask, if the 'user' part is empty, the effect is as if (a) were
        # given, but bits that are set in the umask are not affected.
        # We also need the "reversed umask" for masking
        umask = os.umask(0)
        os.umask(umask)
        rev_umask = umask ^ PERM_BITS

        # Permission bits constants documented at:
        # http://docs.python.org/2/library/stat.html#stat.S_ISUID
        if apply_X_permission:
            X_perms = {
                'u': {'X': stat.S_IXUSR},
                'g': {'X': stat.S_IXGRP},
                'o': {'X': stat.S_IXOTH},
            }
        else:
            X_perms = {
                'u': {'X': 0},
                'g': {'X': 0},
                'o': {'X': 0},
            }

        user_perms_to_modes = {
            'u': {
                'r': rev_umask & stat.S_IRUSR if use_umask else stat.S_IRUSR,
                'w': rev_umask & stat.S_IWUSR if use_umask else stat.S_IWUSR,
                'x': rev_umask & stat.S_IXUSR if use_umask else stat.S_IXUSR,
                's': stat.S_ISUID,
                't': 0,
                'u': prev_mode & stat.S_IRWXU,
                'g': (prev_mode & stat.S_IRWXG) << 3,
                'o': (prev_mode & stat.S_IRWXO) << 6},
            'g': {
                'r': rev_umask & stat.S_IRGRP if use_umask else stat.S_IRGRP,
                'w': rev_umask & stat.S_IWGRP if use_umask else stat.S_IWGRP,
                'x': rev_umask & stat.S_IXGRP if use_umask else stat.S_IXGRP,
                's': stat.S_ISGID,
                't': 0,
                'u': (prev_mode & stat.S_IRWXU) >> 3,
                'g': prev_mode & stat.S_IRWXG,
                'o': (prev_mode & stat.S_IRWXO) << 3},
            'o': {
                'r': rev_umask & stat.S_IROTH if use_umask else stat.S_IROTH,
                'w': rev_umask & stat.S_IWOTH if use_umask else stat.S_IWOTH,
                'x': rev_umask & stat.S_IXOTH if use_umask else stat.S_IXOTH,
                's': 0,
                't': stat.S_ISVTX,
                'u': (prev_mode & stat.S_IRWXU) >> 6,
                'g': (prev_mode & stat.S_IRWXG) >> 3,
                'o': prev_mode & stat.S_IRWXO},
        }

        # Insert X_perms into user_perms_to_modes
        for key, value in X_perms.items():
            user_perms_to_modes[key].update(value)

        def or_reduce(mode, perm):
            return mode | user_perms_to_modes[user][perm]

        return reduce(or_reduce, perms, 0)

    def set_fs_attributes_if_different(self, file_args, changed, diff=None, expand=True):
        # set modes owners and context as needed
        changed = self.set_context_if_different(
            file_args['path'], file_args['secontext'], changed, diff
        )
        changed = self.set_owner_if_different(
            file_args['path'], file_args['owner'], changed, diff, expand
        )
        changed = self.set_group_if_different(
            file_args['path'], file_args['group'], changed, diff, expand
        )
        changed = self.set_mode_if_different(
            file_args['path'], file_args['mode'], changed, diff, expand
        )
        changed = self.set_attributes_if_different(
            file_args['path'], file_args['attributes'], changed, diff, expand
        )
        return changed

    def set_directory_attributes_if_different(self, file_args, changed, diff=None, expand=True):
        return self.set_fs_attributes_if_different(file_args, changed, diff, expand)

    def set_file_attributes_if_different(self, file_args, changed, diff=None, expand=True):
        return self.set_fs_attributes_if_different(file_args, changed, diff, expand)

    def backup_local(self, fn):
        '''make a date-marked backup of the specified file, return True or False on success or failure'''

        backupdest = ''
        if os.path.exists(fn):
            # backups named basename.PID.YYYY-MM-DD@HH:MM:SS~
            ext = time.strftime("%Y-%m-%d@%H:%M:%S~", time.localtime(time.time()))
            backupdest = '%s.%s.%s' % (fn, os.getpid(), ext)

            try:
                self.preserved_copy(fn, backupdest)
            except (shutil.Error, IOError) as e:
                self.fail_json(msg='Could not make backup of %s to %s: %s' % (fn, backupdest, to_native(e)))

        return backupdest

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

    def atomic_move(self, src, dest, unsafe_writes=False):
        '''atomically move src to dest, copying attributes from dest, returns true on success
        it uses os.rename to ensure this as it is an atomic operation, rest of the function is
        to work around limitations, corner cases and ensure selinux context is saved if possible'''
        context = None
        dest_stat = None
        b_src = to_bytes(src, errors='surrogate_or_strict')
        b_dest = to_bytes(dest, errors='surrogate_or_strict')
        if os.path.exists(b_dest):
            try:
                dest_stat = os.stat(b_dest)

                # copy mode and ownership
                os.chmod(b_src, dest_stat.st_mode & PERM_BITS)
                os.chown(b_src, dest_stat.st_uid, dest_stat.st_gid)

                # try to copy flags if possible
                if hasattr(os, 'chflags') and hasattr(dest_stat, 'st_flags'):
                    try:
                        os.chflags(b_src, dest_stat.st_flags)
                    except OSError as e:
                        for err in 'EOPNOTSUPP', 'ENOTSUP':
                            if hasattr(errno, err) and e.errno == getattr(errno, err):
                                break
                        else:
                            raise
            except OSError as e:
                if e.errno != errno.EPERM:
                    raise
            if self.selinux_enabled():
                context = self.selinux_context(dest)
        else:
            if self.selinux_enabled():
                context = self.selinux_default_context(dest)

        creating = not os.path.exists(b_dest)

        try:
            # Optimistically try a rename, solves some corner cases and can avoid useless work, throws exception if not atomic.
            os.rename(b_src, b_dest)
        except (IOError, OSError) as e:
            if e.errno not in [errno.EPERM, errno.EXDEV, errno.EACCES, errno.ETXTBSY, errno.EBUSY]:
                # only try workarounds for errno 18 (cross device), 1 (not permitted),  13 (permission denied)
                # and 26 (text file busy) which happens on vagrant synced folders and other 'exotic' non posix file systems
                self.fail_json(msg='Could not replace file: %s to %s: %s' % (src, dest, to_native(e)),
                               exception=traceback.format_exc())
            else:
                b_dest_dir = os.path.dirname(b_dest)
                # Use bytes here.  In the shippable CI, this fails with
                # a UnicodeError with surrogateescape'd strings for an unknown
                # reason (doesn't happen in a local Ubuntu16.04 VM)
                native_dest_dir = b_dest_dir
                native_suffix = os.path.basename(b_dest)
                native_prefix = b('.ansible_tmp')
                error_msg = None
                tmp_dest_name = None
                try:
                    tmp_dest_fd, tmp_dest_name = tempfile.mkstemp(prefix=native_prefix, dir=native_dest_dir, suffix=native_suffix)
                except (OSError, IOError) as e:
                    error_msg = 'The destination directory (%s) is not writable by the current user. Error was: %s' % (os.path.dirname(dest), to_native(e))
                except TypeError:
                    # We expect that this is happening because python3.4.x and
                    # below can't handle byte strings in mkstemp().  Traceback
                    # would end in something like:
                    #     file = _os.path.join(dir, pre + name + suf)
                    # TypeError: can't concat bytes to str
                    error_msg = ('Failed creating temp file for atomic move.  This usually happens when using Python3 less than Python3.5. '
                                 'Please use Python2.x or Python3.5 or greater.')
                finally:
                    if error_msg:
                        if unsafe_writes:
                            self._unsafe_writes(b_src, b_dest)
                        else:
                            self.fail_json(msg=error_msg, exception=traceback.format_exc())

                if tmp_dest_name:
                    b_tmp_dest_name = to_bytes(tmp_dest_name, errors='surrogate_or_strict')

                    try:
                        try:
                            # close tmp file handle before file operations to prevent text file busy errors on vboxfs synced folders (windows host)
                            os.close(tmp_dest_fd)
                            # leaves tmp file behind when sudo and not root
                            try:
                                shutil.move(b_src, b_tmp_dest_name)
                            except OSError:
                                # cleanup will happen by 'rm' of tempdir
                                # copy2 will preserve some metadata
                                shutil.copy2(b_src, b_tmp_dest_name)

                            if self.selinux_enabled():
                                self.set_context_if_different(
                                    b_tmp_dest_name, context, False)
                            try:
                                tmp_stat = os.stat(b_tmp_dest_name)
                                if dest_stat and (tmp_stat.st_uid != dest_stat.st_uid or tmp_stat.st_gid != dest_stat.st_gid):
                                    os.chown(b_tmp_dest_name, dest_stat.st_uid, dest_stat.st_gid)
                            except OSError as e:
                                if e.errno != errno.EPERM:
                                    raise
                            try:
                                os.rename(b_tmp_dest_name, b_dest)
                            except (shutil.Error, OSError, IOError) as e:
                                if unsafe_writes and e.errno == errno.EBUSY:
                                    self._unsafe_writes(b_tmp_dest_name, b_dest)
                                else:
                                    self.fail_json(msg='Unable to rename file: %s to %s: %s' % (src, dest, to_native(e)),
                                                   exception=traceback.format_exc())
                        except (shutil.Error, OSError, IOError) as e:
                            self.fail_json(msg='Failed to replace file: %s to %s: %s' % (src, dest, to_native(e)),
                                           exception=traceback.format_exc())
                    finally:
                        self.cleanup(b_tmp_dest_name)

        if creating:
            # make sure the file has the correct permissions
            # based on the current value of umask
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(b_dest, DEFAULT_PERM & ~umask)
            try:
                os.chown(b_dest, os.geteuid(), os.getegid())
            except OSError:
                # We're okay with trying our best here.  If the user is not
                # root (or old Unices) they won't be able to chown.
                pass

        if self.selinux_enabled():
            # rename might not preserve context
            self.set_context_if_different(dest, context, False)

    def _unsafe_writes(self, src, dest):
        # sadly there are some situations where we cannot ensure atomicity, but only if
        # the user insists and we get the appropriate error we update the file unsafely
        try:
            out_dest = in_src = None
            try:
                out_dest = open(dest, 'wb')
                in_src = open(src, 'rb')
                shutil.copyfileobj(in_src, out_dest)
            finally:  # assuring closed files in 2.4 compatible way
                if out_dest:
                    out_dest.close()
                if in_src:
                    in_src.close()
        except (shutil.Error, OSError, IOError) as e:
            self.fail_json(msg='Could not write data to file (%s) from (%s): %s' % (dest, src, to_native(e)),
                           exception=traceback.format_exc())

    def append_to_file(self, filename, str):
        filename = os.path.expandvars(os.path.expanduser(filename))
        fh = open(filename, 'a')
        fh.write(str)
        fh.close()


def format_attributes(attributes):
    attribute_list = []
    for attr in attributes:
        if attr in FILE_ATTRIBUTES:
            attribute_list.append(FILE_ATTRIBUTES[attr])
    return attribute_list


def get_flags_from_attributes(attributes):
    flags = []
    for key, attr in FILE_ATTRIBUTES.items():
        if attr in attributes:
            flags.append(key)
    return ''.join(flags)
