# -*- coding: utf-8 -*-

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

import os
import pwd
import sys

from ansible import constants as C
from ansible import context
from ansible.errors import AnsibleError
from ansible.module_utils.six import iteritems
from ansible.module_utils.parsing.convert_bool import boolean
from ansible.playbook.attribute import FieldAttribute
from ansible.playbook.base import Base
from ansible.plugins import get_plugin_class
from ansible.utils.display import Display
from ansible.plugins.loader import become_loader, get_shell_plugin
from ansible.utils.ssh_functions import check_for_controlpersist


display = Display()


__all__ = ['PlayContext']


TASK_ATTRIBUTE_OVERRIDES = (
    'become',
    'become_user',
    'become_pass',
    'become_method',
    'become_flags',
    'connection',
    'docker_extra_args',  # TODO: remove
    'delegate_to',
    'no_log',
    'remote_user',
)

RESET_VARS = (
    'ansible_connection',
    'ansible_user',
    'ansible_host',
    'ansible_port',

    # TODO: ???
    'ansible_docker_extra_args',
    'ansible_ssh_host',
    'ansible_ssh_pass',
    'ansible_ssh_port',
    'ansible_ssh_user',
    'ansible_ssh_private_key_file',
    'ansible_ssh_pipelining',
    'ansible_ssh_executable',
)

OPTION_FLAGS = ('connection', 'remote_user', 'private_key_file', 'verbosity', 'force_handlers', 'step', 'start_at_task', 'diff',
                'ssh_common_args', 'docker_extra_args', 'sftp_extra_args', 'scp_extra_args', 'ssh_extra_args')


class PlayContext(Base):

    '''
    This class is used to consolidate the connection information for
    hosts in a play and child tasks, where the task may override some
    connection/authentication information.
    '''

    # base
    _module_compression = FieldAttribute(isa='string', default=C.DEFAULT_MODULE_COMPRESSION)
    _shell = FieldAttribute(isa='string')
    _executable = FieldAttribute(isa='string', default=C.DEFAULT_EXECUTABLE)

    # connection fields, some are inherited from Base:
    # (connection, port, remote_user, environment, no_log)
    _remote_addr = FieldAttribute(isa='string')
    _password = FieldAttribute(isa='string')
    _timeout = FieldAttribute(isa='int', default=C.DEFAULT_TIMEOUT)
    _connection_user = FieldAttribute(isa='string')
    _private_key_file = FieldAttribute(isa='string', default=C.DEFAULT_PRIVATE_KEY_FILE)
    _pipelining = FieldAttribute(isa='bool', default=C.ANSIBLE_PIPELINING)

    # networking modules
    _network_os = FieldAttribute(isa='string')

    # docker FIXME: remove these
    _docker_extra_args = FieldAttribute(isa='string')

    # ssh # FIXME: remove these
    _ssh_executable = FieldAttribute(isa='string', default=C.ANSIBLE_SSH_EXECUTABLE)
    _ssh_args = FieldAttribute(isa='string', default=C.ANSIBLE_SSH_ARGS)
    _ssh_common_args = FieldAttribute(isa='string')
    _sftp_extra_args = FieldAttribute(isa='string')
    _scp_extra_args = FieldAttribute(isa='string')
    _ssh_extra_args = FieldAttribute(isa='string')
    _ssh_transfer_method = FieldAttribute(isa='string', default=C.DEFAULT_SSH_TRANSFER_METHOD)

    # ???
    _connection_lockfd = FieldAttribute(isa='int')

    # privilege escalation fields
    _become = FieldAttribute(isa='bool')
    _become_method = FieldAttribute(isa='string')
    _become_user = FieldAttribute(isa='string')
    _become_pass = FieldAttribute(isa='string')
    _become_exe = FieldAttribute(isa='string', default=C.DEFAULT_BECOME_EXE)
    _become_flags = FieldAttribute(isa='string', default=C.DEFAULT_BECOME_FLAGS)
    _prompt = FieldAttribute(isa='string')

    # DEPRECATED: backwards compatibility fields for sudo/su
    _sudo_exe = FieldAttribute(isa='string')
    _sudo_flags = FieldAttribute(isa='string')
    _sudo_pass = FieldAttribute(isa='string')
    _su_exe = FieldAttribute(isa='string')
    _su_flags = FieldAttribute(isa='string')
    _su_pass = FieldAttribute(isa='string')

    # general flags
    _verbosity = FieldAttribute(isa='int', default=0)
    _only_tags = FieldAttribute(isa='set', default=set)
    _skip_tags = FieldAttribute(isa='set', default=set)
    _force_handlers = FieldAttribute(isa='bool', default=False)
    _start_at_task = FieldAttribute(isa='string')
    _step = FieldAttribute(isa='bool', default=False)

    # Fact gathering settings
    # ## DEPRECATED ##  use 'play'
    _gather_subset = FieldAttribute(isa='string', default=C.DEFAULT_GATHER_SUBSET)
    _gather_timeout = FieldAttribute(isa='string', default=C.DEFAULT_GATHER_TIMEOUT)
    _fact_path = FieldAttribute(isa='string', default=C.DEFAULT_FACT_PATH)

    def __init__(self, play=None, passwords=None, connection_lockfd=None):

        super(PlayContext, self).__init__()

        if passwords is None:
            passwords = {}

        self.password = passwords.get('conn_pass', '')
        self.become_pass = passwords.get('become_pass', '')

        self.prompt = ''
        self.success_key = ''

        # a file descriptor to be used during locking operations
        self.connection_lockfd = connection_lockfd

        # set options before play to allow play to override them
        if context.CLIARGS:
            self.set_options()

    def set_options_from_plugin(self, plugin):
        # generic derived from connection plugin, temporary for backwards compat, in the end we should not set play_context properties

        # get options for plugins
        options = C.config.get_configuration_definitions(get_plugin_class(plugin), plugin._load_name)
        for option in options:
            if option:
                flag = options[option].get('name')
                if flag:
                    setattr(self, flag, self.connection.get_option(flag))

        # TODO: made irrelavent by above
        # get ssh options
        # for flag in ('ssh_common_args', 'docker_extra_args', 'sftp_extra_args', 'scp_extra_args', 'ssh_extra_args'):
        #     setattr(self, flag, getattr(options, flag, ''))

    def set_options(self):
        '''
        Configures this connection information instance with data from
        options specified by the user on the command line. These have a
        lower precedence than those set on the play or host.
        '''

        # privilege escalation
        self.become = context.CLIARGS['become']
        self.become_method = context.CLIARGS['become_method']
        self.become_user = context.CLIARGS['become_user']

        self.check_mode = boolean(context.CLIARGS['check'], strict=False)
        self.diff = boolean(context.CLIARGS['diff'], strict=False)

        #  general flags (should we move out?)
        #  should only be 'non plugin' flags
        for flag in OPTION_FLAGS:
            attribute = context.CLIARGS.get(flag, False)
            if attribute:
                setattr(self, flag, attribute)

        if context.CLIARGS.get('timeout', False):
            self.timeout = context.CLIARGS['timeout']

        # get the tag info from options. We check to see if the options have
        # the attribute, as it is not always added via the CLI
        if context.CLIARGS.get('tags', False):
            self.only_tags.update(context.CLIARGS['tags'])

        if len(self.only_tags) == 0:
            self.only_tags = set(['all'])

        if context.CLIARGS.get('skip_tags', False):
            self.skip_tags.update(context.CLIARGS['skip_tags'])

    def set_task_and_variable_override(self, task, variables, templar):
        '''
        Sets attributes from the task if they are set, which will override
        those from the play.

        :arg task: the task object with the parameters that were set on it
        :arg variables: variables from inventory
        :arg templar: templar instance if templating variables is needed
        '''

        new_info = self.copy()

        # loop through a subset of attributes on the task object and set
        # connection fields based on their values
        for attr in TASK_ATTRIBUTE_OVERRIDES:
            if hasattr(task, attr):
                attr_val = getattr(task, attr)
                if attr_val is not None:
                    setattr(new_info, attr, attr_val)

        # next, use the MAGIC_VARIABLE_MAPPING dictionary to update this
        # connection info object with 'magic' variables from the variable list.
        # If the value 'ansible_delegated_vars' is in the variables, it means
        # we have a delegated-to host, so we check there first before looking
        # at the variables in general
        if task.delegate_to is not None:
            # In the case of a loop, the delegated_to host may have been
            # templated based on the loop variable, so we try and locate
            # the host name in the delegated variable dictionary here
            delegated_host_name = templar.template(task.delegate_to)
            delegated_vars = variables.get('ansible_delegated_vars', dict()).get(delegated_host_name, dict())

            delegated_transport = C.DEFAULT_TRANSPORT
            for transport_var in C.MAGIC_VARIABLE_MAPPING.get('connection'):
                if transport_var in delegated_vars:
                    delegated_transport = delegated_vars[transport_var]
                    break

            # make sure this delegated_to host has something set for its remote
            # address, otherwise we default to connecting to it by name. This
            # may happen when users put an IP entry into their inventory, or if
            # they rely on DNS for a non-inventory hostname
            for address_var in ('ansible_%s_host' % delegated_transport,) + C.MAGIC_VARIABLE_MAPPING.get('remote_addr'):
                if address_var in delegated_vars:
                    break
            else:
                display.debug("no remote address found for delegated host %s\nusing its name, so success depends on DNS resolution" % delegated_host_name)
                delegated_vars['ansible_host'] = delegated_host_name

            # reset the port back to the default if none was specified, to prevent
            # the delegated host from inheriting the original host's setting
            for port_var in ('ansible_%s_port' % delegated_transport,) + C.MAGIC_VARIABLE_MAPPING.get('port'):
                if port_var in delegated_vars:
                    break
            else:
                if delegated_transport == 'winrm':
                    delegated_vars['ansible_port'] = 5986
                else:
                    delegated_vars['ansible_port'] = C.DEFAULT_REMOTE_PORT

            # and likewise for the remote user
            for user_var in ('ansible_%s_user' % delegated_transport,) + C.MAGIC_VARIABLE_MAPPING.get('remote_user'):
                if user_var in delegated_vars and delegated_vars[user_var]:
                    break
            else:
                delegated_vars['ansible_user'] = task.remote_user or self.remote_user
        else:
            delegated_vars = dict()

            # setup shell
            for exe_var in C.MAGIC_VARIABLE_MAPPING.get('executable'):
                if exe_var in variables:
                    setattr(new_info, 'executable', variables.get(exe_var))

        attrs_considered = []
        for (attr, variable_names) in iteritems(C.MAGIC_VARIABLE_MAPPING):
            for variable_name in variable_names:
                if attr in attrs_considered:
                    continue
                # if delegation task ONLY use delegated host vars, avoid delegated FOR host vars
                if task.delegate_to is not None:
                    if isinstance(delegated_vars, dict) and variable_name in delegated_vars:
                        setattr(new_info, attr, delegated_vars[variable_name])
                        attrs_considered.append(attr)
                elif variable_name in variables:
                    setattr(new_info, attr, variables[variable_name])
                    attrs_considered.append(attr)
                # no else, as no other vars should be considered

        # become legacy updates -- from commandline
        if not new_info.become_pass:
            if new_info.become_method == 'sudo' and new_info.sudo_pass:
                new_info.become_pass = new_info.sudo_pass
            elif new_info.become_method == 'su' and new_info.su_pass:
                new_info.become_pass = new_info.su_pass

        # become legacy updates -- from inventory file (inventory overrides
        # commandline)
        for become_pass_name in C.MAGIC_VARIABLE_MAPPING.get('become_pass'):
            if become_pass_name in variables:
                break
        else:  # This is a for-else
            if new_info.become_method == 'sudo':
                for sudo_pass_name in C.MAGIC_VARIABLE_MAPPING.get('sudo_pass'):
                    if sudo_pass_name in variables:
                        setattr(new_info, 'become_pass', variables[sudo_pass_name])
                        break
            elif new_info.become_method == 'su':
                for su_pass_name in C.MAGIC_VARIABLE_MAPPING.get('su_pass'):
                    if su_pass_name in variables:
                        setattr(new_info, 'become_pass', variables[su_pass_name])
                        break

        # make sure we get port defaults if needed
        if new_info.port is None and C.DEFAULT_REMOTE_PORT is not None:
            new_info.port = int(C.DEFAULT_REMOTE_PORT)

        # special overrides for the connection setting
        if len(delegated_vars) > 0:
            # in the event that we were using local before make sure to reset the
            # connection type to the default transport for the delegated-to host,
            # if not otherwise specified
            for connection_type in C.MAGIC_VARIABLE_MAPPING.get('connection'):
                if connection_type in delegated_vars:
                    break
            else:
                remote_addr_local = new_info.remote_addr in C.LOCALHOST
                inv_hostname_local = delegated_vars.get('inventory_hostname') in C.LOCALHOST
                if remote_addr_local and inv_hostname_local:
                    setattr(new_info, 'connection', 'local')
                elif getattr(new_info, 'connection', None) == 'local' and (not remote_addr_local or not inv_hostname_local):
                    setattr(new_info, 'connection', C.DEFAULT_TRANSPORT)

        # if the final connection type is local, reset the remote_user value to that of the currently logged in user
        # this ensures any become settings are obeyed correctly
        # we store original in 'connection_user' for use of network/other modules that fallback to it as login user
        # connection_user to be deprecated once connection=local is removed for
        # network modules
        if new_info.connection == 'local':
            if not new_info.connection_user:
                new_info.connection_user = new_info.remote_user
            new_info.remote_user = pwd.getpwuid(os.getuid()).pw_name

        # set no_log to default if it was not previously set
        if new_info.no_log is None:
            new_info.no_log = C.DEFAULT_NO_LOG

        if task.check_mode is not None:
            new_info.check_mode = task.check_mode

        if task.diff is not None:
            new_info.diff = task.diff

        return new_info

    def make_become_cmd(self, cmd, executable=None):
        """ helper function to create privilege escalation commands """
        # DEPRECATED

        if cmd and self.become:

            # load/call become plugins here
            plugin = become_loader.get(self.become_method)
            if plugin:

                options = {'become_exe': self.become_exe or getattr(self, '%s_exe' % self.become_method, self.become_method) or self.become_method,
                           'become_flags': self.become_flags or getattr(self, '%s_flags' % self.become_method, '') or '',
                           'become_user': self.become_user,
                           'become_pass': self.become_pass}
                plugin.set_options(direct=options)

                if not executable:
                    executable = self.executable

                shell = get_shell_plugin(executable=executable)
                cmd = plugin.build_become_command(cmd, shell)
                # for backwards compat:
                self.prompt = plugin.prompt
            else:
                raise AnsibleError("Privilege escalation method not found: %s" % self.become_method)

        return cmd

    def update_vars(self, variables):
        '''
        Adds 'magic' variables relating to connections to the variable dictionary provided.
        In case users need to access from the play, this is a legacy from runner.
        '''

        for prop, var_list in C.MAGIC_VARIABLE_MAPPING.items():
            try:
                if 'become' in prop:
                    continue

                var_val = getattr(self, prop)
                for var_opt in var_list:
                    if var_opt not in variables and var_val is not None:
                        variables[var_opt] = var_val
            except AttributeError:
                continue

    def _get_attr_connection(self):
        ''' connections are special, this takes care of responding correctly '''
        conn_type = None
        if self._attributes['connection'] == 'smart':
            conn_type = 'ssh'
            if sys.platform.startswith('darwin') and self.password:
                # due to a current bug in sshpass on OSX, which can trigger
                # a kernel panic even for non-privileged users, we revert to
                # paramiko on that OS when a SSH password is specified
                conn_type = "paramiko"
            else:
                # see if SSH can support ControlPersist if not use paramiko
                if not check_for_controlpersist(self.ssh_executable):
                    conn_type = "paramiko"

        # if someone did `connection: persistent`, default it to using a persistent paramiko connection to avoid problems
        elif self._attributes['connection'] == 'persistent':
            conn_type = 'paramiko'

        if conn_type:
            self.connection = conn_type

        return self._attributes['connection']
