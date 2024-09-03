=============================================
ansible-core 2.16 "All My Love" Release Notes
=============================================

.. contents:: Topics


v2.16.11rc1
===========

Release Summary
---------------

| Release Date: 2024-09-03
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Bugfixes
--------

- Fix ``SemanticVersion.parse()`` to store the version string so that ``__repr__`` reports it instead of ``None`` (https://github.com/ansible/ansible/pull/83831).
- Fix an issue where registered variable was not available for templating in ``loop_control.label`` on skipped looped tasks (https://github.com/ansible/ansible/issues/83619)
- Fix for ``meta`` tasks breaking host/fork affinity with ``host_pinned`` strategy (https://github.com/ansible/ansible/issues/83294)
- Fix using the current task's directory for looking up relative paths within roles (https://github.com/ansible/ansible/issues/82695).
- atomic_move - fix using the setgid bit on the parent directory when creating files (https://github.com/ansible/ansible/issues/46742, https://github.com/ansible/ansible/issues/67177).
- connection plugins using the 'extras' option feature would need variables to match the plugin's loaded name, sometimes requiring fqcn, which is not the same as the documented/declared/expected variables. Now we fall back to the 'basename' of the fqcn, but plugin authors can still set the expected value directly.
- csvfile lookup - give an error when no search term is provided using modern config syntax (https://github.com/ansible/ansible/issues/83689).
- include_tasks - Display location when attempting to load a task list where ``include_*`` did not specify any value - https://github.com/ansible/ansible/issues/83874
- module respawn - Address an issue with Python 2 where a respawned module could not parse module args (https://github.com/ansible/ansible/issues/83812)
- powershell - Improve CLIXML decoding to decode all control characters and unicode characters that are encoded as surrogate pairs.
- psrp - Fix bug when attempting to fetch a file path that contains special glob characters like ``[]``
- runtime-metadata sanity test - do not crash on deprecations if ``galaxy.yml`` contains an empty ``version`` field (https://github.com/ansible/ansible/pull/83831).
- ssh - Fix bug when attempting to fetch a file path with characters that should be quoted when using the ``piped`` transfer method

v2.16.10
========

Release Summary
---------------

| Release Date: 2024-08-12
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Minor Changes
-------------

- ansible-test - Improve the error message shown when an unknown ``--remote`` or ``--docker`` option is given.
- ansible-test - Removed the ``vyos/1.1.8`` network remote as it is no longer functional.

Bugfixes
--------

- config, restored the ability to set module compression via a variable
- linear strategy: fix handlers included via ``include_tasks`` handler to be executed in lockstep (https://github.com/ansible/ansible/issues/83019)

v2.16.9
=======

Release Summary
---------------

| Release Date: 2024-07-15
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Bugfixes
--------

- dnf, dnf5 - fix for installing a set of packages by specifying them using a wildcard character (https://github.com/ansible/ansible/issues/83373)
- linear strategy now provides a properly templated task name to the v2_runner_on_started callback event.
- templating hostvars under native jinja will not cause serialization errors anymore.

v2.16.8
=======

Release Summary
---------------

| Release Date: 2024-06-17
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Minor Changes
-------------

- ansible-test - Update ``pypi-test-container`` to version 3.1.0.

Bugfixes
--------

- Fix the task attribute ``resolved_action`` to show the FQCN instead of ``None`` when ``action`` or ``local_action`` is used in the playbook.
- Fix using ``module_defaults`` with ``local_action``/``action`` (https://github.com/ansible/ansible/issues/81905).
- fixed unit test test_borken_cowsay to address mock not been properly applied when existing unix system already have cowsay installed.
- powershell - Implement more robust deletion mechanism for C# code compilation temporary files. This should avoid scenarios where the underlying temporary directory may be temporarily locked by antivirus tools or other IO problems. A failure to delete one of these temporary directories will result in a warning rather than an outright failure.

v2.16.7
=======

Release Summary
---------------

| Release Date: 2024-05-20
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Minor Changes
-------------

- ansible.builtin.user - Remove user not found warning (https://github.com/ansible/ansible/issues/80267)

Bugfixes
--------

- Add a version ceiling constraint for pypsrp to avoid potential breaking changes in the 1.0.0 release.
- Fix NEVRA parsing of package names that include digit(s) in them (https://github.com/ansible/ansible/issues/76463, https://github.com/ansible/ansible/issues/81018)
- Fix handlers not being executed in lockstep using the linear strategy in some cases (https://github.com/ansible/ansible/issues/82307)
- Give the tombstone error for ``include`` pre-fork like other tombstoned action/module plugins.
- Include the task location when a module or action plugin is deprecated (https://github.com/ansible/ansible/issues/82450).
- Mirror the behavior of dnf on the command line when handling NEVRAs with omitted epoch (https://github.com/ansible/ansible/issues/71808)
- ansible-test - Automatically enable the PyPI proxy for the ``centos7`` container to restore the ability to use ``pip`` in that container.
- ansible_managed restored it's 'templatability' by ensuring the possible injection routes are cut off earlier in the process.
- assemble - fixed missing parameter 'content' in _get_diff_data API (https://github.com/ansible/ansible/issues/82359).
- dnf - fix an issue when installing a package by specifying a file it provides could result in installing a different package providing the same file than the package already installed resulting in resolution failure (https://github.com/ansible/ansible/issues/82461)
- uri - update the documentation for follow_redirects.

v2.16.6
=======

Release Summary
---------------

| Release Date: 2024-04-15
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Bugfixes
--------

- Consolidated the list of internal static vars, centralized them as constant and completed from some missing entries.
- Fix check for missing _sub_plugin attribute in older connection plugins (https://github.com/ansible/ansible/pull/82954)
- Fixes permission for cache json file from 600 to 644 (https://github.com/ansible/ansible/issues/82683).
- Slight optimization to hostvars (instantiate template only once per host, vs per call to var).
- allow_duplicates - fix evaluating if the current role allows duplicates instead of using the initial value from the duplicate's cached role.
- ansible-config will now properly template defaults before dumping them.
- ansible-test ansible-doc sanity test - do not remove underscores from plugin names in collections before calling ``ansible-doc`` (https://github.com/ansible/ansible/pull/82574).
- async - Fix bug that stopped running async task in ``--check`` when ``check_mode: False`` was set as a task attribute - https://github.com/ansible/ansible/issues/82811
- blockinfile - when ``create=true`` is used with a filename without path, the module crashed (https://github.com/ansible/ansible/pull/81638).
- dnf - fix an issue when cached RPMs were left in the cache directory even when the keepcache setting was unset (https://github.com/ansible/ansible/issues/81954)
- dnf5 - replace removed API calls
- facts - add a generic detection for VMware in product name.
- fetch - add error message when using ``dest`` with a trailing slash that becomes a local directory - https://github.com/ansible/ansible/issues/82878
- find - do not fail on Permission errors (https://github.com/ansible/ansible/issues/82027).
- unarchive modules now uses zipinfo options without relying on implementation defaults, making it more compatible with all OS/distributions.
- winrm - Do not raise another exception during cleanup when a task is timed out - https://github.com/ansible/ansible/issues/81095

v2.16.5
=======

Release Summary
---------------

| Release Date: 2024-03-25
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Minor Changes
-------------

- ansible-test - Add a work-around for permission denied errors when using ``pytest >= 8`` on multi-user systems with an installed version of ``ansible-test``.

Bugfixes
--------

- Fix an issue when setting a plugin name from an unsafe source resulted in ``ValueError: unmarshallable object`` (https://github.com/ansible/ansible/issues/82708)
- Harden python templates for respawn and ansiballz around str literal quoting
- ansible-test - The ``libexpat`` package is automatically upgraded during remote bootstrapping to maintain compatibility with newer Python packages.
- template - Fix error when templating an unsafe string which corresponds to an invalid type in Python (https://github.com/ansible/ansible/issues/82600).
- winrm - does not hang when attempting to get process output when stdin write failed

v2.16.4
=======

Release Summary
---------------

| Release Date: 2024-02-26
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Bugfixes
--------

- Fix loading vars_plugins in roles (https://github.com/ansible/ansible/issues/82239).
- expect - fix argument spec error using timeout=null (https://github.com/ansible/ansible/issues/80982).
- include_vars - fix calculating ``depth`` relative to the root and ensure all files are included (https://github.com/ansible/ansible/issues/80987).
- templating - ensure syntax errors originating from a template being compiled into Python code object result in a failure (https://github.com/ansible/ansible/issues/82606)

v2.16.3
=======

Release Summary
---------------

| Release Date: 2024-01-29
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Security Fixes
--------------

- ANSIBLE_NO_LOG - Address issue where ANSIBLE_NO_LOG was ignored (CVE-2024-0690)

Bugfixes
--------

- Run all handlers with the same ``listen`` topic, even when notified from another handler (https://github.com/ansible/ansible/issues/82363).
- ``ansible-galaxy role import`` - fix using the ``role_name`` in a standalone role's ``galaxy_info`` metadata by disabling automatic removal of the ``ansible-role-`` prefix. This matches the behavior of the Galaxy UI which also no longer implicitly removes the ``ansible-role-`` prefix. Use the ``--role-name`` option or add a ``role_name`` to the ``galaxy_info`` dictionary in the role's ``meta/main.yml`` to use an alternate role name.
- ``ansible-test sanity --test runtime-metadata`` - add ``action_plugin`` as a valid field for modules in the schema (https://github.com/ansible/ansible/pull/82562).
- ansible-config init will now dedupe ini entries from plugins.
- ansible-galaxy role import - exit with 1 when the import fails (https://github.com/ansible/ansible/issues/82175).
- ansible-galaxy role install - fix symlinks (https://github.com/ansible/ansible/issues/82702, https://github.com/ansible/ansible/issues/81965).
- ansible-galaxy role install - normalize tarfile paths and symlinks using ``ansible.utils.path.unfrackpath`` and consider them valid as long as the realpath is in the tarfile's role directory (https://github.com/ansible/ansible/issues/81965).
- delegate_to when set to an empty or undefined variable will now give a proper error.
- dwim functions for lookups should be better at detectging role context even in abscense of tasks/main.
- roles, code cleanup and performance optimization of dependencies, now cached,  and ``public`` setting is now determined once, at role instantiation.
- roles, the ``static`` property is now correctly set, this will fix issues with ``public`` and ``DEFAULT_PRIVATE_ROLE_VARS`` controls on exporting vars.
- unsafe data - Enable directly using ``AnsibleUnsafeText`` with Python ``pathlib`` (https://github.com/ansible/ansible/issues/82414)

v2.16.2
=======

Release Summary
---------------

| Release Date: 2023-12-11
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Bugfixes
--------

- unsafe data - Address an incompatibility when iterating or getting a single index from ``AnsibleUnsafeBytes``
- unsafe data - Address an incompatibility with ``AnsibleUnsafeText`` and ``AnsibleUnsafeBytes`` when pickling with ``protocol=0``

v2.16.1
=======

Release Summary
---------------

| Release Date: 2023-12-04
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Breaking Changes / Porting Guide
--------------------------------

- assert - Nested templating may result in an inability for the conditional to be evaluated. See the porting guide for more information.

Security Fixes
--------------

- templating - Address issues where internal templating can cause unsafe variables to lose their unsafe designation (CVE-2023-5764)

Bugfixes
--------

- Fix issue where an ``include_tasks`` handler in a role was not able to locate a file in ``tasks/`` when ``tasks_from`` was used as a role entry point and ``main.yml`` was not present (https://github.com/ansible/ansible/issues/82241)
- Plugin loader does not dedupe nor cache filter/test plugins by file basename, but full path name.
- Restoring the ability of filters/tests can have same file base name but different tests/filters defined inside.
- ansible-pull now will expand relative paths for the ``-d|--directory`` option is now expanded before use.
- ansible-pull will now correctly handle become and connection password file options for ansible-playbook.
- flush_handlers - properly handle a handler failure in a nested block when ``force_handlers`` is set (http://github.com/ansible/ansible/issues/81532)
- module no_log will no longer affect top level booleans, for example ``no_log_module_parameter='a'`` will no longer hide ``changed=False`` as a 'no log value' (matches 'a').
- role params now have higher precedence than host facts again, matching documentation, this had unintentionally changed in 2.15.
- wait_for should not handle 'non mmapable files' again.

v2.16.0
=======

Release Summary
---------------

| Release Date: 2023-11-06
| `Porting Guide <https://docs.ansible.com/ansible-core/2.16/porting_guides/porting_guide_core_2.16.html>`__


Minor Changes
-------------

- Add Python type hints to the Display class (https://github.com/ansible/ansible/issues/80841)
- Add ``GALAXY_COLLECTIONS_PATH_WARNING`` option to disable the warning given by ``ansible-galaxy collection install`` when installing a collection to a path that isn't in the configured collection paths.
- Add ``python3.12`` to the default ``INTERPRETER_PYTHON_FALLBACK`` list.
- Add ``utcfromtimestamp`` and ``utcnow`` to ``ansible.module_utils.compat.datetime`` to return fixed offset datetime objects.
- Add a general ``GALAXY_SERVER_TIMEOUT`` config option for distribution servers (https://github.com/ansible/ansible/issues/79833).
- Added Python type annotation to connection plugins
- CLI argument parsing - Automatically prepend to the help of CLI arguments that support being specified multiple times. (https://github.com/ansible/ansible/issues/22396)
- DEFAULT_TRANSPORT now defaults to 'ssh', the old 'smart' option is being deprecated as versions of OpenSSH without control persist are basically not present anymore.
- Documentation for set filters ``intersect``, ``difference``, ``symmetric_difference`` and ``union`` now states that the returned list items are in arbitrary order.
- Record ``removal_date`` in runtime metadata as a string instead of a date.
- Remove the ``CleansingNodeVisitor`` class and its usage due to the templating changes that made it superfluous. Also simplify the ``Conditional`` class.
- Removed ``exclude`` and ``recursive-exclude`` commands for generated files from the ``MANIFEST.in`` file. These excludes were unnecessary since releases are expected to be built with a clean worktree.
- Removed ``exclude`` commands for sanity test files from the ``MANIFEST.in`` file. These tests were previously excluded because they did not pass when run from an sdist. However, sanity tests are not expected to pass from an sdist, so excluding some (but not all) of the failing tests makes little sense.
- Removed redundant ``include`` commands from the ``MANIFEST.in`` file. These includes either duplicated default behavior or another command.
- The ``ansible-core`` sdist no longer contains pre-generated man pages. Instead, a ``packaging/cli-doc/build.py`` script is included in the sdist. This script can generate man pages and standalone RST documentation for ``ansible-core`` CLI programs.
- The ``docs`` and ``examples`` directories are no longer included in the ``ansible-core`` sdist. These directories have been moved to the https://github.com/ansible/ansible-documentation repository.
- The minimum required ``setuptools`` version is now 66.1.0, as it is the oldest version to support Python 3.12.
- Update ``ansible_service_mgr`` fact to include init system for SMGL OS family
- Use ``ansible.module_utils.common.text.converters`` instead of ``ansible.module_utils._text``.
- Use ``importlib.resources.abc.TraversableResources`` instead of deprecated ``importlib.abc.TraversableResources`` where available (https:/github.com/ansible/ansible/pull/81082).
- Use ``include`` where ``recursive-include`` is unnecessary in the ``MANIFEST.in`` file.
- Use ``package_data`` instead of ``include_package_data`` for ``setup.cfg`` to avoid ``setuptools`` warnings.
- Utilize gpg check provided internally by the ``transaction.run`` method as oppose to calling it manually.
- ``Templar`` - do not add the ``dict`` constructor to ``globals`` as all required Jinja2 versions already do so
- ansible-doc - allow to filter listing of collections and metadata dump by more than one collection (https://github.com/ansible/ansible/pull/81450).
- ansible-galaxy - Add a plural option to improve ignoring multiple signature error status codes when installing or verifying collections. A space-separated list of error codes can follow --ignore-signature-status-codes in addition to specifying --ignore-signature-status-code multiple times (for example, ``--ignore-signature-status-codes NO_PUBKEY UNEXPECTED``).
- ansible-galaxy - Remove internal configuration argument ``v3`` (https://github.com/ansible/ansible/pull/80721)
- ansible-galaxy - add note to the collection dependency resolver error message about pre-releases if ``--pre`` was not provided (https://github.com/ansible/ansible/issues/80048).
- ansible-galaxy - used to crash out with a "Errno 20 Not a directory" error when extracting files from a role when hitting a file with an illegal name (https://github.com/ansible/ansible/pull/81553). Now it gives a warning identifying the culprit file and the rule violation (e.g., ``my$class.jar`` has a ``$`` in the name) before crashing out, giving the user a chance to remove the invalid file and try again. (https://github.com/ansible/ansible/pull/81555).
- ansible-test - Add Alpine 3.18 to remotes
- ansible-test - Add Fedora 38 container.
- ansible-test - Add Fedora 38 remote.
- ansible-test - Add FreeBSD 13.2 remote.
- ansible-test - Add new pylint checker for new ``# deprecated:`` comments within code to trigger errors when time to remove code that has no user facing deprecation message. Only supported in ansible-core, not collections.
- ansible-test - Add support for RHEL 8.8 remotes.
- ansible-test - Add support for RHEL 9.2 remotes.
- ansible-test - Add support for testing with Python 3.12.
- ansible-test - Allow float values for the ``--timeout`` option to the ``env`` command. This simplifies testing.
- ansible-test - Enable ``thread`` code coverage in addition to the existing ``multiprocessing`` coverage.
- ansible-test - Make Python 3.12 the default version used in the ``base`` and ``default`` containers.
- ansible-test - RHEL 8.8 provisioning can now be used with the ``--python 3.11`` option.
- ansible-test - RHEL 9.2 provisioning can now be used with the ``--python 3.11`` option.
- ansible-test - Refactored ``env`` command logic and timeout handling.
- ansible-test - Remove Fedora 37 remote support.
- ansible-test - Remove Fedora 37 test container.
- ansible-test - Remove Python 3.8 and 3.9 from RHEL 8.8.
- ansible-test - Remove obsolete embedded script for configuring WinRM on Windows remotes.
- ansible-test - Removed Ubuntu 20.04 LTS image from the `--remote` option.
- ansible-test - Removed `freebsd/12.4` remote.
- ansible-test - Removed `freebsd/13.1` remote.
- ansible-test - Removed test remotes: rhel/8.7, rhel/9.1
- ansible-test - Removed the deprecated ``--docker-no-pull`` option.
- ansible-test - Removed the deprecated ``--no-pip-check`` option.
- ansible-test - Removed the deprecated ``foreman`` test plugin.
- ansible-test - Removed the deprecated ``govcsim`` support from the ``vcenter`` test plugin.
- ansible-test - Replace the ``pytest-forked`` pytest plugin with a custom plugin.
- ansible-test - The ``no-get-exception`` sanity test is now limited to plugins in collections. Previously any Python file in a collection was checked for ``get_exception`` usage.
- ansible-test - The ``replace-urlopen`` sanity test is now limited to plugins in collections. Previously any Python file in a collection was checked for ``urlopen`` usage.
- ansible-test - The ``use-compat-six`` sanity test is now limited to plugins in collections. Previously any Python file in a collection was checked for ``six`` usage.
- ansible-test - The openSUSE test container has been updated to openSUSE Leap 15.5.
- ansible-test - Update pip to ``23.1.2`` and setuptools to ``67.7.2``.
- ansible-test - Update the ``default`` containers.
- ansible-test - Update the ``nios-test-container`` to version 2.0.0, which supports API version 2.9.
- ansible-test - Update the logic used to detect when ``ansible-test`` is running from source.
- ansible-test - Updated the CloudStack test container to version 1.6.1.
- ansible-test - Updated the distro test containers to version 6.3.0 to include coverage 7.3.2 for Python 3.8+. The alpine3 container is now based on 3.18 instead of 3.17 and includes Python 3.11 instead of Python 3.10.
- ansible-test - Use ``datetime.datetime.now`` with ``tz`` specified instead of ``datetime.datetime.utcnow``.
- ansible-test - Use a context manager to perform cleanup at exit instead of using the built-in ``atexit`` module.
- ansible-test - When invoking ``sleep`` in containers during container setup, the ``env`` command is used to avoid invoking the shell builtin, if present.
- ansible-test - remove Alpine 3.17 from remotes
- ansible-test — Python 3.8–3.12 will use ``coverage`` v7.3.2.
- ansible-test — ``coverage`` v6.5.0 is to be used only under Python 3.7.
- ansible-vault create: Now raises an error when opening the editor without tty. The flag --skip-tty-check restores previous behaviour.
- ansible_user_module - tweaked macos user defaults to reflect expected defaults (https://github.com/ansible/ansible/issues/44316)
- apt - return calculated diff while running apt clean operation.
- blockinfile - add append_newline and prepend_newline options (https://github.com/ansible/ansible/issues/80835).
- cli - Added short option '-J' for asking for vault password (https://github.com/ansible/ansible/issues/80523).
- command - Add option ``expand_argument_vars`` to disable argument expansion and use literal values - https://github.com/ansible/ansible/issues/54162
- config lookup new option show_origin to also return the origin of a configuration value.
- display methods for warning and deprecation are now proxied to main process when issued from a fork. This allows for the deduplication of warnings and deprecations to work globally.
- dnf5 - enable environment groups installation testing in CI as its support was added.
- dnf5 - enable now implemented ``cacheonly`` functionality
- executor now skips persistent connection when it detects an action that does not require a connection.
- find module - Add ability to filter based on modes
- gather_facts now will use gather_timeout setting to limit parallel execution of modules that do not themselves use gather_timeout.
- group - remove extraneous warning shown when user does not exist (https://github.com/ansible/ansible/issues/77049).
- include_vars - os.walk now follows symbolic links when traversing directories (https://github.com/ansible/ansible/pull/80460)
- module compression is now sourced directly via config, bypassing play_context possibly stale values.
- reboot - show last error message in verbose logs (https://github.com/ansible/ansible/issues/81574).
- service_facts now returns more info for rcctl managed systesm (OpenBSD).
- tasks - the ``retries`` keyword can be specified without ``until`` in which case the task is retried until it succeeds but at most ``retries`` times (https://github.com/ansible/ansible/issues/20802)
- user - add new option ``password_expire_warn`` (supported on Linux only) to set the number of days of warning before a password change is required (https://github.com/ansible/ansible/issues/79882).
- yum_repository - Align module documentation with parameters

Breaking Changes / Porting Guide
--------------------------------

- Any plugin using the config system and the `cli` entry to use the `timeout` from the command line, will see the value change if the use had configured it in any of the lower precedence methods. If relying on this behaviour to consume the global/generic timeout from the DEFAULT_TIMEOUT constant, please consult the documentation on plugin configuration to add the overlaping entries.
- ansible-test - Test plugins that rely on containers no longer support reusing running containers. The previous behavior was an undocumented, untested feature.
- service module will not permanently configure variables/flags for openbsd when doing enable/disable operation anymore, this module was never meant to do this type of work, just to manage the service state itself. A rcctl_config or similar module should be created and used instead.

Deprecated Features
-------------------

- Deprecated ini config option ``collections_paths``, use the singular form ``collections_path`` instead
- Deprecated the env var ``ANSIBLE_COLLECTIONS_PATHS``, use the singular form ``ANSIBLE_COLLECTIONS_PATH`` instead
- Old style vars plugins which use the entrypoints `get_host_vars` or `get_group_vars` are deprecated. The plugin should be updated to inherit from `BaseVarsPlugin` and define a `get_vars` method as the entrypoint.
- Support for Windows Server 2012 and 2012 R2 has been removed as the support end of life from Microsoft is October 10th 2023. These versions of Windows will no longer be tested in this Ansible release and it cannot be guaranteed that they will continue to work going forward.
- ``STRING_CONVERSION_ACTION`` config option is deprecated as it is no longer used in the Ansible Core code base.
- the 'smart' option for setting a connection plugin is being removed as its main purpose (choosing between ssh and paramiko) is now irrelevant.
- vault and unfault filters - the undocumented ``vaultid`` parameter is deprecated and will be removed in ansible-core 2.20. Use ``vault_id`` instead.
- yum_repository - deprecated parameter 'keepcache' (https://github.com/ansible/ansible/issues/78693).

Removed Features (previously deprecated)
----------------------------------------

- ActionBase - remove deprecated ``_remote_checksum`` method
- PlayIterator - remove deprecated ``cache_block_tasks`` and ``get_original_task`` methods
- Remove deprecated ``FileLock`` class
- Removed Python 3.9 as a supported version on the controller. Python 3.10 or newer is required.
- Removed ``include`` which has been deprecated in Ansible 2.12. Use ``include_tasks`` or ``import_tasks`` instead.
- ``Templar`` - remove deprecated ``shared_loader_obj`` parameter of ``__init__``
- ``fetch_url`` - remove auto disabling ``decompress`` when gzip is not available
- ``get_action_args_with_defaults`` - remove deprecated ``redirected_names`` method parameter
- ansible-test - Removed support for the remote Windows targets 2012 and 2012-R2
- inventory_cache - remove deprecated ``default.fact_caching_prefix`` ini configuration option, use ``defaults.fact_caching_prefix`` instead.
- module_utils/basic.py - Removed Python 3.5 as a supported remote version. Python 2.7 or Python 3.6+ is now required.
- stat - removed unused `get_md5` parameter.

Security Fixes
--------------

- ansible-galaxy - Prevent roles from using symlinks to overwrite files outside of the installation directory (CVE-2023-5115)

Bugfixes
--------

- Allow for searching handler subdir for included task via include_role (https://github.com/ansible/ansible/issues/81722)
- AnsibleModule.run_command - Only use selectors when needed, and rely on Python stdlib subprocess for the simple task of collecting stdout/stderr when prompt matching is not required.
- Cache host_group_vars after instantiating it once and limit the amount of repetitive work it needs to do every time it runs.
- Call PluginLoader.all() once for vars plugins, and load vars plugins that run automatically or are enabled specifically by name subsequently.
- Display - Defensively configure writing to stdout and stderr with a custom encoding error handler that will replace invalid characters while providing a deprecation warning that non-utf8 text will result in an error in a future version.
- Exclude internal options from man pages and docs.
- Fix ``ansible-config init`` man page option indentation.
- Fix ``ast`` deprecation warnings for ``Str`` and ``value.s`` when using Python 3.12.
- Fix ``run_once`` being incorrectly interpreted on handlers (https://github.com/ansible/ansible/issues/81666)
- Fix exceptions caused by various inputs when performing arg splitting or parsing key/value pairs. Resolves issue https://github.com/ansible/ansible/issues/46379 and issue https://github.com/ansible/ansible/issues/61497
- Fix incorrect parsing of multi-line Jinja2 blocks when performing arg splitting or parsing key/value pairs.
- Fix post-validating looped task fields so the strategy uses the correct values after task execution.
- Fixed `pip` module failure in case of usage quotes for `virtualenv_command` option for the venv command. (https://github.com/ansible/ansible/issues/76372)
- From issue https://github.com/ansible/ansible/issues/80880, when notifying a handler from another handler, handler notifications must be registered immediately as the flush_handler call is not recursive.
- Import ``FILE_ATTRIBUTES`` from ``ansible.module_utils.common.file`` in ``ansible.module_utils.basic`` instead of defining it twice.
- Inventory scripts parser not treat exception when getting hostsvar (https://github.com/ansible/ansible/issues/81103)
- On Python 3 use datetime methods ``fromtimestamp`` and ``now`` with UTC timezone instead of ``utcfromtimestamp`` and ``utcnow``, which are deprecated in Python 3.12.
- PluginLoader - fix Jinja plugin performance issues (https://github.com/ansible/ansible/issues/79652)
- PowerShell - Remove some code which is no longer valid for dotnet 5+
- Prevent running same handler multiple times when included via ``include_role`` (https://github.com/ansible/ansible/issues/73643)
- Prompting - add a short sleep between polling for user input to reduce CPU consumption (https://github.com/ansible/ansible/issues/81516).
- Properly disable ``jinja2_native`` in the template module when jinja2 override is used in the template (https://github.com/ansible/ansible/issues/80605)
- Properly template tags in parent blocks (https://github.com/ansible/ansible/issues/81053)
- Remove unreachable parser error for removed ``static`` parameter of ``include_role``
- Replace uses of ``configparser.ConfigParser.readfp()`` which was removed in Python 3.12 with ``configparser.ConfigParser.read_file()`` (https://github.com/ansible/ansible/issues/81656)
- Set filters ``intersect``, ``difference``, ``symmetric_difference`` and ``union`` now always return a ``list``, never a ``set``. Previously, a ``set`` would be returned if the inputs were a hashable type such as ``str``, instead of a collection, such as a ``list`` or ``tuple``.
- Set filters ``intersect``, ``difference``, ``symmetric_difference`` and ``union`` now use set operations when the given items are hashable. Previously, list operations were performed unless the inputs were a hashable type such as ``str``, instead of a collection, such as a ``list`` or ``tuple``.
- Switch result queue from a ``multiprocessing.queues.Queue` to ``multiprocessing.queues.SimpleQueue``, primarily to allow properly handling pickling errors, to prevent an infinite hang waiting for task results
- The ``ansible-config init`` command now has a documentation description.
- The ``ansible-galaxy collection download`` command now has a documentation description.
- The ``ansible-galaxy collection install`` command documentation is now visible (previously hidden by a decorator).
- The ``ansible-galaxy collection verify`` command now has a documentation description.
- The ``ansible-galaxy role install`` command documentation is now visible (previously hidden by a decorator).
- The ``ansible-inventory`` command command now has a documentation description (previously used as the epilog).
- The ``hostname`` module now also updates both current and permanent hostname on OpenBSD. Before it only updated the permanent hostname (https://github.com/ansible/ansible/issues/80520).
- Update module_utils.urls unit test to work with cryptography >= 41.0.0.
- When generating man pages, use ``func`` to find the command function instead of looking it up by the command name.
- ``StrategyBase._process_pending_results`` - create a ``Templar`` on demand for templating ``changed_when``/``failed_when``.
- ``ansible-galaxy`` now considers all collection paths when identifying which collection requirements are already installed. Use the ``COLLECTIONS_PATHS`` and ``COLLECTIONS_SCAN_SYS_PATHS`` config options to modify these. Previously only the install path was considered when resolving the candidates. The install path will remain the only one potentially modified. (https://github.com/ansible/ansible/issues/79767, https://github.com/ansible/ansible/issues/81163)
- ``ansible.module_utils.service`` - ensure binary data transmission in ``daemonize()``
- ``ansible.module_utils.service`` - fix inter-process communication in ``daemonize()``
- ``import_role`` reverts to previous behavior of exporting vars at compile time.
- ``pkg_mgr`` - fix the default dnf version detection
- ansiballz - Prevent issue where the time on the control host could change part way through building the ansiballz file, potentially causing a pre-1980 date to be used during ansiballz unpacking leading to a zip file error (https://github.com/ansible/ansible/issues/80089)
- ansible terminal color settings were incorrectly limited to 16 options via 'choices', removing so all 256 can be accessed.
- ansible-console - fix filtering by collection names when a collection search path was set (https://github.com/ansible/ansible/pull/81450).
- ansible-galaxy - Enabled the ``data`` tarfile filter during role installation for Python versions that support it. A probing mechanism is used to avoid Python versions with a broken implementation.
- ansible-galaxy - Fix issue installing collections containing directories with more than 100 characters on python versions before 3.10.6
- ansible-galaxy - Fix variable type error when installing subdir collections (https://github.com/ansible/ansible/issues/80943)
- ansible-galaxy - Provide a better error message when using a requirements file with an invalid format - https://github.com/ansible/ansible/issues/81901
- ansible-galaxy - fix installing collections from directories that have a trailing path separator (https://github.com/ansible/ansible/issues/77803).
- ansible-galaxy - fix installing signed collections (https://github.com/ansible/ansible/issues/80648).
- ansible-galaxy - reduce API calls to servers by fetching signatures only for final candidates.
- ansible-galaxy - started allowing the use of pre-releases for collections that do not have any stable versions published. (https://github.com/ansible/ansible/pull/81606)
- ansible-galaxy - started allowing the use of pre-releases for dependencies on any level of the dependency tree that specifically demand exact pre-release versions of collections and not version ranges. (https://github.com/ansible/ansible/pull/81606)
- ansible-galaxy collection verify - fix verifying signed collections when the keyring is not configured.
- ansible-galaxy info - fix reporting no role found when lookup_role_by_name returns None.
- ansible-inventory - index available_hosts for major performance boost when dumping large inventories
- ansible-test - Add a ``pylint`` plugin to work around a known issue on Python 3.12.
- ansible-test - Add support for ``argcomplete`` version 3.
- ansible-test - All containers created by ansible-test now include the current test session ID in their name. This avoids conflicts between concurrent ansible-test invocations using the same container host.
- ansible-test - Always use ansible-test managed entry points for ansible-core CLI tools when not running from source. This fixes issues where CLI entry points created during install are not compatible with ansible-test.
- ansible-test - Fix a traceback that occurs when attempting to test Ansible source using a different ansible-test. A clear error message is now given when this scenario occurs.
- ansible-test - Fix handling of timeouts exceeding one day.
- ansible-test - Fix parsing of cgroup entries which contain a ``:`` in the path (https://github.com/ansible/ansible/issues/81977).
- ansible-test - Fix several possible tracebacks when using the ``-e`` option with sanity tests.
- ansible-test - Fix various cases where the test timeout could expire without terminating the tests.
- ansible-test - Include missing ``pylint`` requirements for Python 3.10.
- ansible-test - Pre-build a PyYAML wheel before installing requirements to avoid a potential Cython build failure.
- ansible-test - Remove redundant warning about missing programs before attempting to execute them.
- ansible-test - The ``import`` sanity test now checks the collection loader for remote-only Python support when testing ansible-core.
- ansible-test - Unit tests now report warnings generated during test runs. Previously only warnings generated during test collection were reported.
- ansible-test - Update ``pylint`` to 2.17.2 to resolve several possible false positives.
- ansible-test - Update ``pylint`` to 2.17.3 to resolve several possible false positives.
- ansible-test - Update ``pylint`` to version 3.0.1.
- ansible-test - Use ``raise ... from ...`` when raising exceptions from within an exception handler.
- ansible-test - When bootstrapping remote FreeBSD instances, use the OS packaged ``setuptools`` instead of installing the latest version from PyPI.
- ansible-test local change detection - use ``git merge-base <branch> HEAD`` instead of ``git merge-base --fork-point <branch>`` (https://github.com/ansible/ansible/pull/79734).
- ansible-vault - fail when the destination file location is not writable before performing encryption (https://github.com/ansible/ansible/issues/81455).
- apt - ignore fail_on_autoremove and allow_downgrade parameters when using aptitude (https://github.com/ansible/ansible/issues/77868).
- blockinfile - avoid crash with Python 3 if creating the directory fails when ``create=true`` (https://github.com/ansible/ansible/pull/81662).
- connection timeouts defined in ansible.cfg will now be properly used, the --timeout cli option was obscuring them by always being set.
- copy - print correct destination filename when using `content` and `--diff` (https://github.com/ansible/ansible/issues/79749).
- copy unit tests - Fixing "dir all perms" documentation and formatting for easier reading.
- core will now also look at the connection plugin to force 'local' interpreter for networking path compatibility as just ansible_network_os could be misleading.
- deb822_repository - use http-agent for receiving content (https://github.com/ansible/ansible/issues/80809).
- debconf - idempotency in questions with type 'password' (https://github.com/ansible/ansible/issues/47676).
- distribution facts - fix Source Mage family mapping
- dnf - fix a failure when a package from URI was specified and ``update_only`` was set (https://github.com/ansible/ansible/issues/81376).
- dnf5 - Update dnf5 module to handle API change for setting the download directory (https://github.com/ansible/ansible/issues/80887)
- dnf5 - Use ``transaction.check_gpg_signatures`` API call to check package signatures AND possibly to recover from when keys are missing.
- dnf5 - fix module and package names in the message following failed module respawn attempt
- dnf5 - use the logs API to determine transaction problems
- dpkg_selections - check if the package exists before performing the selection operation (https://github.com/ansible/ansible/issues/81404).
- encrypt - deprecate passlib_or_crypt API (https://github.com/ansible/ansible/issues/55839).
- fetch - Handle unreachable errors properly (https://github.com/ansible/ansible/issues/27816)
- file modules - Make symbolic modes with X use the computed permission, not original file (https://github.com/ansible/ansible/issues/80128)
- file modules - fix validating invalid symbolic modes.
- first found lookup has been updated to use the normalized argument parsing (pythonic) matching the documented examples.
- first found lookup, fixed an issue with subsequent items clobbering information from previous ones.
- first_found lookup now gets 'untemplated' loop entries and handles templating itself as task_executor was removing even 'templatable' entries and breaking functionality. https://github.com/ansible/ansible/issues/70772
- galaxy - check if the target for symlink exists (https://github.com/ansible/ansible/pull/81586).
- galaxy - cross check the collection type and collection source (https://github.com/ansible/ansible/issues/79463).
- gather_facts parallel option was doing the reverse of what was stated, now it does run modules in parallel when True and serially when False.
- handlers - fix ``v2_playbook_on_notify`` callback not being called when notifying handlers
- handlers - the ``listen`` keyword can affect only one handler with the same name, the last one defined as it is a case with the ``notify`` keyword (https://github.com/ansible/ansible/issues/81013)
- include_role - expose variables from parent roles to role's handlers (https://github.com/ansible/ansible/issues/80459)
- inventory_ini - handle SyntaxWarning while parsing ini file in inventory (https://github.com/ansible/ansible/issues/81457).
- iptables - remove default rule creation when creating iptables chain to be more similar to the command line utility (https://github.com/ansible/ansible/issues/80256).
- lib/ansible/utils/encrypt.py - remove unused private ``_LOCK`` (https://github.com/ansible/ansible/issues/81613)
- lookup/url.py - Fix incorrect var/env/ini entry for `force_basic_auth`
- man page build - Remove the dependency on the ``docs`` directory for building man pages.
- man page build - Sub commands of ``ansible-galaxy role`` and ``ansible-galaxy collection`` are now documented.
- module responses - Ensure that module responses are utf-8 adhereing to JSON RFC and expectations of the core code.
- module/role argument spec - validate the type for options that are None when the option is required or has a non-None default (https://github.com/ansible/ansible/issues/79656).
- modules/user.py - Add check for valid directory when creating new user homedir (allows /dev/null as skeleton) (https://github.com/ansible/ansible/issues/75063)
- paramiko_ssh, psrp, and ssh connection plugins - ensure that all values for options that should be strings are actually converted to strings (https://github.com/ansible/ansible/pull/81029).
- password_hash - fix salt format for ``crypt``  (only used if ``passlib`` is not installed) for the ``bcrypt`` algorithm.
- pep517 build backend - Copy symlinks when copying the source tree. This avoids tracebacks in various scenarios, such as when a venv is present in the source tree.
- pep517 build backend - Use the documented ``import_module`` import from ``importlib``.
- pip module - Update module to prefer use of the python ``packaging`` and ``importlib.metadata`` modules due to ``pkg_resources`` being deprecated (https://github.com/ansible/ansible/issues/80488)
- pkg_mgr.py - Fix `ansible_pkg_mgr` incorrect in TencentOS Server Linux
- pkg_mgr.py - Fix `ansible_pkg_mgr` is unknown in Kylin Linux (https://github.com/ansible/ansible/issues/81332)
- powershell modules - Only set an rc of 1 if the PowerShell pipeline signaled an error occurred AND there are error records present. Previously it would do so only if the error signal was present without checking the error count.
- replace - handle exception when bad escape character is provided in replace (https://github.com/ansible/ansible/issues/79364).
- role deduplication - don't deduplicate before a role has had a task run for that particular host (https://github.com/ansible/ansible/issues/81486).
- service module, does not permanently configure flags flags on Openbsd when enabling/disabling a service.
- service module, enable/disable is not a exclusive action in checkmode anymore.
- setup gather_timeout - Fix timeout in get_mounts_facts for linux.
- setup module (fact gathering) will now try to be smarter about different versions of facter emitting error when --puppet flag is used w/o puppet.
- syntax check - Limit ``--syntax-check`` to ``ansible-playbook`` only, as that is the only CLI affected by this argument (https://github.com/ansible/ansible/issues/80506)
- tarfile - handle data filter deprecation warning message for extract and extractall (https://github.com/ansible/ansible/issues/80832).
- template - Fix for formatting issues when a template path contains valid jinja/strftime pattern (especially line break one) and using the template path in ansible_managed (https://github.com/ansible/ansible/pull/79129)
- templating - In the template action and lookup, use local jinja2 environment overlay overrides instead of mutating the templars environment
- templating - prevent setting arbitrary attributes on Jinja2 environments via Jinja2 overrides in templates
- templating escape and single var optimization now use correct delimiters when custom ones are provided either via task or template header.
- unarchive - fix unarchiving sources that are copied to the remote node using a relative temporory directory path (https://github.com/ansible/ansible/issues/80710).
- uri - fix search for JSON type to include complex strings containing '+'
- uri/urls - Add compat function to handle the ability to parse the filename from a Content-Disposition header (https://github.com/ansible/ansible/issues/81806)
- urls.py - fixed cert_file and key_file parameters when running on Python 3.12 - https://github.com/ansible/ansible/issues/80490
- user - set expiration value correctly when unable to retrieve the current value from the system (https://github.com/ansible/ansible/issues/71916)
- validate-modules sanity test - replace semantic markup parsing and validating code with the code from `antsibull-docs-parser 0.2.0 <https://github.com/ansible-community/antsibull-docs-parser/releases/tag/0.2.0>`__ (https://github.com/ansible/ansible/pull/80406).
- vars_prompt - internally convert the ``unsafe`` value to ``bool``
- vault and unvault filters now properly take ``vault_id`` parameter.
- win_fetch - Add support for using file with wildcards in file name. (https://github.com/ansible/ansible/issues/73128)
- winrm - Better handle send input failures when communicating with hosts under load

Known Issues
------------

- ansible-galaxy - dies in the middle of installing a role when that role contains Java inner classes (files with $ in the file name).  This is by design, to exclude temporary or backup files. (https://github.com/ansible/ansible/pull/81553).
- ansible-test - The ``pep8`` sanity test is unable to detect f-string spacing issues (E201, E202) on Python 3.10 and 3.11. They are correctly detected under Python 3.12. See (https://github.com/PyCQA/pycodestyle/issues/1190).
