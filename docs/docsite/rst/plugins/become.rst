.. contents:: Topics

.. versionadded:: 2.8

Become Plugins
--------------

Become plugins work to ensure that Ansible can use certain privilege escalation systems when running the basic commands to work with
the target machine as well as the modules required to execute the tasks specified in the play.
These utilities (``sudo``, ``su``, ``doas``, etc) generally let you 'become' another user to execute a command as with the permissions of that user.



.. _enabling_become:

Enabling Become Plugins
+++++++++++++++++++++++

Those shipped with Ansible are already enabled. For custom plugins, you can add them by dropping into a ``become_plugins`` directory
adjacent to your play, inside a role, or by putting it in one of the become plugin directory sources configured in :ref:`ansible.cfg <ansible_configuration_settings>`.


.. _using_become:

Using Become Plugins
++++++++++++++++++++

In addition to the default configuration settings in :ref:`ansible_configuration_settings` or the ``--become-method`` command line option,
you can use the ``become_method`` keyword in a play or, if you need to be 'host specific', the connection variable
``ansible_become_method`` to select the plugin to use.

You can further control the settings for each plugin via other configuration options detailed in the plugin themselves (linked below).

.. toctree:: :maxdepth: 1
    :glob:

    become/*

.. seealso::

   :doc:`../user_guide/playbooks`
       An introduction to playbooks
   :doc:`inventory`
       Ansible inventory plugins
   :doc:`callback`
       Ansible callback plugins
   :doc:`../user_guide/playbooks_filters`
       Jinja2 filter plugins
   :doc:`../user_guide/playbooks_tests`
       Jinja2 test plugins
   :doc:`../user_guide/playbooks_lookups`
       Jinja2 lookup plugins
   `User Mailing List <https://groups.google.com/group/ansible-devel>`_
       Have a question?  Stop by the google group!
   `irc.freenode.net <http://irc.freenode.net>`_
       #ansible IRC chat channel
