# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Matt Martz <matt@sivel.net>
# Copyright (C) 2015 Rackspace US, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import abc
import ast
import os
import traceback

from distutils.version import StrictVersion

from ansible import __version__ as ansible_version
from ansible.module_utils.six import with_metaclass
from ansible.plugins.loader import fragment_loader
from ansible.utils.plugin_docs import get_docstring

from reporter import Reporter

from utils import CaptureStd, parse_yaml


def plugin_doc_schema(v):
    pass


class Validator(with_metaclass(abc.ABCMeta, object)):
    """Validator instances are intended to be run on a single object.  if you
    are scanning multiple objects for problems, you'll want to have a separate
    Validator for each one."""

    def __init__(self, path, reporter=None):
        self.path = path
        self.basename = os.path.basename(self.path)
        self.name, _ = os.path.splitext(self.basename)

        self.reporter = reporter or Reporter()

    @property
    def object_name(self):
        return self.basename

    @property
    def object_path(self):
        return self.path

    @abc.abstractmethod
    def validate(self):
        """Run this method to generate the test results"""
        pass


class FileValidator(Validator):

    def __init__(self, path, reporter=None):
        super(FileValidator, self).__init__(path, reporter=reporter)

        with open(path) as f:
            self.text = f.read()
        self.length = len(self.text.splitlines())
        try:
            self.ast = ast.parse(self.text)
        except Exception:
            self.ast = None

    def _python_file(self):
        if self.path.endswith('.py') or self._python_module_override:
            return True
        return False

    def _powershell_file(self):
        if self.path.endswith('.ps1'):
            return True
        return False

    def _get_docs(self):
        docs = {
            'DOCUMENTATION': {
                'value': None,
                'lineno': 0,
                'end_lineno': 0,
            },
            'EXAMPLES': {
                'value': None,
                'lineno': 0,
                'end_lineno': 0,
            },
            'RETURN': {
                'value': None,
                'lineno': 0,
                'end_lineno': 0,
            },
            'ANSIBLE_METADATA': {
                'value': None,
                'lineno': 0,
                'end_lineno': 0,
            }
        }
        for child in self.ast.body:
            if isinstance(child, ast.Assign):
                for grandchild in child.targets:
                    if not isinstance(grandchild, ast.Name):
                        continue

                    if grandchild.id == 'DOCUMENTATION':
                        docs['DOCUMENTATION']['value'] = child.value.s
                        docs['DOCUMENTATION']['lineno'] = child.lineno
                        docs['DOCUMENTATION']['end_lineno'] = (
                            child.lineno + len(child.value.s.splitlines())
                        )
                    elif grandchild.id == 'EXAMPLES':
                        docs['EXAMPLES']['value'] = child.value.s
                        docs['EXAMPLES']['lineno'] = child.lineno
                        docs['EXAMPLES']['end_lineno'] = (
                            child.lineno + len(child.value.s.splitlines())
                        )
                    elif grandchild.id == 'RETURN':
                        docs['RETURN']['value'] = child.value.s
                        docs['RETURN']['lineno'] = child.lineno
                        docs['RETURN']['end_lineno'] = (
                            child.lineno + len(child.value.s.splitlines())
                        )
                    elif grandchild.id == 'ANSIBLE_METADATA':
                        docs['ANSIBLE_METADATA']['value'] = child.value
                        docs['ANSIBLE_METADATA']['lineno'] = child.lineno
                        try:
                            docs['ANSIBLE_METADATA']['end_lineno'] = (
                                child.lineno + len(child.value.s.splitlines())
                            )
                        except AttributeError:
                            docs['ANSIBLE_METADATA']['end_lineno'] = (
                                child.value.values[-1].lineno
                            )

        return docs

    def _validate_docs(self):
        doc_info = self._get_docs()
        deprecated = False
        doc = None
        if not bool(doc_info['DOCUMENTATION']['value']):
            self.reporter.error(
                path=self.object_path,
                code=301,
                msg='No DOCUMENTATION provided'
            )
        else:
            doc, errors, traces = parse_yaml(
                doc_info['DOCUMENTATION']['value'],
                doc_info['DOCUMENTATION']['lineno'],
                self.name, 'DOCUMENTATION'
            )
            for error in errors:
                self.reporter.error(
                    path=self.object_path,
                    code=302,
                    **error
                )
            for trace in traces:
                self.reporter.trace(
                    path=self.object_path,
                    tracebk=trace
                )
            if not errors and not traces:
                with CaptureStd():
                    try:
                        get_docstring(self.path, fragment_loader, verbose=True)
                    except AssertionError:
                        fragment = doc['extends_documentation_fragment']
                        self.reporter.error(
                            path=self.object_path,
                            code=303,
                            msg='DOCUMENTATION fragment missing: %s' % fragment
                        )
                    except Exception as e:
                        self.reporter.trace(
                            path=self.object_path,
                            tracebk=traceback.format_exc()
                        )
                        self.reporter.error(
                            path=self.object_path,
                            code=304,
                            msg='Unknown DOCUMENTATION error, see TRACE: %s' % e
                        )

                if 'options' in doc and doc['options'] is None:
                    self.reporter.error(
                        path=self.object_path,
                        code=320,
                        msg='DOCUMENTATION.options must be a dictionary/hash when used',
                    )

                if self.object_name.startswith('_') and not os.path.islink(self.object_path):
                    deprecated = True
                    if 'deprecated' not in doc or not doc.get('deprecated'):
                        self.reporter.error(
                            path=self.object_path,
                            code=318,
                            msg='Module deprecated, but DOCUMENTATION.deprecated is missing'
                        )

                if os.path.islink(self.object_path):
                    # This module has an alias, which we can tell as it's a symlink
                    # Rather than checking for `module: $filename` we need to check against the true filename
                    self._validate_docs_schema(
                        doc,
                        self.__class__.DOCUMENTATION_SCHEMA(
                            os.readlink(self.object_path).split('.')[0]
                        ),
                        'DOCUMENTATION',
                        305
                    )
                else:
                    # This is the normal case
                    self._validate_docs_schema(
                        doc,
                        self.__class__.DOCUMENTATION_SCHEMA(
                            self.object_name.split('.')[0]
                        ),
                        'DOCUMENTATION',
                        305
                    )

                self._check_version_added(doc)
                self._check_for_new_args(doc)

        return doc_info, doc, deprecated

    def _check_for_new_args(self, doc):
        if not self.base_branch or self._is_new_module():
            return

        with CaptureStd():
            try:
                existing_doc = get_docstring(self.base_module, fragment_loader, verbose=True)[0]
                existing_options = existing_doc.get('options', {}) or {}
            except AssertionError:
                fragment = doc['extends_documentation_fragment']
                self.reporter.warning(
                    path=self.object_path,
                    code=392,
                    msg='Pre-existing DOCUMENTATION fragment missing: %s' % fragment
                )
                return
            except Exception as e:
                self.reporter.warning_trace(
                    path=self.object_path,
                    tracebk=e
                )
                self.reporter.warning(
                    path=self.object_path,
                    code=391,
                    msg=('Unknown pre-existing DOCUMENTATION '
                         'error, see TRACE. Submodule refs may '
                         'need updated')
                )
                return

        try:
            mod_version_added = StrictVersion(
                str(existing_doc.get('version_added', '0.0'))
            )
        except ValueError:
            mod_version_added = StrictVersion('0.0')

        options = doc.get('options', {}) or {}

        should_be = '.'.join(ansible_version.split('.')[:2])
        strict_ansible_version = StrictVersion(should_be)

        for option, details in options.items():
            try:
                names = [option] + details.get('aliases', [])
            except (TypeError, AttributeError):
                # Reporting of this syntax error will be handled by schema validation.
                continue

            if any(name in existing_options for name in names):
                continue

            try:
                version_added = StrictVersion(
                    str(details.get('version_added', '0.0'))
                )
            except ValueError:
                version_added = details.get('version_added', '0.0')
                self.reporter.error(
                    path=self.object_path,
                    code=308,
                    msg=('version_added for new option (%s) '
                         'is not a valid version number: %r' %
                         (option, version_added))
                )
                continue
            except Exception:
                # If there is any other exception it should have been caught
                # in schema validation, so we won't duplicate errors by
                # listing it again
                continue

            if (strict_ansible_version != mod_version_added and
                    (version_added < strict_ansible_version or
                     strict_ansible_version < version_added)):
                self.reporter.error(
                    path=self.object_path,
                    code=309,
                    msg=('version_added for new option (%s) should '
                         'be %s. Currently %s' %
                         (option, should_be, version_added))
                )

    def validate(self):
        self._check_gpl3_header()

        if self._python_file():
            doc_info, docs = self._validate_docs()

        return doc_info, docs
