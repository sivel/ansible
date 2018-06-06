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

from __future__ import print_function

import json
import sys

from collections import OrderedDict
from contextlib import contextmanager


class ReporterEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Exception):
            return str(o)

        return json.JSONEncoder.default(self, o)


class Reporter(object):
    def __init__(self):
        self.files = OrderedDict()

    def _ensure_default_entry(self, path):
        try:
            self.files[path]
        except KeyError:
            self.files[path] = {
                'errors': [],
                'warnings': [],
                'traces': [],
                'warning_traces': []
            }

    def _log(self, path, code, msg, level='error', line=0, column=0):
        self._ensure_default_entry(path)
        lvl_dct = self.files[path]['%ss' % level]
        lvl_dct.append({
            'code': code,
            'msg': msg,
            'line': line,
            'column': column
        })

    def error(self, *args, **kwargs):
        self._log(*args, level='error', **kwargs)

    def warning(self, *args, **kwargs):
        self._log(*args, level='warning', **kwargs)

    def trace(self, path, tracebk):
        self._ensure_default_entry(path)
        self.files[path]['traces'].append(tracebk)

    def warning_trace(self, path, tracebk):
        self._ensure_default_entry(path)
        self.files[path]['warning_traces'].append(tracebk)

    @staticmethod
    @contextmanager
    def _output_handle(output):
        if output != '-':
            handle = open(output, 'w+')
        else:
            handle = sys.stdout

        yield handle

        handle.flush()
        handle.close()

    @staticmethod
    def _filter_out_ok(reports):
        temp_reports = OrderedDict()
        for path, report in reports.items():
            if report['errors'] or report['warnings']:
                temp_reports[path] = report

        return temp_reports

    def plain(self, warnings=False, output='-'):
        """Print out the test results in plain format

        output is ignored here for now
        """
        ret = []

        for path, report in Reporter._filter_out_ok(self.files).items():
            traces = report['traces'][:]
            if warnings and report['warnings']:
                traces.extend(report['warning_traces'])

            for trace in traces:
                print('TRACE:')
                print('\n    '.join(('    %s' % trace).splitlines()))
            for error in report['errors']:
                error['path'] = path
                print('%(path)s:%(line)d:%(column)d: E%(code)d %(msg)s' % error)
                ret.append(1)
            if warnings:
                for warning in report['warnings']:
                    warning['path'] = path
                    print('%(path)s:%(line)d:%(column)d: W%(code)d %(msg)s' % warning)

        return 3 if ret else 0

    def json(self, warnings=False, output='-'):
        """Print out the test results in json format

        warnings is not respected in this output
        """
        ret = [len(r['errors']) for _, r in self.files.items()]

        with Reporter._output_handle(output) as handle:
            print(json.dumps(Reporter._filter_out_ok(self.files), indent=4, cls=ReporterEncoder), file=handle)

        return 3 if sum(ret) else 0
