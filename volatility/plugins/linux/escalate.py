# Volatility
#
# Authors
# Adam Traub <traubad@vcu.edu>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

from volatility import renderers
from volatility.renderers.basic import Address

import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.obj as obj
import volatility.debug as debug

import volatility.win32 as win32

class escalate(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        self._config.add_option('PID', short_option='i', type="int", default=None,
            help='ID of Process to Escalate', action='store')

        self._config.add_option('NAME', short_option='n', type='str', default=None,
            help='Name of Process to Escalate', action='store')

        if self._config.PID is None and self._config.NAME is None:
            raise(Exception("Either a process id or a Process name is required e.g." +
                            "\nescalate -i 1104" +
                            "\nescalate -n bash"))

        self._addrspace = utils.load_as(self._config)

    def get_pid_from_name(self, name):
        for eproc in win32.tasks.pslist(self._addrspace):
            if eproc.ImageFileName == name:
                return eproc.UniqueProcessId.v()
        else:
            raise(Exception("Bad Process name: {}".format(name)))


    def render_text(self, outfd, data):
        pid = self._config.PID

        if pid is None:
            pid = self.get_pid_from_name(self._config.NAME)

        outfd.write(pid)

        # output = win32.tasks.pslist(self._addrspace)
        # for eproc in win32.tasks.pslist(self._addrspace):
        #     print "{0:16} {1:<6} {2:<6} {3:#08x}".format(eproc.ImageFileName,
        #                                                eproc.UniqueProcessId.v(),
        #                                                eproc.InheritedFromUniqueProcessId.v(),
        #                                                eproc.obj_offset)
    # #Borrowed this from PSTree
    # @cache.CacheDecorator(lambda self: "tests/pstree/verbose={0}".format(self._config.VERBOSE))
    # def calculate(self):
    #
    #     ## Load a new address space
    #     addr_space = utils.load_as(self._config)
    #
    #     return dict(
    #             (int(task.UniqueProcessId), task)
    #             for task in tasks.pslist(addr_space)
    #             )
