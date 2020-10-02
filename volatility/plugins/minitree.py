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

class minitree(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option='p', type="int", default=None, help='Process ID',
            action = 'store')
        if self._config.PID is None:
            raise(Exception("Process ID is required.  Please use -p ####"))

    def render_text(self, outfd, data):
        current = self._config.PID
        toWrite = ""
        while current in data:
            task = data[current]
            toWrite = "{:15} {:6}  {:6}\n".format(task.ImageFileName+":", current, task.InheritedFromUniqueProcessId,) + toWrite
            current = int(task.InheritedFromUniqueProcessId)
        outfd.write(toWrite)



    #Borrowed this from PSTree
    @cache.CacheDecorator(lambda self: "tests/pstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):

        ## Load a new address space
        addr_space = utils.load_as(self._config)

        return dict(
                (int(task.UniqueProcessId), task)
                for task in tasks.pslist(addr_space)
                )
