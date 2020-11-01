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

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.pslist as linux_pslist


class escalate(linux_pslist.linux_pslist):

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)

        self._config.add_option('PID', short_option='i', type="int", default=None,
            help='ID of Process to Escalate', action='store')

        self._config.add_option('NAME', short_option='n', type='string', default=None, help='Name of Process to Escalate', action='store')

        if self._config.PID is None and self._config.NAME is None:
            raise(Exception("Either a process id or a Process name is required e.g." +
                            "\nescalate -i 1104" +
                            "\nescalate -n bash"))

    def get_pid_from_name(self, name):
        for proc in linux_pslist.linux_pslist(self._config).calculate():
            if proc.comm == name:
                return proc.pid
        else:
            raise(Exception("Bad Process name: {}".format(name)))


    def render_text(self, outfd, data):
        pid = self._config.PID

        if pid is None:
            pid = self.get_pid_from_name(self._config.NAME)

        outfd.write("Pid: {}".format(pid))
