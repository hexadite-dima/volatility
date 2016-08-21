# Volatility kmem address space plugin
# Copyright (C) 2016 Hexadite Ltd.
#
# Authors:
# Dima Krasner - dima@hexadite.com
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import fcntl
import ctypes
import struct
import volatility.addrspace as addrspace
import volatility.plugins.addrspaces.standard as standard


# xnu/bsd/sys/disk.h
DKIOCGETMEMDEVINFO = 0x4018645a

class dk_memdev_info_t(ctypes.Structure):
    _fields_ = [
        ('mi_mdev', ctypes.c_uint), # boolean_t really and it's signed on x86, but we can get away with that since it's 0 and 1
        ('mi_phys', ctypes.c_uint),
        ('mi_base', ctypes.c_uint32),
        ('mi_size', ctypes.c_uint64)
    ]


class KmemAddressSpace(standard.FileAddressSpace):
    # right after FileAddressSpace
    order = 101

    def __init__(self, base, config, layered = False, **kwargs):
        # yes, I to copy these three lines from FileAddressSpace
        addrspace.BaseAddressSpace.__init__(self, base, config, **kwargs)
        self.as_assert(base == None or layered, 'Must be first Address Space')
        print base,layered, kwargs

        self.fname = '/dev/kmem'
        self.fhandle = open(self.fname, 'rb')
        try:
            buf = ctypes.create_string_buffer(ctypes.sizeof(dk_memdev_info_t))
            fcntl.ioctl(self.fhandle.fileno(), DKIOCGETMEMDEVINFO, buf, True)
	    self.fsize = ctypes.cast(buf, ctypes.POINTER(dk_memdev_info_t)).contents.mi_size
            self._long_struct = struct.Struct("=I")
        except Exception:
            # we don't want to choke Volatility with EMFILE
            self.fhandle.close()
