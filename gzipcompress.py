"""
Discord File System
Copyright (C) 2022  NWhut

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from gzip import GzipFile
from collections import deque


CHUNK = 16 * 1024


class Buffer(object):
    def __init__ (self):
        self.__buf = deque()
        self.__size = 0
    def __len__(self):
        return self.__size
    def write(self, data):
        self.__buf.append(data)
        self.__size += len(data)
    def read(self, size=-1):
        if size < 0: size = self.__size
        ret_list = []
        while size > 0 and len(self.__buf):
            s = self.__buf.popleft()
            size -= len(s)
            ret_list.append(s)
        if size < 0:
            ret_list[-1], remainder = ret_list[-1][:size], ret_list[-1][size:]
            self.__buf.appendleft(remainder)
        ret = b''.join(ret_list)
        self.__size -= len(ret)
        return ret
    def flush(self):
        pass
    def clear(self):
        return self.__init__()
    def close(self):
        pass


class GzipCompressReadStream(object):
    def __init__(self, reader, seeker=None):
        self.__input = reader
        self.__seeker = seeker
        if self.__seeker:
            def fn_seek(self, pos):
                seeker(seeker)
                self.__buf.clear()
            self.seek = fn_seek
        self.__buf = Buffer()
        self.__gzip = GzipFile(None, mode='wb', fileobj=self.__buf)
    def read(self, size=-1):
        while size < 0 or len(self.__buf) < size:
            s = self.__input(size)
            if not s:
                self.__gzip.close()
                break
            self.__gzip.write(s)
        return self.__buf.read(size)
    def __len__(self): return 1#len(self.__buf)