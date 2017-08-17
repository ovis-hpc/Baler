#!/usr/bin/env python

import struct
import mmap
import os
import sys

"""A 2D array is a 2-dimensional array of count[time, comp_id].
"""

"""Named2DArray file format described in C structure:

struct Named2DArray {
    union {
        struct header hdr;
        char _[4096]; /* reserved 4K header for future expansion */
    };
    struct cell   data[];
};

struct header {
    char name[256]; /* null-terminated */
    uint64_t time_bin_width;
    uint64_t total_count;
};

struct cell {
    uint64_t    time_stamp;
    uint64_t    comp_id;
    uint64_t    count;
};

"""

class Debug(object): pass

DEBUG = Debug()

HDR_FMT = "<256sqq"
# calculate padding
tmp_sz = struct.calcsize(HDR_FMT)
HDR_FMT = "%s%dx" % (HDR_FMT, 4096 - tmp_sz)
HDR_SZ = struct.calcsize(HDR_FMT)
assert(HDR_SZ == 4096)
CELL_FMT = "<qqq"
CELL_SZ = struct.calcsize(CELL_FMT)

class HeaderException(Exception):
    """Raised when an incomplete header is detected"""
    pass

class DataOrderException(Exception):
    """Raised when trying to append a cell that is out of order"""
    pass

class Named2DArray(object):
    """ Named2DArray(path, mode)

        path - the path to the file
        mode - "r" for read-only, "w" for read+write
    """
    def __init__(self, path, mode="r"):
        if mode == "r":
            self._fmode = "rb+"
        elif mode == "w":
            self._fmode = "ab+"
        else:
            raise AttributeError("mode canonly be 'r' or 'w'")
        self.mode = mode
        self._hdr = None
        self._hdr_map = None
        self._packed_hdr = None
        self._file = open(path, self._fmode, 0) # no buffering
        try:
            self._load_hdr()
        except HeaderException:
            if mode == "w":
                self._hdr_init()
                self._load_hdr()
            else:
                raise
        self._read_last_cell()

    def _load_hdr(self):
        """Load header information"""
        f = self._file
        f.seek(0)
        self._packed_hdr = f.read(HDR_SZ)
        hdr_sz = len(self._packed_hdr)
        if hdr_sz < HDR_SZ:
            raise HeaderException("Header size %d < %d" % (hdr_sz, HDR_SZ))
        try:
            self._hdr = struct.unpack(HDR_FMT, self._packed_hdr)
        except:
            raise HeaderException("Invalid Header")
        finally:
            f.seek(0, 2) # always seek to the end-of-file
        self._hdr_map = mmap.mmap(f.fileno(), HDR_SZ)
        self._total_count = self.get_total_count()

    def _read_last_cell(self):
        """Get the last cell"""
        f = self._file
        f.seek(-CELL_SZ, 2)
        if f.tell() < HDR_SZ:
            self._last_cell = None
        else:
            c = f.read(CELL_SZ)
            self._last_cell = struct.unpack(CELL_FMT, c)
        return self._last_cell

    def _hdr_init(self):
        """Private method, don't call directly"""
        self._hdr = ("", 3600, 0)
        self._write_hdr()

    def _write_hdr(self):
        """A routine to write/update the header"""
        self._packed_hdr = struct.pack(HDR_FMT, *self._hdr)
        self._file.seek(0)
        self._file.write(self._packed_hdr)
        self._file.seek(0, 2) # to the end of file

    def reset(self, time_bin_width = 3600):
        """Reset the file"""
        self._file.truncate(HDR_SZ)
        self.set_time_bin_width(time_bin_width)
        self._set_total_count(0)
        self._last_cell = None

    def get_name(self):
        self._hdr_map.seek(0)
        s = self._hdr_map.read(256)
        return s

    def set_name(self, name):
        self._hdr_map.seek(0)
        self._hdr_map.write(struct.pack("256s", name))

    def get_time_bin_width(self):
        self._hdr_map.seek(256)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def set_time_bin_width(self, val):
        self._hdr_map.seek(256)
        self._hdr_map.write(struct.pack("<q", val))

    def get_total_count(self):
        self._hdr_map.seek(256 + 8)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def _set_total_count(self, val):
        """ This is private."""
        self._total_count = val
        self._hdr_map.seek(256 + 8)
        self._hdr_map.write(struct.pack("<q", val))

    def append(self, ts, comp_id, count):
        if self._last_cell and self._last_cell[0:2] >= (ts, comp_id):
            # Data out of order
            raise DataOrderException("Trying to append %s after %s" %
                                     (str((ts, comp_id, count)),
                                     str(self._last_cell)))
        data = struct.pack(CELL_FMT, ts, comp_id, count)
        # NOTE: Other methods guarantee that self._file is always at EOF.
        self._total_count += count
        self._file.write(data)
        self._set_total_count(self._total_count)

    def verify(self):
        count = 0
        f = self._file
        f.seek(HDR_SZ)
        s = self._file.read(CELL_SZ)
        while len(s) == CELL_SZ:
            p = struct.unpack(CELL_FMT, s)
            count += p[2]
            s = self._file.read(CELL_SZ)
        _count = self.get_total_count()
        if count != self.get_total_count():
            raise Exception("count(%d) != total_count(%d)" %
                            (count, _count))

    def dump(self, f=sys.stdout):
        """Dump Named2DArray information to the given file `f`"""
        print >>f, "Name:", self.get_name()
        print >>f, "  Time Bin Width:", self.get_time_bin_width()
        print >>f, "  Total Count:", self.get_total_count()
        self._file.seek(HDR_SZ)
        s = self._file.read(CELL_SZ)
        while len(s) == CELL_SZ:
            p = struct.unpack(CELL_FMT, s)
            print p
            s = self._file.read(CELL_SZ)


if __name__ == "__main__":
    # Simple test ...
    a = Named2DArray("test.2da", "w")
    a.reset()
    a.set_name("test_array")
    ts_array = [1502985600, 1502985600+3600, 1502985600 + 2*3600]
    comp_id_array = [256, 257, 258, 259]
    total_count = 0
    for t in ts_array:
        for c in comp_id_array:
            total_count += 10
            a.append(t, c, 10)
    assert(a.get_total_count() == total_count)
    a.dump()
