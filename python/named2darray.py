#!/usr/bin/env python

import struct
import mmap
import os
import sys

"""A 2D array is an array of (x, y, count) tuples.
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
    uint64_t x_bin_width;
    uint64_t y_bin_width;
    uint64_t total_count;
    uint64_t cell_count;
};

struct cell {
    uint64_t    x;
    uint64_t    y;
    uint64_t    count;
};

"""

class Debug(object): pass

DEBUG = Debug()

HDR_FMT = "<256sqqq"
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
            _fmode = "rb+"
            self._write = False
        elif mode == "w":
            _fmode = "ab+"
            self._write = True
        else:
            raise AttributeError("mode canonly be 'r' or 'w'")
        self.mode = mode
        self._hdr = None
        self._hdr_map = None
        self._packed_hdr = None
        self._path = path

        if self._write:
            self._file = open(path, "ab+", 0) # no buffering
            try:
                self._load_hdr()
            except HeaderException:
                self._hdr_init()
                self._load_hdr()
        else:
            # read-only, use mmap ... it is way faster
            self._file = f = open(path, "rb+")
            self._load_hdr()
            fno = f.fileno()
            f.seek(0, 2) # seek to EOF
            sz = f.tell()
            self._file = mmap.mmap(fno, sz, mmap.MAP_SHARED, mmap.PROT_READ)
            f.close()
        self._read_last_cell()

    def __del__(self):
        if self._file:
            self._file.close()
        if self._hdr_map:
            self._hdr_map.close()

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
        self._cell_count = self.get_cell_count()

    def _read_last_cell(self):
        """Get the last cell"""
        f = self._file
        f.seek(-CELL_SZ, 2)
        if f.tell() < HDR_SZ:
            self._last_cell = None
        else:
            c = f.read(CELL_SZ)
            self._last_cell = struct.unpack(CELL_FMT, c)
        if not self._write:
            # position at the first cell
            f.seek(HDR_SZ)
        return self._last_cell

    def _hdr_init(self):
        """Private method, don't call directly"""
        self._hdr = ("", 3600, 1, 0)
        self._write_hdr()

    def _write_hdr(self):
        """A routine to write/update the header"""
        self._packed_hdr = struct.pack(HDR_FMT, *self._hdr)
        self._file.seek(0)
        self._file.write(self._packed_hdr)
        self._file.seek(0, 2) # to the end of file

    def reset(self, x_bin_width = 3600, y_bin_width = 1):
        """Reset the file"""
        self._file.truncate(HDR_SZ)
        self.set_x_bin_width(x_bin_width)
        self.set_y_bin_width(y_bin_width)
        self._set_total_count(0)
        self._set_cell_count(0)
        self._last_cell = None

    def get_name(self):
        self._hdr_map.seek(0)
        s = self._hdr_map.read(256)
        return s

    def set_name(self, name):
        self._hdr_map.seek(0)
        self._hdr_map.write(struct.pack("256s", name))

    def get_x_bin_width(self):
        self._hdr_map.seek(256)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def set_x_bin_width(self, val):
        self._hdr_map.seek(256)
        self._hdr_map.write(struct.pack("<q", val))

    def get_y_bin_width(self):
        self._hdr_map.seek(256 + 8)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def set_y_bin_width(self, val):
        self._hdr_map.seek(256 + 8)
        self._hdr_map.write(struct.pack("<q", val))

    def get_total_count(self):
        self._hdr_map.seek(256 + 2*8)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def _set_total_count(self, val):
        """ This is private."""
        self._total_count = val
        self._hdr_map.seek(256 + 2*8)
        self._hdr_map.write(struct.pack("<q", val))

    def get_cell_count(self):
        self._hdr_map.seek(256 + 3*8)
        s = self._hdr_map.read(8)
        return struct.unpack("<q", s)[0]

    def get_last_cell(self):
        return self._last_cell

    def _set_cell_count(self, val):
        self._cell_count = val
        self._hdr_map.seek(256 + 3*8)
        self._hdr_map.write(struct.pack("<q", val))

    def append(self, x, y, count):
        if self._last_cell and self._last_cell[0:2] >= (x, y):
            # Data out of order
            raise DataOrderException("Trying to append %s after %s" %
                                     (str((x, y, count)),
                                     str(self._last_cell)))
        data = struct.pack(CELL_FMT, x, y, count)
        self._file.seek(0, 2)
        self._file.write(data)
        self._set_total_count(self._total_count + count)
        self._set_cell_count(self._cell_count + 1)

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
        print >>f, "  X-Bin Width:", self.get_x_bin_width()
        print >>f, "  Y-Bin Width:", self.get_y_bin_width()
        print >>f, "  Total Count:", self.get_total_count()
        for p in self:
            print p

    def get(self, i):
        """Get the i-th entry"""
        try:
            self._file.seek(HDR_SZ + i * CELL_SZ)
            s = self._file.read(CELL_SZ)
            if not s:
                raise ValueError()
        except ValueError:
            raise IndexError("Invalid index %d" % i)
        p = struct.unpack(CELL_FMT, s)
        return p

    def seek(self, x, y):
        """Seek to (x, y) element, or the first element greater thant (x, y)."""
        s = (x, y, 0)
        l = 0
        r = self._cell_count - 1
        while l <= r:
            c = (l+r)/2
            p = self.get(c)
            if p[0] == x and p[1] == y:
                # found
                r = c - 1
                break
            if s < p:
                r = c - 1
            else:
                l = c + 1
        self._file.seek(HDR_SZ + (r + 1)*CELL_SZ)

    def next(self):
        """Read a cell from the Named2DArray file."""
        s = self._file.read(CELL_SZ)
        if not s:
            return None
        p = struct.unpack(CELL_FMT, s)
        return p

    def __iter__(self):
        p = self.next()
        while p:
            yield p
            p = self.next()


if __name__ == "__main__":
    # Simple test ...
    a = Named2DArray("test.2da", "w")
    a.reset()
    a.set_name("test_array")
    ts_array = [1502985600, 1502985600+3600, 1502985600 + 2*3600]
    comp_id_array = [256, 257, 258, 259]
    total_count = 0
    i = 10
    for t in ts_array:
        for c in comp_id_array:
            total_count += i
            a.append(t, c, i)
            i += 10
    assert(a.get_total_count() == total_count)
    a.dump()
