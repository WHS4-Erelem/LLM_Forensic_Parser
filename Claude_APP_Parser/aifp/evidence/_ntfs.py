"""
NTFS $MFT 파서.

오프라인 분석용으로 작성·검증한 독립 모듈을 그대로 편입했다.
읽기 전용으로만 동작하며 어떤 경로에도 쓰지 않는다.
"""

"""Minimal read-only NTFS parser: MFT records, attributes, runlists, path resolution."""
import struct, datetime


def filetime(v):
    if v == 0:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)
    except Exception:
        return None


def fmt(dt):
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] if dt else ''


def fixup(buf, bps):
    if len(buf) < 48:
        return buf
    uso, usc = struct.unpack_from("<HH", buf, 4)
    arr = buf[uso:uso + 2 * usc]
    if len(arr) < 2 * usc:
        return buf
    b = bytearray(buf)
    for i in range(1, usc):
        off = i * bps - 2
        if off + 2 > len(b):
            break
        b[off:off + 2] = arr[2 * i:2 * i + 2]
    return bytes(b)


def decode_runs(data, off=0):
    runs = []
    lcn = 0
    i = off
    while i < len(data):
        h = data[i]
        if h == 0:
            break
        lsz, osz = h & 0x0F, (h >> 4) & 0x0F
        i += 1
        if lsz == 0 or i + lsz + osz > len(data):
            break
        ln = int.from_bytes(data[i:i + lsz], 'little')
        i += lsz
        if osz:
            o = int.from_bytes(data[i:i + osz], 'little', signed=True)
            i += osz
            lcn += o
            runs.append((lcn, ln))
        else:
            runs.append((None, ln))
    return runs


class Attr:
    __slots__ = ('type', 'name', 'resident', 'data', 'runs', 'alloc_size',
                 'real_size', 'flags', 'init_size', 'start_vcn')

    def __init__(self):
        self.type = 0
        self.name = ''
        self.resident = True
        self.data = b''
        self.runs = []
        self.alloc_size = 0
        self.real_size = 0
        self.flags = 0
        self.init_size = 0
        self.start_vcn = 0


def parse_attrs(rec):
    off = struct.unpack_from("<H", rec, 20)[0]
    out = []
    while off + 4 <= len(rec):
        atype = struct.unpack_from("<I", rec, off)[0]
        if atype == 0xFFFFFFFF:
            break
        if off + 16 > len(rec):
            break
        alen = struct.unpack_from("<I", rec, off + 4)[0]
        if alen == 0 or off + alen > len(rec):
            break
        a = Attr()
        a.type = atype
        nonres = rec[off + 8]
        nlen = rec[off + 9]
        noff = struct.unpack_from("<H", rec, off + 10)[0]
        a.flags = struct.unpack_from("<H", rec, off + 12)[0]
        if nlen:
            a.name = rec[off + noff:off + noff + 2 * nlen].decode('utf-16le', 'replace')
        if nonres == 0:
            a.resident = True
            dlen, doff = struct.unpack_from("<IH", rec, off + 16)
            a.data = rec[off + doff:off + doff + dlen]
            a.real_size = dlen
            a.alloc_size = dlen
        else:
            a.resident = False
            a.start_vcn = struct.unpack_from("<Q", rec, off + 16)[0]
            a.alloc_size, a.real_size, a.init_size = struct.unpack_from("<QQQ", rec, off + 40)
            roff = struct.unpack_from("<H", rec, off + 32)[0]
            a.runs = decode_runs(rec[off:off + alen], roff)
        out.append(a)
        off += alen
    return out


class Entry:
    __slots__ = ('ref', 'seq', 'in_use', 'is_dir', 'parent', 'name', 'name_ns', 'si', 'fn',
                 'size', 'alloc', 'streams', 'base_ref', 'path')

    def __init__(self):
        self.ref = 0
        self.seq = 0
        self.in_use = False
        self.is_dir = False
        self.parent = 0
        self.name = ''
        self.name_ns = 0
        self.si = (None, None, None, None)
        self.fn = (None, None, None, None)
        self.size = 0
        self.alloc = 0
        self.streams = []
        self.base_ref = 0
        self.path = None


class NTFS:
    def __init__(self, vol):
        self.v = vol
        bs = vol.read(0, 512)
        self.bps = struct.unpack_from("<H", bs, 11)[0]
        spc = bs[13]
        self.spc = spc if spc < 0x80 else 1 << (256 - spc)
        self.total_sectors = struct.unpack_from("<Q", bs, 40)[0]
        self.mft_lcn = struct.unpack_from("<Q", bs, 48)[0]
        c = bs[64]
        self.cluster = self.spc * self.bps
        self.rec_size = c * self.cluster if c < 0x80 else 1 << (256 - c)
        self.mft_runs = None
        self._bootstrap()

    def _bootstrap(self):
        off = self.mft_lcn * self.cluster
        rec = fixup(self.v.read(off, self.rec_size), self.bps)
        attrs = parse_attrs(rec)
        data = [a for a in attrs if a.type == 0x80 and a.name == '']
        if not data:
            raise ValueError("no $DATA on $MFT")
        self.mft_runs = list(data[0].runs)
        self.mft_size = data[0].real_size
        al = [a for a in attrs if a.type == 0x20]
        if al:
            self._extend_mft_runs(al[0])
        self.num_records = self.mft_size // self.rec_size

    def _read_runs(self, runs, size=None):
        out = bytearray()
        for lcn, ln in runs:
            n = ln * self.cluster
            if lcn is None:
                out += b'\0' * n
            else:
                got = 0
                CH = 8 * 1024 * 1024
                while got < n:
                    k = min(CH, n - got)
                    out += self.v.read(lcn * self.cluster + got, k)
                    got += k
            if size is not None and len(out) >= size:
                break
        if size is not None:
            return bytes(out[:size])
        return bytes(out)

    def _extend_mft_runs(self, al):
        raw = al.data if al.resident else self._read_runs(al.runs, al.real_size)
        i = 0
        extra = []
        while i + 26 <= len(raw):
            atype, rlen = struct.unpack_from("<IH", raw, i)
            if rlen == 0:
                break
            if atype == 0x80:
                ref = struct.unpack_from("<Q", raw, i + 16)[0] & 0xFFFFFFFFFFFF
                extra.append(ref)
            i += rlen
        for ref in sorted(set(extra)):
            if ref == 0:
                continue
            rec = self.record_raw(ref)
            if rec is None:
                continue
            for a in parse_attrs(rec):
                if a.type == 0x80 and a.name == '' and not a.resident:
                    self.mft_runs = self.mft_runs + a.runs

    def _mft_offset(self, ref):
        want = ref * self.rec_size
        pos = 0
        for lcn, ln in self.mft_runs:
            n = ln * self.cluster
            if pos <= want < pos + n:
                if lcn is None:
                    return None
                return lcn * self.cluster + (want - pos)
            pos += n
        return None

    def record_raw(self, ref):
        off = self._mft_offset(ref)
        if off is None:
            return None
        rec = self.v.read(off, self.rec_size)
        if rec[:4] != b'FILE':
            return None
        return fixup(rec, self.bps)

    def read_mft(self):
        pos = 0
        for lcn, ln in self.mft_runs:
            n = ln * self.cluster
            if lcn is None:
                pos += n
                continue
            base = lcn * self.cluster
            done = 0
            CH = 8 * 1024 * 1024
            while done < n:
                sz = min(CH, n - done)
                buf = self.v.read(base + done, sz)
                for k in range(0, sz, self.rec_size):
                    ref = (pos + done + k) // self.rec_size
                    r = buf[k:k + self.rec_size]
                    if r[:4] == b'FILE':
                        yield ref, fixup(r, self.bps)
                done += sz
            pos += n

    @staticmethod
    def parse_entry(ref, rec):
        e = Entry()
        e.ref = ref
        e.seq = struct.unpack_from("<H", rec, 16)[0]
        flags = struct.unpack_from("<H", rec, 22)[0]
        e.in_use = bool(flags & 1)
        e.is_dir = bool(flags & 2)
        e.base_ref = struct.unpack_from("<Q", rec, 32)[0] & 0xFFFFFFFFFFFF
        best = -1
        for a in parse_attrs(rec):
            if a.type == 0x10 and a.resident and len(a.data) >= 32:
                cr, mo, mft, ac = struct.unpack_from("<QQQQ", a.data, 0)
                e.si = (filetime(cr), filetime(mo), filetime(mft), filetime(ac))
            elif a.type == 0x30 and a.resident and len(a.data) >= 66:
                par = struct.unpack_from("<Q", a.data, 0)[0] & 0xFFFFFFFFFFFF
                cr, mo, mft, ac = struct.unpack_from("<QQQQ", a.data, 8)
                nlen = a.data[64]
                ns = a.data[65]
                nm = a.data[66:66 + 2 * nlen].decode('utf-16le', 'replace')
                score = {0: 3, 1: 2, 3: 3, 2: 1}.get(ns, 0)
                if score > best:
                    best = score
                    e.name = nm
                    e.parent = par
                    e.name_ns = ns
                    e.fn = (filetime(cr), filetime(mo), filetime(mft), filetime(ac))
            elif a.type == 0x80:
                e.streams.append((a.name, a.real_size, a.resident))
                if a.name == '':
                    if a.start_vcn == 0:
                        e.size = max(e.size, a.real_size)
                        e.alloc = max(e.alloc, a.alloc_size)
        return e

    def data_of(self, rec, stream=''):
        parts = []
        total = None
        for a in parse_attrs(rec):
            if a.type == 0x80 and a.name == stream:
                if a.resident:
                    return a.data
                if a.start_vcn == 0:
                    total = a.real_size
                parts.append(a)
        if not parts:
            return None
        parts.sort(key=lambda a: a.start_vcn)
        runs = []
        for a in parts:
            runs.extend(a.runs)
        return self._read_runs(runs, total)


    def full_attrs(self, ref, rec=None):
        """Attributes of a base record merged with all its extension records."""
        if rec is None:
            rec = self.record_raw(ref)
        if rec is None:
            return []
        attrs = parse_attrs(rec)
        refs = set()
        for a in attrs:
            if a.type == 0x20:
                raw = a.data if a.resident else self._read_runs(a.runs, a.real_size)
                i = 0
                while i + 26 <= len(raw):
                    atype, rlen = struct.unpack_from("<IH", raw, i)
                    if rlen == 0:
                        break
                    r = struct.unpack_from("<Q", raw, i + 16)[0] & 0xFFFFFFFFFFFF
                    if r != ref:
                        refs.add(r)
                    i += rlen
        for r in sorted(refs):
            er = self.record_raw(r)
            if er is not None:
                attrs.extend(parse_attrs(er))
        return attrs

    def stream_runs(self, attrs, stream=''):
        """-> (runs, real_size, resident_data or None)"""
        parts = [a for a in attrs if a.type == 0x80 and a.name == stream]
        if not parts:
            return None, None, None
        res = [a for a in parts if a.resident]
        if res:
            return None, res[0].real_size, res[0].data
        parts.sort(key=lambda a: a.start_vcn)
        total = None
        for a in parts:
            if a.start_vcn == 0:
                total = a.real_size
        if total is None:
            total = max(a.real_size for a in parts)
        runs = []
        for a in parts:
            runs.extend(a.runs)
        return runs, total, None

    def read_stream(self, attrs, stream=''):
        runs, total, res = self.stream_runs(attrs, stream)
        if runs is None and res is None:
            return None
        if res is not None:
            return res
        return self._read_runs(runs, total)

