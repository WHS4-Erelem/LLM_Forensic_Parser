"""BitLocker 볼륨 잠금 해제 — Claude Web 파서(image/volumes.py)의 방식을 pytsk3 에 맞춰 옮긴 것.

파티션 선두의 '-FVE-FS-' 로 BitLocker 를 알아보고 dissect.fve 로 푼 뒤, 복호화 스트림을 TSK 이미지로 노출한다.
그 위에 pytsk3.FS_Info 를 그대로 올리므로 나머지 코드(vfs · usn)는 암호화 여부를 모른다.

해제 순서: 복호화 완료 상태 → clear key(일시 중단 · 장치 암호화 활성화 대기, 키 불필요) → 받은 키.
키 형식(Claude Web 과 같음): recovery:<48자리 복구 키> | passphrase:<암호> | bek:<.BEK 경로> | fvek:<hex>
키 값은 결과·로그에 남기지 않는다 (해제 방법 이름만 남긴다).

자체 점검: python -m cxparser.bitlocker
"""

import io

import pytsk3

from .errors import VolumeLockedError

SIGNATURE = b"-FVE-FS-"
KEY_KINDS = ("recovery", "passphrase", "bek", "fvek")


def is_bitlocker(img, offset):
    try:
        return img.read(offset, 512)[3:11] == SIGNATURE
    except (OSError, RuntimeError):
        return False


class _PartitionFile:
    """TSK 이미지의 한 파티션을 dissect 가 읽을 파일 객체로."""

    def __init__(self, img, offset, size):
        self._img, self._offset, self.size, self._pos = img, offset, size, 0

    def seek(self, pos, whence=io.SEEK_SET):
        self._pos = max(0, pos + (0, self._pos, self.size)[whence])
        return self._pos

    def tell(self):
        return self._pos

    def read(self, n=-1):
        left = self.size - self._pos
        n = left if n is None or n < 0 else min(n, left)
        if n <= 0:
            return b""
        data = self._img.read(self._offset + self._pos, n)
        self._pos += len(data)
        return data


class _PlainImgInfo(pytsk3.Img_Info):
    """복호화 스트림을 TSK 이미지로 노출 (볼륨 하나 = 오프셋 0 에서 시작하는 이미지)."""

    def __init__(self, stream):
        self._s = stream
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        pass

    def read(self, offset, size):
        self._s.seek(offset)
        return self._s.read(size)

    def get_size(self):
        return self._s.size


class _FastXts:
    """dissect.fve 의 AES-XTS 복호화와 같은 결과를 섹터 묶음 단위로 계산한다.

    dissect 는 16바이트 블록마다 파이썬으로 돌아 약 5MB/s 다. 이 파서는 한 이미지에서 3GB 쯤 읽으므로
    (미할당 MFT 엔트리·USN 저널) 그대로 쓰면 10분 가까이 걸린다. 여기서는 한 번에 받은 섹터들의 트윅을
    큰 정수 하나에 128비트 레인으로 담아 GF(2^128) 배가를 한꺼번에 하고, AES 는 ECB 한 번으로 처리한다.
    demo() 가 dissect 결과와 바이트 단위로 대조한다.
    """

    def __init__(self, slow):
        from Crypto.Cipher import AES
        from Crypto.Util.strxor import strxor
        self._slow, self._size, self._xor = slow, slow.sector_size, strxor
        half = slow.block_size
        self._aes = AES.new(slow.key[:half], AES.MODE_ECB)
        self._tweak = AES.new(slow.key[half:], AES.MODE_ECB)
        self._n = 0

    def decrypt(self, data, sector=0, output=None):
        size = self._size
        n = len(data) // size
        if output is not None or n == 0 or len(data) % size or size % 16:
            return self._slow.decrypt(data, sector, output)
        if n != self._n:                       # 레인별 마스크 (섹터 수가 같으면 재사용)
            self._n = n
            self._low = int.from_bytes(((1 << 127) - 1).to_bytes(16, "little") * n, "little")
            self._one = int.from_bytes((1).to_bytes(16, "little") * n, "little")
        ivs = b"".join((sector + i).to_bytes(8, "little") + bytes(8) for i in range(n))    # plain64
        x = int.from_bytes(self._tweak.encrypt(ivs), "little")
        tweaks = bytearray(len(data))
        for j in range(size // 16):            # j번째 블록의 트윅을 모든 섹터에 대해 한꺼번에
            xb = x.to_bytes(16 * n, "little")
            for k in range(16):
                tweaks[j * 16 + k::size] = xb[k::16]
            x = ((x & self._low) << 1) ^ (((x >> 127) & self._one) * 0x87)
        tweaks = bytes(tweaks)
        return self._xor(self._aes.decrypt(self._xor(bytes(data), tweaks)), tweaks)


def _speed_up(stream):
    """AES-XTS(Windows 10 이후 기본)면 빠른 복호화로 바꿔 끼운다. 그 외 방식·준비 실패는 dissect 그대로."""
    try:
        from dissect.fve.crypto._pycryptodome import XtsMode
        from dissect.fve.crypto.base import Plain64
        c = stream.cipher
        if isinstance(c, XtsMode) and isinstance(c.iv_mode, Plain64) and c.iv_sector_size == c.sector_size:
            stream.cipher = _FastXts(c)
    except Exception:  # 속도만 포기한다
        pass


def open_volume(img, offset, size, key_material=None):
    """BitLocker 파티션 → (복호화된 TSK 이미지, 해제 방법 이름). 못 풀면 VolumeLockedError."""
    try:
        from dissect.fve.bde import BDE
    except ImportError as exc:
        raise VolumeLockedError("BitLocker 볼륨을 풀려면 dissect.fve 가 필요합니다 (requirements.txt)",
                                missing=str(exc))
    try:
        bde = BDE(_PartitionFile(img, offset, size))
        protectors = {"clear_key": bde.has_clear_key(), "recovery_password": bde.has_recovery_password(),
                      "passphrase": bde.has_passphrase(), "bek": bde.has_bek()}
    except Exception as exc:
        raise VolumeLockedError("BitLocker 메타데이터를 읽을 수 없습니다: %s" % _short(exc))

    method, clear_error = None, None
    if bde.unlocked:
        method = "decrypted_state"             # 복호화 완료 상태 — 헤더만 BitLocker 형식
    elif protectors["clear_key"]:
        try:
            bde.unlock_with_clear_key()
            method = "clear_key"
        except Exception as exc:  # 받은 키로 다시 시도한다
            clear_error = _short(exc)
    if method is None:
        kind, _, value = (key_material or "").partition(":")
        if not value:
            raise VolumeLockedError("BitLocker 볼륨이 잠겨 있습니다 — 키가 필요합니다 (--key-material)",
                                    protectors=protectors, clear_key_error=clear_error)
        if kind not in KEY_KINDS:
            raise VolumeLockedError("--key-material 은 recovery: / passphrase: / bek: / fvek: 로 시작해야 합니다")
        try:
            if kind == "recovery":
                bde.unlock_with_recovery_password(value)
            elif kind == "passphrase":
                bde.unlock_with_passphrase(value)
            elif kind == "bek":
                with open(value, "rb") as fh:
                    bde.unlock_with_bek(fh)
            else:
                bde.unlock_with_fvek(bytes.fromhex(value))
        except Exception as exc:
            raise VolumeLockedError("받은 키(%s)로 BitLocker 볼륨을 풀지 못했습니다: %s" % (kind, _short(exc)),
                                    protectors=protectors)
        method = kind
    stream = bde.open()
    _speed_up(stream)
    return _PlainImgInfo(stream), method


def _short(exc):
    return ("%s: %s" % (type(exc).__name__, exc)).splitlines()[0][:200]


def demo():
    import os

    from dissect.fve.crypto import create_cipher
    for bits, key_len in ((128, 32), (256, 64)):               # 빠른 XTS == dissect XTS
        slow = create_cipher("aes-xts-%d-plain64" % bits, os.urandom(key_len), sector_size=512, iv_sector_size=512)
        fast = _FastXts(slow)
        for sectors, first in ((1, 0), (128, 12345), (300, 2 ** 33 + 5)):
            buf = os.urandom(512 * sectors)
            assert fast.decrypt(buf, first) == slow.decrypt(buf, first), (bits, sectors)

    class FakeImg:                                             # 파티션 창: 오프셋 보정, 끝에서 잘림
        data = bytes(range(256)) * 8

        def read(self, offset, size):
            return self.data[offset:offset + size]
    f = _PartitionFile(FakeImg(), 512, 1024)
    assert f.read(4) == FakeImg.data[512:516] and f.tell() == 4
    assert f.seek(-8, io.SEEK_END) == 1016 and f.read() == FakeImg.data[1528:1536] and f.read(1) == b""
    assert is_bitlocker(FakeImg(), 0) is False
    print("bitlocker demo ok")


if __name__ == "__main__":
    demo()
