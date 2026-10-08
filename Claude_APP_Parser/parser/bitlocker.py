"""BitLocker 볼륨 잠금 해제.

팀 공통 방식을 그대로 따른다 (Claude Web 파서 image/volumes.py, ChatGPT Desktop 파서
cxparser/bitlocker.py 와 같은 감지·해제 순서와 키 형식). 새 키 형식을 만들지 않는다.

  감지   파티션 선두 3~11 바이트의 '-FVE-FS-'
  해제   dissect.fve 의 BDE — 복호화 완료 상태 → clear key(일시 중단 등, 키 불필요) → 받은 키
  연결   복호화 스트림을 pytsk3.Img_Info 로 노출한다. 그 위에 FS_Info 를 그대로 올리므로
         vfs · usn 은 암호화 여부를 모른다.

키 형식: recovery:<48자리 복구 키> | passphrase:<암호> | bek:<.BEK 경로> | fvek:<hex>
환경변수 ERELM_KEY_MATERIAL 로도 받는다 (명령행 기록에 남기지 않을 때).

키 값은 어디에도 남기지 않는다. 예외 메시지·경고·결과 파일에는 "어떤 종류의 키로
시도했는가" 와 보호자 목록만 들어간다. 키가 없으면 잠김으로 돌려보내고, 무차별
대입이나 우회는 하지 않는다.

자체 점검: python -m parser.bitlocker
"""

import io

import pytsk3

from .errors import VolumeLockedError

SIGNATURE = b"-FVE-FS-"
KEY_KINDS = ("recovery", "passphrase", "bek", "fvek")
KEY_ENV = "ERELM_KEY_MATERIAL"     # 팀 공용 환경변수 — 파서 이름을 넣지 않는다


def is_bitlocker(img, offset):
    """파티션 선두가 BitLocker 인가. 읽지 못하면 False — 판정을 만들어 내지 않는다."""
    try:
        return img.read(offset, 512)[3:11] == SIGNATURE
    except (OSError, RuntimeError):
        return False


def key_kind(key_material):
    """키 종류 이름만 (값 제외). 형식이 맞지 않으면 None."""
    kind, _, value = (key_material or "").partition(":")
    return kind if value and kind in KEY_KINDS else None


class _PartitionFile:
    """TSK 이미지의 한 파티션을 dissect 가 읽을 파일 객체로 (읽기 전용)."""

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

    dissect 는 16바이트 블록마다 파이썬으로 돌아 약 5MB/s 다. 이 파서는 미할당 MFT
    엔트리와 $UsnJrnl 까지 읽어서 그대로 두면 이미지 하나에 수 분이 더 걸린다.
    한 번에 받은 섹터들의 트윅을 큰 정수 하나에 128비트 레인으로 담아 GF(2^128)
    배가를 한꺼번에 하고, AES 는 ECB 한 번으로 처리한다. 팀 ChatGPT Desktop 파서와
    같은 구현이며 demo() 가 dissect 결과와 바이트 단위로 대조한다.
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
        ivs = b"".join((sector + i).to_bytes(8, "little") + bytes(8) for i in range(n))  # plain64
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
    """AES-XTS(Windows 10 이후 기본)면 빠른 복호화로 바꿔 끼운다. 그 외·실패는 dissect 그대로."""
    try:
        from dissect.fve.crypto._pycryptodome import XtsMode
        from dissect.fve.crypto.base import Plain64
        c = stream.cipher
        if (isinstance(c, XtsMode) and isinstance(c.iv_mode, Plain64)
                and c.iv_sector_size == c.sector_size):
            stream.cipher = _FastXts(c)
    except Exception:  # noqa: BLE001 — 속도만 포기한다
        pass


def open_volume(img, offset, size, key_material=None):
    """BitLocker 파티션 -> (복호화된 TSK 이미지, 해제 방법, 보호자 목록). 못 풀면 VolumeLockedError."""
    try:
        from dissect.fve.bde import BDE
    except ImportError as exc:
        raise VolumeLockedError("BitLocker 볼륨을 풀려면 dissect.fve 가 필요합니다 "
                                "(pip install -r requirements.txt)", missing=str(exc))
    try:
        bde = BDE(_PartitionFile(img, offset, size))
        protectors = {"clear_key": bool(bde.has_clear_key()),
                      "recovery_password": bool(bde.has_recovery_password()),
                      "passphrase": bool(bde.has_passphrase()),
                      "bek": bool(bde.has_bek())}
    except Exception as exc:  # noqa: BLE001 — 라이브러리 예외 종류가 다양하다
        raise VolumeLockedError("BitLocker 메타데이터를 읽을 수 없습니다: %s" % _short(exc))

    method, clear_error = None, None
    if bde.unlocked:
        method = "decrypted_state"             # 복호화 완료 상태 — 헤더만 BitLocker 형식
    elif protectors["clear_key"]:
        try:
            bde.unlock_with_clear_key()
            method = "clear_key"
        except Exception as exc:  # noqa: BLE001 — 받은 키로 다시 시도한다
            clear_error = _short(exc)

    if method is None:
        kind, _, value = (key_material or "").partition(":")
        if not value:
            raise VolumeLockedError(
                "BitLocker 볼륨이 잠겨 있습니다 — 키가 필요합니다 (--key-material 또는 "
                "환경변수 %s)" % KEY_ENV,
                protectors=protectors, clear_key_error=clear_error)
        if kind not in KEY_KINDS:
            raise VolumeLockedError(
                "--key-material 은 recovery: / passphrase: / bek: / fvek: 로 시작해야 합니다",
                protectors=protectors)
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
        except Exception as exc:  # noqa: BLE001 — 키 값은 메시지에 넣지 않는다
            raise VolumeLockedError(
                "받은 키(%s)로 BitLocker 볼륨을 풀지 못했습니다: %s"
                % (kind, _short(exc, secret=value)),
                protectors=protectors, key_kind=kind)
        method = kind

    stream = bde.open()
    _speed_up(stream)
    return _PlainImgInfo(stream), method, protectors


def _short(exc, secret=None):
    """예외 요약 한 줄. 라이브러리가 키를 메시지에 되풀이해도 결과에 남지 않게 지운다."""
    s = ("%s: %s" % (type(exc).__name__, exc)).splitlines()[0][:200]
    if secret:
        s = s.replace(secret, "<key>")
    return s


def demo():
    import os

    from dissect.fve.crypto import create_cipher
    for bits, key_len in ((128, 32), (256, 64)):               # 빠른 XTS == dissect XTS
        slow = create_cipher("aes-xts-%d-plain64" % bits, os.urandom(key_len),
                             sector_size=512, iv_sector_size=512)
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
    assert f.seek(-8, io.SEEK_END) == 1016 and f.read() == FakeImg.data[1528:1536]
    assert f.read(1) == b""
    assert is_bitlocker(FakeImg(), 0) is False
    assert key_kind("recovery:1-2") == "recovery" and key_kind("fvek:") is None
    assert key_kind("password:x") is None
    print("bitlocker demo ok")


if __name__ == "__main__":
    demo()
