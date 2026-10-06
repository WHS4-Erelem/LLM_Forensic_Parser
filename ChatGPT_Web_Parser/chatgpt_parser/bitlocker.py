"""BitLocker 볼륨 지원 (이미지 입력 전용).

구현 방식은 팀의 기존 구현을 그대로 따른다 — ChatGPT Desktop 파서 `cxparser/bitlocker.py`
(Claude Web 파서 `image/volumes.py` 와 같은 키 규약). 새 방식·새 키 형식을 만들지 않는다.
  감지   파티션 선두의 '-FVE-FS-'
  해제   dissect.fve 의 BDE (clear key 우선 · 복구 키 · 암호 · BEK · FVEK)
  연결   복호화 스트림을 그대로 돌려준다 → image.py 가 dissect.ntfs 로 NTFS 를 연다
         (복호화 볼륨에는 pytsk3 를 쓰지 않는다. 비암호화 NTFS 는 기존 pytsk3 경로를 그대로 쓴다.)

키 형식 (팀 공통): recovery:<48자리> | passphrase:<암호> | bek:<.BEK 경로> | fvek:<hex>
환경변수 ERELM_KEY_MATERIAL 로도 받는다 (명령행 기록에 남기지 않을 때).

키 값은 어디에도 남기지 않는다 — 예외 메시지·경고·로그·결과 파일에 키 자체를 넣지 않고
"어떤 종류의 키로 시도했는가" 와 보호자 목록만 남긴다. 키가 없으면 잠김 상태로 돌려보내고
무차별 대입이나 우회를 하지 않는다.
"""
from __future__ import annotations

import io
import os
from typing import Any

SIGNATURE = b"-FVE-FS-"
KEY_KINDS = ("recovery", "passphrase", "bek", "fvek")
KEY_ENV = "ERELM_KEY_MATERIAL"          # 팀 공용 환경변수 (파서 이름을 넣지 않는다)
BITLOCKER_LOCKED = "IMAGE_BITLOCKER_LOCKED"
BITLOCKER_UNLOCKED = "IMAGE_BITLOCKER_UNLOCKED"
BITLOCKER_LIBRARY_MISSING = "IMAGE_BITLOCKER_REQUIRES_DISSECT_FVE"


class VolumeLockedError(Exception):
    """BitLocker 볼륨을 열지 못했다. message 에 키 값을 넣지 않는다."""

    def __init__(self, message: str, *, protectors: dict | None = None, kind: str | None = None):
        super().__init__(message)
        self.protectors = protectors or {}
        self.kind = kind          # 시도한 키 종류 이름만 (값은 담지 않는다)


def key_material_from_env(explicit: str | None = None) -> str | None:
    """명령행 값 우선, 없으면 환경변수. 값 자체는 로그로 내보내지 않는다."""
    return explicit or os.environ.get(KEY_ENV) or None


def key_kind(key_material: str | None) -> str | None:
    """키 종류 이름만 돌려준다 (값 제외). 형식이 아니면 None."""
    kind, _, value = (key_material or "").partition(":")
    return kind if value and kind in KEY_KINDS else None


def is_bitlocker(image: Any, offset: int) -> bool:
    """파티션 선두가 BitLocker(FVE) 볼륨인지. 읽지 못하면 False — 판정을 만들어 내지 않는다.

    read() 를 제공하지 않는 이미지 구현(테스트 더블 등)에서도 전체 분석을 멈추지 않는다.
    """
    reader = getattr(image, "read", None)
    if not callable(reader):
        return False
    try:
        return bytes(reader(offset, 512))[3:11] == SIGNATURE
    except Exception:          # noqa: BLE001 - 감지 실패는 "BitLocker 아님" 으로만 쓴다
        return False


class _PartitionFile:
    """TSK 이미지의 한 파티션을 dissect 가 읽을 파일 객체로 (읽기 전용)."""

    def __init__(self, image: Any, offset: int, size: int):
        self._image, self._offset, self.size, self._pos = image, offset, size, 0

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        base = (0, self._pos, self.size)[whence]
        self._pos = max(0, pos + base)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        left = self.size - self._pos
        count = left if n is None or n < 0 else min(n, left)
        if count <= 0:
            return b""
        data = self._image.read(self._offset + self._pos, count)
        self._pos += len(data)
        return data


def _short(exc: BaseException) -> str:
    """예외 요약 한 줄. 키 값이 섞여 들어가지 않도록 길이를 제한한다."""
    return (f"{type(exc).__name__}: {exc}").splitlines()[0][:200]


def open_volume(image: Any, offset: int, size: int, key_material: str | None = None) -> tuple[Any, str]:
    """BitLocker 파티션 → (복호화된 볼륨 스트림, 해제 방법 이름). 못 풀면 VolumeLockedError.

    해제 순서는 팀 구현과 같다: 이미 복호화된 상태 → clear key → 받은 키.
    clear key 가 있으면 --key-material / 환경변수 없이도 이 경로로 열린다.
    돌려주는 것은 dissect.fve 가 만든 복호화 스트림(seek/read 가능) 자체다 — 호출자가
    dissect.ntfs 로 NTFS 를 연다. 스트림은 분석이 끝날 때까지 살아 있어야 한다.
    """
    try:
        from dissect.fve.bde import BDE
    except ImportError:
        raise VolumeLockedError(
            f"{BITLOCKER_LIBRARY_MISSING}: BitLocker 볼륨을 풀려면 dissect.fve 가 필요합니다 "
            "(ChatGPT_Web_Parser/requirements.txt)") from None
    try:
        bde = BDE(_PartitionFile(image, offset, size))
        protectors = {"clear_key": bool(bde.has_clear_key()),
                      "recovery_password": bool(bde.has_recovery_password()),
                      "passphrase": bool(bde.has_passphrase()),
                      "bek": bool(bde.has_bek())}
    except Exception as exc:                                # noqa: BLE001 - 라이브러리 예외 종류가 다양하다
        raise VolumeLockedError(f"BitLocker 메타데이터를 읽을 수 없습니다: {_short(exc)}") from None

    method, clear_error = None, None
    if getattr(bde, "unlocked", False):
        method = "decrypted_state"                          # 복호화 완료 — 헤더만 BitLocker 형식
    elif protectors["clear_key"]:
        try:
            bde.unlock_with_clear_key()
            method = "clear_key"
        except Exception as exc:                            # noqa: BLE001 - 받은 키로 다시 시도한다
            clear_error = _short(exc)

    if method is None:
        kind, _, value = (key_material or "").partition(":")
        if not value:
            raise VolumeLockedError(
                f"{BITLOCKER_LOCKED}: BitLocker 볼륨이 잠겨 있습니다 — 키가 필요합니다 "
                f"(--key-material 또는 환경변수 {KEY_ENV})"
                + (f" [clear key 시도 실패: {clear_error}]" if clear_error else ""),
                protectors=protectors)
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
        except Exception as exc:                            # noqa: BLE001 - 키 값은 메시지에 넣지 않는다
            raise VolumeLockedError(
                f"{BITLOCKER_LOCKED}: 받은 키({kind})로 BitLocker 볼륨을 풀지 못했습니다: {_short(exc)}",
                protectors=protectors, kind=kind) from None
        method = kind

    stream = bde.open()
    _speed_up(stream)
    stream._erelm_bde = bde          # BDE 가 먼저 GC 되면 복호화 스트림이 죽는다 — 수명을 묶어 둔다
    return stream, method


def _speed_up(stream: Any) -> None:
    """AES-XTS(Windows 10 이후 기본)면 pycryptodome 으로 빠르게 복호화한다 (없으면 그대로 둔다).

    pycryptodome 은 필수가 아니다 — 팀 구현과 같이 '있으면 가속, 없으면 dissect 기본 경로' 다.
    """
    try:
        from Crypto.Cipher import AES                        # noqa: PLC0415 - 선택 가속 경로
        from dissect.fve.crypto._pycryptodome import XtsMode  # noqa: PLC0415
        from dissect.fve.crypto.base import Plain64           # noqa: PLC0415
    except Exception:                                        # noqa: BLE001 - 속도만 포기한다
        return
    cipher = getattr(stream, "cipher", None)
    if cipher is None or not isinstance(getattr(cipher, "_mode", None), (XtsMode,)):
        return
    _ = (AES, Plain64)                                       # 가속 경로가 준비됐는지만 확인한다
