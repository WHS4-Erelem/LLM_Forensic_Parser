"""
증거 계층 — 이미지를 열고, 볼륨을 찾고, 무결성을 증명한다.

파서가 지켜야 할 세 가지가 여기서 구현된다.

  **무결성** 이미지를 읽기 전용으로만 열고, 분석 전후 해시를 비교해
            원본이 바뀌지 않았음을 증명한다. 마운트하지 않으므로
            OS가 볼륨에 쓸 일도 없다.

  **가용성** 볼륨 하나가 깨져도 다른 볼륨을 계속 본다. 불량 섹터는
            0으로 채우고 진행하며, 그 사실을 기록한다.

"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..errors import ErrorCollector, InputError
from .container import Container, open_container
from .vfs import Backend, NtfsBackend, VPath

__all__ = ["Evidence", "open_evidence", "VPath", "NtfsBackend"]


@dataclass
class VolumeInfo:
    index: int
    start: int
    size: int
    label: str
    filesystem: str = "unknown"
    mounted: bool = False
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "start": self.start, "size": self.size,
                "label": self.label, "filesystem": self.filesystem,
                "selected": self.mounted, "note": self.note}


class Evidence:
    """
    분석 대상 증거 한 벌.

    image  : 디스크 이미지 (.dd / .E01)
    dir    : 정식 절차로 획득한 파일 사본 — 이미지를 못 뜨는 경우의 대안
    """

    def __init__(self, backend: Backend, errs: ErrorCollector, *,
                 container: Container | None = None,
                 volumes: list[VolumeInfo] | None = None,
                 source: str = "") -> None:
        self.backend = backend
        self.errs = errs
        self.container = container
        self.volumes = volumes or []
        self.source = source
        self.opened_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.closed_utc: str | None = None

    @property
    def root(self) -> VPath:
        return VPath(self.backend, "")

    @property
    def mode(self) -> str:
        return "image" if isinstance(self.backend, NtfsBackend) else "directory"

    # ── 폴더 모드 무결성 ───────────────────────────────────────────────

    # ── 작업 사본 ──────────────────────────────────────────────────────
    def export_dir(self, rel: str, dest: Path, *, max_files: int = 4000,
                   max_bytes: int = 512 * 1024 * 1024) -> Path | None:
        """
        증거에서 하위 트리를 **작업 폴더로 꺼낸다**.

        LevelDB·캐시 리더처럼 실제 파일 경로를 요구하는 외부 라이브러리가 있어서
        필요한 부분만 추출해 그 위에서 파싱한다. 증거 자체는 읽기만 한다.
        산출물의 근거 경로에는 작업 사본이 아니라 **증거 안의 원래 경로**를 적는다.
        """
        src = self.root / rel
        if not src.exists():
            return None
        dest.mkdir(parents=True, exist_ok=True)
        n = total = 0
        stack = [(src, dest)]
        while stack:
            vdir, rdir = stack.pop()
            rdir.mkdir(parents=True, exist_ok=True)
            for child in vdir.iterdir():
                if n >= max_files or total >= max_bytes:
                    self.errs.add("warning", "EXPORT_TRUNCATED", "collect", "evidence",
                                  f"작업 사본 추출 상한 도달 — {rel} 일부만 추출됨")
                    return dest
                if child.is_dir():
                    stack.append((child, rdir / child.name))
                    continue
                try:
                    data = child.read_bytes()
                except (FileNotFoundError, OSError):
                    self.errs.add("warning", "EXPORT_FAILED", "collect", "evidence",
                                  f"추출 실패: {child.rel}")
                    continue
                (rdir / child.name).write_bytes(data)
                n += 1
                total += len(data)
        self.errs.add("info", "EXPORT_OK", "collect", "evidence",
                      f"작업 사본 추출 {rel} — {n}개 파일 {total:,}B")
        return dest

    # ── 무결성 ─────────────────────────────────────────────────────────
    def verify_and_close(self) -> dict[str, Any]:
        """분석 종료 시 해시를 다시 재고 원본 불변을 확인한다."""
        self.closed_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report: dict[str, Any] = {
            "mode": self.mode,
            "source": self.source,
            "opened_utc": self.opened_utc,
            "closed_utc": self.closed_utc,
            "write_capable": False,
            "write_guarantee": ("컨테이너와 VFS에 쓰기 메서드가 존재하지 않는다. "
                                "증거 파일은 'rb'로만 열린다 — 구조적으로 쓰기가 불가능하다"),
            "mounted": False,
            "volumes": [v.to_dict() for v in self.volumes],
        }
        if self.container is not None:
            self.container.hash_close()
            report["container"] = self.container.describe()
            ok = self.container.integrity_ok
            report["integrity_verified"] = ok
            if ok is False:
                self.errs.add("fatal", "INTEGRITY_FAILED", "collect", "evidence",
                              "분석 전후 이미지 해시가 다르다 — 증거가 변조되었을 수 있다. "
                              "결과를 신뢰하지 말 것")
            elif ok:
                self.errs.add("info", "INTEGRITY_OK", "collect", "evidence",
                              "분석 전후 이미지 해시 동일 — 원본 불변 확인")
            self.container.close()
        return report


def identify_filesystem(vol) -> str:
    """
    볼륨의 파일시스템을 식별한다.

    NTFS가 아니어도 **무엇인지는 알려줘야** 조사관이 다음 수를 둘 수 있다.
    "NTFS 없음"만 던지면 이미지가 잘못된 건지 리눅스인지 알 수 없다.
    """
    try:
        boot = vol.read(0, 512)
    except Exception:
        return "읽기 실패"

    oem = boot[3:11]
    if oem == b"NTFS    ":
        return "NTFS"
    if oem[:5] == b"EXFAT":
        return "exFAT"
    if boot[54:59] == b"FAT12":
        return "FAT12"
    if boot[54:59] == b"FAT16":
        return "FAT16"
    if boot[82:87] == b"FAT32":
        return "FAT32"
    if oem[:4] == b"-FVE":
        return "BitLocker(암호화)"

    # ext2/3/4 — 슈퍼블록은 1024바이트 뒤, 매직 0xEF53
    try:
        sb = vol.read(1024, 128)
        if sb[56:58] == b"\x53\xef":
            feat = int.from_bytes(sb[96:100], "little")   # incompat
            kind = "ext4" if feat & 0x40 else "ext3/ext2"
            return kind
    except Exception:
        pass

    # APFS / HFS+
    try:
        blk = vol.read(0, 40)
        if blk[32:36] == b"NXSB":
            return "APFS"
        if blk[:2] in (b"H+", b"HX"):
            return "HFS+"
    except Exception:
        pass

    if oem.strip(b"\x00"):
        return oem.decode("ascii", "replace").strip()
    return "미상"


def _open_ntfs(vol, label: str, errs: ErrorCollector):
    """
    NTFS 볼륨을 연다.

    부트섹터는 NTFS인데 $MFT를 못 읽는 경우가 실제로 있다 —
    볼륨이 손상됐거나, 이미지가 중간에 잘렸거나, 암호화(BitLocker)된 경우다.
    구조체 언팩 오류를 그대로 토해내면 조사관이 원인을 알 수 없으므로
    무엇이 문제인지 말해 준다.
    """
    from . import _ntfs
    try:
        return _ntfs.NTFS(vol)
    except Exception as exc:
        raise InputError(
            f"{label}: NTFS 부트섹터는 확인됐으나 $MFT를 읽지 못했다 ({type(exc).__name__}). "
            f"볼륨이 손상됐거나, 이미지가 잘렸거나, 암호화(BitLocker)됐을 수 있다"
        ) from exc


def _ntfs_candidates(container: Container, errs: ErrorCollector
                     ) -> tuple[list[tuple[VolumeInfo, Any]], list[VolumeInfo]]:
    """
    파티션 표를 읽어 **NTFS 볼륨 후보를 전부** 돌려준다.
    어느 볼륨을 쓸지는 여기서 정하지 않는다 — 고르는 일은 open_evidence 가 한다.
    """
    from .partition import Volume, partitions

    infos: list[VolumeInfo] = []
    candidates: list[tuple[VolumeInfo, Any]] = []

    # ── 0) 볼륨 이미지인지 먼저 본다 ────────────────────────────────────
    # 디스크 이미지가 아니라 파티션 하나만 뜬 이미지가 흔하다.
    # NTFS 부트섹터도 끝에 0x55AA를 달고 있어서 MBR로 오인되므로 이 검사가 먼저다.
    try:
        head = container.read(0, 512)
    except Exception as exc:
        errs.from_exception(exc, "collect", "evidence")
        head = b""

    if head[3:11] == b"NTFS    ":
        info = VolumeInfo(index=0, start=0, size=container.size,
                          label="볼륨 이미지(파티션 표 없음)", filesystem="NTFS")
        errs.add("info", "VOLUME_IMAGE", "collect", "evidence",
                 "이미지 첫 섹터가 NTFS 부트섹터 — 디스크가 아니라 볼륨 이미지로 처리한다")
        return [(info, Volume(container, 0, container.size))], [info]

    # ── 1) 파티션 표 ───────────────────────────────────────────────────
    try:
        parts = partitions(container)
    except Exception as exc:
        errs.from_exception(exc, "collect", "evidence")
        parts = []

    if not parts:
        parts = [(0, 0, container.size, "전체 이미지(파티션 표 없음)")]

    for idx, start, size, label in parts:
        info = VolumeInfo(index=idx, start=start, size=size, label=str(label))
        vol = Volume(container, start, size)
        info.filesystem = identify_filesystem(vol)
        if info.filesystem == "NTFS":
            candidates.append((info, vol))
        else:
            info.note = f"{info.filesystem} — 이 파서는 NTFS만 읽는다"
        infos.append(info)

    # ── 2) 이미지가 잘렸는지 ────────────────────────────────────────────
    # 획득이 중간에 끊긴 이미지(다운로드 미완료·저장공간 부족)가 실제로 온다.
    # 파티션 표가 말하는 디스크 끝보다 파일이 작으면 그 사실을 먼저 알려야 한다.
    # 잘린 범위는 0으로 읽히므로, 모르고 보면 "파일이 없다"로 오해하게 된다.
    disk_end = max((i.start + i.size for i in infos), default=0)
    if disk_end > container.size:
        for i in infos:
            if i.start + i.size > container.size:
                have = max(0, container.size - i.start)
                i.note = ((i.note + " · ") if i.note else "") + (
                    f"이미지가 잘려 이 볼륨의 {have:,}B / {i.size:,}B 만 존재")
        errs.add("warning", "IMAGE_TRUNCATED", "collect", "evidence",
                 f"이미지가 파티션 표가 말하는 디스크보다 작다 — "
                 f"파일 {container.size:,}B / 디스크 {disk_end:,}B, "
                 f"{disk_end - container.size:,}B 누락. 획득이 중단됐거나 파일이 잘린 "
                 f"것으로 보인다. 잘린 범위는 0으로 읽히며 그 영역의 파일은 복원되지 않는다")

    if not candidates:
        if infos:
            found = " / ".join(
                f"#{i.index} {i.filesystem} {i.size / (1 << 30):.1f}GB" for i in infos)
            raise InputError(
                f"이미지에 NTFS 볼륨이 없다. 발견된 파티션: {found}. "
                f"이 파서는 Windows(NTFS)의 Claude Desktop만 분석한다")
        raise InputError("이미지에서 파티션을 찾지 못했다. "
                         "손상됐거나 지원하지 않는 형식일 수 있다")

    return candidates, infos


def _mount_volume(info: VolumeInfo, vol: Any, image_name: str,
                  errs: ErrorCollector) -> NtfsBackend:
    """NTFS 볼륨 하나를 열어 $MFT를 색인한다. (마운트라 부르지만 OS 마운트가 아니다)"""
    label = f"파티션 #{info.index} {info.label}"
    if info.note and "잘려" in info.note:
        label += " (잘린 이미지 — 일부만 존재)"
    fs = _open_ntfs(vol, label, errs)
    backend = NtfsBackend(fs, volume_label=info.label, image_name=image_name)
    errs.add("info", "MFT_INDEXED", "collect", "evidence",
             f"#{info.index} {info.label} — $MFT 색인 완료, 엔트리 "
             f"{len(backend.entries):,}건 (삭제 {len(backend.deleted):,}건 포함)")
    return backend


def _pick_volume(candidates: list[tuple[VolumeInfo, Any]], image_name: str,
                 errs: ErrorCollector, want_index: int | None,
                 probe: Any, probe_label: str) -> tuple[VolumeInfo, NtfsBackend]:
    """
    분석할 NTFS 볼륨을 고른다.

    이미지마다 디스크 구성이 다르다. 사용자 프로필이 가장 큰 볼륨에 있으리란 보장이
    없으므로 **큰 볼륨부터 열어 대상이 실제로 있는지 확인하고** 있는 볼륨을 쓴다.
    어디에도 없으면 가장 큰 볼륨을 분석해 "미검출"을 근거와 함께 남긴다.
    `--volume` 으로 지정하면 그 볼륨만 연다 — 조사관의 지정이 자동 판단보다 우선이다.
    """
    if want_index is not None:
        chosen = next((c for c in candidates if c[0].index == want_index), None)
        if chosen is None:
            found = " / ".join(f"#{i.index}" for i, _ in candidates)
            raise InputError(f"--volume {want_index} 는 NTFS 볼륨이 아니다. "
                             f"NTFS 볼륨: {found}")
        info, vol = chosen
        return info, _mount_volume(info, vol, image_name, errs)

    order = sorted(candidates, key=lambda c: c[0].size, reverse=True)
    fallback: tuple[VolumeInfo, NtfsBackend] | None = None
    failures: list[str] = []

    for pos, (info, vol) in enumerate(order):
        more = pos + 1 < len(order)
        try:
            backend = _mount_volume(info, vol, image_name, errs)
        except InputError as exc:
            # 볼륨 하나가 깨져도 나머지는 계속 본다 (가용성)
            failures.append(str(exc))
            errs.add("warning", "VOLUME_UNREADABLE", "collect", "evidence", str(exc))
            continue

        if probe is None:
            return info, backend
        try:
            hit = bool(probe(backend))
        except Exception as exc:
            errs.from_exception(exc, "collect", "evidence")
            hit = False
        if hit:
            if fallback is not None:
                errs.add("info", "VOLUME_PROBED", "collect", "evidence",
                         f"#{info.index} {info.label} 에서 {probe_label} 흔적 확인 — "
                         f"이 볼륨을 분석한다")
            rest = [f"#{i.index} {i.label}" for i, _ in order[pos + 1:]]
            if rest:
                # 여기서 멈추지 않으면 남은 볼륨의 $MFT 까지 전부 읽어야 한다.
                # 대신 확인하지 않았다는 사실을 분명히 남긴다 — 다른 볼륨에도
                # 같은 앱이 설치돼 있을 수 있고, 그것을 모르고 지나가면 안 된다.
                errs.add("warning", "VOLUME_NOT_PROBED", "collect", "evidence",
                         f"남은 볼륨 {', '.join(rest)} 은 확인하지 않았다 — "
                         f"거기에도 {probe_label} 흔적이 있을 수 있다. "
                         f"보려면 --volume 으로 지정해 다시 실행할 것")
            return info, backend
        errs.add("info", "VOLUME_PROBED", "collect", "evidence",
                 f"#{info.index} {info.label} 에 {probe_label} 앱 루트가 없다"
                 + (" — 다음 볼륨을 본다" if more else ""))
        if fallback is None:
            fallback = (info, backend)

    if fallback is not None:
        info, backend = fallback
        where = "가장 큰 볼륨" if len(order) > 1 else "이 볼륨"
        errs.add("info", "VOLUME_FALLBACK", "collect", "evidence",
                 f"어느 NTFS 볼륨에서도 {probe_label} 앱 루트를 찾지 못했다 — "
                 f"{where} #{info.index} 을 분석하고 미검출로 기록한다")
        return info, backend

    # 전부 실패했다 — 사유를 그대로 전한다. 조사관이 원인을 알아야 다음 수를 둔다.
    if failures:
        raise InputError(" / ".join(failures))
    raise InputError("이미지에서 열 수 있는 NTFS 볼륨을 찾지 못했다")


def open_evidence(source: Path, errs: ErrorCollector, *,
                  mode: str = "auto", volume_index: int | None = None,
                  probe: Any = None, probe_label: str = "대상") -> Evidence:
    """
    증거를 연다.

    입력은 디스크 이미지뿐이다 (.dd / .E01).
    """
    source = Path(source)

    container = open_container(source)
    container.hash_open()                     # 분석 전 해시
    errs.add("info", "EVIDENCE_OPENED", "collect", "evidence",
             f"{container.kind} 이미지 열기 — 파일 {len(container.sources)}개, "
             f"{container.size:,}B, 읽기 전용")

    candidates, volumes = _ntfs_candidates(container, errs)
    if len(candidates) > 1 and volume_index is None:
        errs.add("info", "VOLUME_MULTI", "collect", "evidence",
                 f"NTFS 볼륨 {len(candidates)}개 — 대상이 있는 볼륨을 찾아 고른다 "
                 f"(--volume 으로 직접 지정 가능)")

    sel, backend = _pick_volume(candidates, source.name, errs,
                                volume_index, probe, probe_label)
    sel.mounted = True
    errs.add("info", "VOLUME_SELECTED", "collect", "evidence",
             f"NTFS 볼륨 선택: #{sel.index} {sel.label} ({sel.size:,}B) — 마운트하지 않음")

    return Evidence(backend, errs, container=container, volumes=volumes,
                    source=str(source))
