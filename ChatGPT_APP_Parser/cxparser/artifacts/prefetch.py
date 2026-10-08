"""C:\\Windows\\Prefetch\\CODEX.EXE-<해시>.pf — 윈도가 직접 남기는 실행 기록 (E08-01 애플리케이션 실행).

조사(2026-09-23, 평서문 표본): CODEX.EXE-5FD576D9.pf 의 실행 시각 13:16:47 이 앱 로그의 두 번째 프로세스 시작(13:16:47)과 같은 초.
Win10/11 의 .pf 는 MAM 압축(XPRESS Huffman) — 해제는 Windows 의 ntdll.RtlDecompressBufferEx 로만 한다.
다른 OS 에서 돌리면 압축을 풀 수 없어 관찰 레코드만 남긴다 (실행 횟수·시각은 모름).
포맷 v30/v31: 실행 시각 8개 = 오프셋 0x80 부터 FILETIME 8개, 실행 횟수 = 0xC8. v26: 0x80/0x98. v23(Win7): 시각 1개 0x80, 횟수 0x98.
"""

import sys
from datetime import datetime, timedelta, timezone

from .. import events, model

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_LAYOUT = {30: (0x80, 8, 0xC8), 31: (0x80, 8, 0xC8), 26: (0x80, 8, 0x98), 23: (0x80, 1, 0x98)}


def _filetime(v):
    return (_EPOCH + timedelta(microseconds=v / 10)).isoformat(timespec="microseconds").replace("+00:00", "Z") if v else None


def mam_decompress(data):
    """MAM(0x04 = XPRESS Huffman) 헤더가 붙은 .pf 를 푼다. Windows 가 아니거나 실패하면 None."""
    if data[:3] != b"MAM":
        return data
    if sys.platform != "win32":
        return None
    import ctypes
    size = int.from_bytes(data[4:8], "little")
    ntdll = ctypes.WinDLL("ntdll")
    ws, fr = ctypes.c_ulong(0), ctypes.c_ulong(0)
    if ntdll.RtlGetCompressionWorkSpaceSize(ctypes.c_ushort(4), ctypes.byref(ws), ctypes.byref(fr)) != 0:
        return None
    out, final, wsbuf = ctypes.create_string_buffer(size), ctypes.c_ulong(0), ctypes.create_string_buffer(ws.value)
    r = ntdll.RtlDecompressBufferEx(ctypes.c_ushort(4), out, ctypes.c_ulong(size), ctypes.c_char_p(data[8:]),
                                    ctypes.c_ulong(len(data) - 8), ctypes.byref(final), wsbuf)
    return out.raw[:final.value] if r == 0 else None


def parse(vfile, image_desc, rb, max_excerpt=500):
    raw = vfile.read()
    data = mam_decompress(raw)
    if data is None or len(data) < 0x100 or data[4:8] != b"SCCA":
        why = ("MAM 압축 해제 불가 (Windows 에서만 가능)" if data is None and sys.platform != "win32"
               else "Prefetch 서명(SCCA) 이 없거나 해제 실패")
        return [model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"),
            model.timestamp(utc=vfile.si_times.get("modified"), meaning="Prefetch 파일의 MFT 수정 시각 (마지막 실행 무렵)",
                            source=model.TS_SOURCE_MFT),
            model.user_action(observed="Prefetch 파일 존재: %s" % vfile.path.rsplit("/", 1)[-1],
                              rationale="%s — 실행 시각·횟수는 읽지 못함" % why),
            model.evidence(image_desc, vfile, locator="file"), status="partial",
            notes=[why], details={"artifact": "prefetch", "candidate_event": "E08-01"})]
    ver = int.from_bytes(data[0:4], "little")
    exe = data[16:76].decode("utf-16le", "replace").split("\x00")[0]
    run_off, n_runs, cnt_off = _LAYOUT.get(ver, (0x80, 8, None))
    run_count = int.from_bytes(data[cnt_off:cnt_off + 4], "little") if cnt_off else None
    runs = sorted({_filetime(int.from_bytes(data[run_off + 8 * i:run_off + 8 * i + 8], "little")) for i in range(n_runs)} - {None})
    sha = vfile.sha256()
    records = []
    for i, iso in enumerate(runs):
        records.append(model.Record(
            rb.next_id(), "E08-01", events.name("E08-01"),
            model.timestamp(utc=iso, original=iso, fmt="FILETIME(UTC)",
                            meaning="Prefetch 에 기록된 실행 시각 (최근 %d회 중 하나)" % n_runs, source=model.TS_SOURCE_CONTENT),
            model.user_action(action="애플리케이션 실행", confidence=model.CONF_CONFIRMED,
                              rationale=("윈도 Prefetch(%s, v%d) 의 실행 시각 목록 — OS 가 프로세스 시작 시 직접 기록. "
                                         "총 실행 횟수 %s, 최근 %d회 시각만 보존") % (exe, ver, run_count, n_runs)),
            model.evidence(image_desc, vfile, locator="prefetch_run=%d/%d" % (i + 1, len(runs)), artifact_sha256=sha),
            status="ok",
            details={"artifact": "prefetch", "exe": exe, "prefetch_version": ver, "run_count": run_count,
                     "run_index": i + 1, "runs_recorded": len(runs), "all_runs_utc": runs}))
    return records
