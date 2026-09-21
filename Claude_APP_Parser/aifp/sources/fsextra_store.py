"""
확장 파일시스템 아티팩트 — `$UsnJrnl:$J` 와 `$Recycle.Bin`.

`--extended-fs` 를 줬을 때만 돈다. 둘 다 볼륨 루트에 있는 시스템 아티팩트라
앱 폴더가 지워진 뒤에도 남는다.

  `$UsnJrnl:$J`   파일 생성·삭제·이름 변경이 시각과 함께 줄줄이 남는다.
                  앱 폴더가 통째로 지워졌어도 **무엇이 언제 사라졌는지**가 여기 남는다.
  `$Recycle.Bin`  휴지통으로 보낸 파일의 **원래 경로와 삭제 시각**이 `$I` 파일에 있다.

둘 다 볼륨 전체를 뒤지므로, 대상과 무관한 기록까지 다 담지 않는다.
규칙 파일이 준 키워드에 걸리는 것만 남긴다.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Iterator

from ..provenance import ArtifactRef, Storage
from ..timeutil import TimeSource, from_filetime, to_utc_iso
from .base import Record, Source

# USN 변경 사유 — 필요한 것만 이름을 붙인다
USN_REASONS: tuple[tuple[int, str], ...] = (
    (0x00000001, "데이터 덮어쓰기"),
    (0x00000002, "데이터 추가"),
    (0x00000004, "데이터 잘림"),
    (0x00000100, "파일 생성"),
    (0x00000200, "파일 삭제"),
    (0x00001000, "이름 변경(이전 이름)"),
    (0x00002000, "이름 변경(새 이름)"),
    (0x00008000, "기본 정보 변경"),
    (0x00080000, "보안 변경"),
    (0x80000000, "핸들 닫힘"),
)
RENAME_OLD = 0x00001000
RENAME_NEW = 0x00002000
FILE_DELETE = 0x00000200
FILE_CREATE = 0x00000100

MAX_J_BYTES = 512 * 1024 * 1024      # $J 가 아무리 커도 여기까지만 읽는다
CHUNK = 8 * 1024 * 1024
MAX_RECORD = 8 * 1024                # 이보다 긴 길이 필드는 손상으로 본다
MIN_RECORD = 56


def reason_text(flags: int) -> str:
    names = [n for bit, n in USN_REASONS if flags & bit]
    return " · ".join(names) if names else f"0x{flags:08x}"


# Claude Desktop 이 파일을 두는 곳. 경로가 여기에 걸리면 데스크톱 흔적이다.
DESKTOP_MARKS = (
    "appdata/local/claude", "appdata/roaming/claude",
    "packages/claude_pzs8sxrjxfjjc", "windowsapps/claude_",
    "programdata/claude",
)
BROWSER_MARKS = ("/user data/", "indexeddb", "/profiles/", "mozilla/firefox")

# MSIX 패키지 폴더 이름 — Claude_<버전>_x64__pzs8sxrjxfjjc
PACKAGE_RE = re.compile(r"^claude_[\d.]+_x64__pzs8sxrjxfjjc", re.I)


def product_of(path: str, name: str) -> str:
    """
    경로를 보고 어느 제품의 흔적인지 가른다.

    이름에 claude 가 들어갔다고 전부 Claude Desktop 이 아니다. 실제 이미지에서는
    OpenAI Codex 런타임이 claude_code_desktop-icon.svg 같은 파일을 들고 있었고,
    그것이 데스크톱 증거로 잘못 실렸다. 경로를 봐야 가를 수 있다.

    돌려주는 값
        ""                 Claude Desktop (이 파서의 대상)
        "Claude Web"       브라우저에 남은 claude.ai 흔적
        "Claude Code(CLI)" 사용자 홈의 .claude 계열
        "다른 앱"           이름만 겹치는 남의 파일 — 표에 싣지 않는다
    """
    low = (path or "").lower()
    base = (name or "").lower()
    if not low:
        return ""                      # 경로를 모르면 판단하지 않는다(버리지 않는다)
    if base.startswith(".claude") or "/.claude" in low:
        return "Claude Code(CLI)"
    if any(m in low for m in BROWSER_MARKS) and "claude" in low:
        return "Claude Web"
    if any(m in low for m in DESKTOP_MARKS):
        return ""
    # MSIX 패키지는 제거될 때 WindowsApps\Deleted 로 옮겨진다.
    # 중간에 폴더가 하나 끼므로 단순 문자열 비교로는 걸리지 않는다.
    if re.search(r"windowsapps/(?:[^/]+/)?claude_", low):
        return ""
    # 실행·설치 흔적은 앱 폴더 밖에 있다. 파일 이름이 아니라 놓인 자리로 가른다.
    if "windows/prefetch/" in low and base.startswith("claude"):
        return ""
    if "/downloads/" in low and base.startswith("claude setup"):
        return ""
    return "다른 앱"


class UsnJrnlSource(Source):
    """`$Extend/$UsnJrnl:$J` 변경 저널."""

    name = "usnjrnl"
    scope = "volume"
    display = "변경 저널"

    def locate(self) -> list:
        backend = getattr(self.volume_root, "backend", None) if self.volume_root else None
        if backend is None or not hasattr(backend, "by_path"):
            return []
        return [p for p in backend.by_path if p.endswith("$usnjrnl")]

    # ── $J 스트림을 덩어리로 흘려 읽는다 ────────────────────────────────
    def _stream_chunks(self, fs, runs) -> Iterator[bytes]:
        read = 0
        for lcn, ln in runs:
            n = ln * fs.cluster
            if lcn is None:                      # 구멍 — 0으로 채워진 구간, 건너뛴다
                read += n
                continue
            got = 0
            while got < n and read < MAX_J_BYTES:
                k = min(CHUNK, n - got, MAX_J_BYTES - read)
                try:
                    yield fs.v.read(lcn * fs.cluster + got, k)
                except Exception as exc:
                    self.errs.from_exception(exc, "parse", self.name)
                    return
                got += k
                read += k
            if read >= MAX_J_BYTES:
                self.errs.add("warning", "USN_TRUNCATED", "parse", self.name,
                              f"$J 가 커서 {MAX_J_BYTES:,}B 까지만 읽었다")
                return

    @staticmethod
    def consumed_end(buf: bytes) -> int:
        """
        온전히 읽어낸 마지막 위치.

        청크 경계에 걸친 레코드를 다음 덩어리로 넘기려면 '끝에서 N바이트'가 아니라
        **레코드 경계**를 알아야 한다. 고정 길이로 자르면 다음 덩어리가 레코드 중간에서
        시작해 파싱이 즉시 멈추고 그 덩어리가 통째로 버려진다.
        """
        i = 0
        n = len(buf)
        while i + 60 <= n:
            (length,) = struct.unpack_from("<I", buf, i)
            if length == 0:
                i += 8
                continue
            if length > MAX_RECORD or length < MIN_RECORD:
                nxt = UsnJrnlSource._resync(buf, i, n)
                if nxt >= n:
                    return n                     # 뒤쪽 전체가 쓰레기 — 이월하지 않는다
                i = nxt
                continue
            if i + length > n:
                break
            i += length
        return i

    @staticmethod
    def _resync(buf: bytes, start: int, n: int) -> int:
        """
        손상 구간을 건너뛰고 다음 레코드 머리를 찾는다.

        저널 한가운데가 깨졌다고 그 뒤를 통째로 버리면 증거가 사라진다.
        USN 레코드는 8바이트 경계에 놓이므로 8바이트씩 전진하며
        길이·버전·이름 필드가 앞뒤로 맞는 지점을 찾는다.
        """
        i = start + 8 - (start % 8 or 8)
        while i + 60 <= n:
            (length,) = struct.unpack_from("<I", buf, i)
            if MIN_RECORD <= length <= MAX_RECORD and i + length <= n:
                major = struct.unpack_from("<H", buf, i + 4)[0]
                if major in (2, 3):
                    nlen, noff = struct.unpack_from(
                        "<HH", buf, i + (56 if major == 2 else 72))
                    if 0 < nlen <= 512 and nlen % 2 == 0 and noff + nlen <= length:
                        return i
            i += 8
        return n

    @staticmethod
    def _iter_records(buf: bytes, base: int) -> Iterator[dict[str, Any]]:
        i = 0
        n = len(buf)
        while i + 60 <= n:
            (length,) = struct.unpack_from("<I", buf, i)
            if length == 0:                      # 0 채움 구간 — 다음 레코드까지 건너뛴다
                i += 8
                continue
            if length > MAX_RECORD or length < MIN_RECORD:
                # 길이 필드가 깨졌다 — 뒤쪽을 포기하지 말고 다음 레코드를 찾는다
                nxt = UsnJrnlSource._resync(buf, i, n)
                if nxt >= n:
                    break
                i = nxt
                continue
            if i + length > n:
                break                            # 덩어리 경계에 걸림 — 다음으로 이월
            major, minor = struct.unpack_from("<HH", buf, i + 4)
            try:
                if major == 2:
                    fref, pref, usn, ts = struct.unpack_from("<QQQQ", buf, i + 8)
                    reason, _src, _sid, _attr = struct.unpack_from("<IIII", buf, i + 40)
                    nlen, noff = struct.unpack_from("<HH", buf, i + 56)
                elif major == 3:
                    fref = struct.unpack_from("<Q", buf, i + 8)[0]
                    pref = struct.unpack_from("<Q", buf, i + 24)[0]
                    usn, ts = struct.unpack_from("<QQ", buf, i + 40)
                    reason, _src, _sid, _attr = struct.unpack_from("<IIII", buf, i + 56)
                    nlen, noff = struct.unpack_from("<HH", buf, i + 72)
                else:
                    i += length
                    continue
                name = buf[i + noff:i + noff + nlen].decode("utf-16-le", "replace")
            except (struct.error, UnicodeDecodeError):
                i += length
                continue
            yield {"usn": usn, "file_ref": fref & 0xFFFFFFFFFFFF,
                   "parent_ref": pref & 0xFFFFFFFFFFFF, "reason": reason,
                   "name": name, "ts": ts, "offset": base + i}
            i += length

    def read(self) -> list[Record]:
        paths = self.locate()
        if not paths:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name,
                          "$UsnJrnl 을 찾지 못했다")
            return []

        backend = self.volume_root.backend
        fs = backend.fs
        path = paths[0]
        ref = backend.by_path[path]
        try:
            attrs = fs.full_attrs(ref)
            runs, total, resident = fs.stream_runs(attrs, "$J")
        except Exception as exc:
            self.errs.from_exception(exc, "parse", self.name)
            return []
        if runs is None and resident is None:
            self.errs.add("warning", "ARTIFACT_CORRUPT", "parse", self.name,
                          "$UsnJrnl 에 $J 스트림이 없다")
            return []

        words = self._keywords()
        seen_names: dict[str, dict] = {}     # 이름 변경 짝 맞추기
        grouped: dict[tuple, dict] = {}      # (파일, 종류) → 한 건으로 묶는다
        kept = scanned = 0
        base = 0

        chunks = ([resident] if runs is None
                  else self._stream_chunks(fs, runs))
        carry = b""            # 앞 덩어리에서 다 읽지 못한 잔여 바이트
        carry_base = 0         # 그 잔여분이 스트림에서 시작하는 위치
        for chunk in chunks:
            buf = carry + chunk
            for rec in self._iter_records(buf, carry_base):
                scanned += 1
                low = rec["name"].lower()
                if not any(w in low for w in words):
                    continue
                kept += 1
                self._collect(rec, seen_names, grouped)
            end = self.consumed_end(buf)
            carry_base += end
            carry = buf[end:]
            if len(carry) > 4 * 1024 * 1024:
                # 레코드 경계를 못 찾은 채 잔여분만 불어나는 상황 — 동기화가 깨졌다
                self.errs.add("warning", "USN_DESYNC", "parse", self.name,
                              f"$J 레코드 경계를 잃었다 — {len(carry):,}B 를 건너뛰고 "
                              f"다음 덩어리부터 다시 맞춘다")
                carry_base += len(carry)
                carry = b""

        for g in grouped.values():
            self._emit_group(g)

        skipped = getattr(self, "_skipped", [])
        if skipped:
            # 무엇을 왜 뺐는지 밝힌다. 말없이 빼면 그것도 증거 유실이다.
            sample = ", ".join(skipped[:3])
            self.errs.add("info", "USN_OTHER_PRODUCT", "parse", self.name,
                          f"이름만 겹치는 다른 앱의 파일 {len(skipped)}건은 표에서 뺐다 "
                          f"(예: {sample})")
        self.errs.add("info", "USN_PARSED", "parse", self.name,
                      f"$J 레코드 {scanned:,}건 확인 — 대상 관련 {kept:,}건"
                      + (f", 그중 다른 앱 {len(skipped)}건 제외" if skipped else ""))
        return self.records

    def _keywords(self) -> list[str]:
        """규칙 파일이 아니라 대상 앱 이름에서 뽑는다. 볼륨 전체가 대상이므로 좁혀야 한다."""
        words = {"claude"}
        root = getattr(self.root, "rel", "") or ""
        for part in str(root).lower().replace("\\", "/").split("/"):
            if part.startswith("claude"):
                words.add(part)
        return sorted(words)

    @staticmethod
    def _kind_of(reason: int) -> str:
        if reason & FILE_DELETE:
            return "usn_delete"
        if reason & (RENAME_OLD | RENAME_NEW):
            return "usn_rename"
        if reason & FILE_CREATE:
            return "usn_create"
        return "usn_event"

    def _collect(self, rec: dict[str, Any], seen_names: dict[str, dict],
                 grouped: dict[tuple, dict]) -> None:
        """
        같은 파일에 대한 기록은 한 건으로 묶는다.
        앱을 지우면 파일 하나에 수십 건이 쌓이는데, 그걸 전부 타임라인에 올리면
        정작 무슨 일이 있었는지가 묻힌다. 처음·마지막 시각과 횟수만 남긴다.
        """
        if rec["reason"] & RENAME_OLD:
            seen_names[str(rec["file_ref"])] = rec
        renamed_from = None
        if rec["reason"] & RENAME_NEW:
            old = seen_names.pop(str(rec["file_ref"]), None)
            renamed_from = old["name"] if old else None

        kind = self._kind_of(rec["reason"])
        key = (rec["file_ref"], rec["name"], kind)
        when = from_filetime(rec["ts"])
        ts = to_utc_iso(when) if when else None

        g = grouped.get(key)
        if g is None:
            grouped[key] = {
                "kind": kind, "name": rec["name"], "file_ref": rec["file_ref"],
                "parent_ref": rec["parent_ref"], "first_ts": ts, "last_ts": ts,
                "reasons": rec["reason"], "count": 1, "offset": rec["offset"],
                "usn": rec["usn"], "renamed_from": renamed_from,
            }
            return
        g["count"] += 1
        g["reasons"] |= rec["reason"]
        g["renamed_from"] = g["renamed_from"] or renamed_from
        if ts:
            g["first_ts"] = min(g["first_ts"] or ts, ts)
            g["last_ts"] = max(g["last_ts"] or ts, ts)

    def _emit_group(self, g: dict[str, Any]) -> None:
        ref = ArtifactRef(path=f"{self.volume_root}/$Extend/$UsnJrnl:$J",
                          storage=Storage.FILESYSTEM.value,
                          offset=g["offset"], locator=f"USN {g['usn']}")
        path, sure = self._path_of(g["file_ref"], g["parent_ref"], g["name"])
        product = product_of(path, g["name"])
        if product == "다른 앱" and not sure:
            # 짐작한 경로만으로 버리지 않는다. 대신 표시만 한다.
            product = "다른 앱(추정)"
        if product == "다른 앱":
            # 이름만 겹치는 남의 파일이다. 표에 실으면 없는 행위를 만든다.
            # 버린 사실은 세어서 실행 기록에 남긴다.
            if not hasattr(self, "_skipped"):
                self._skipped = []
            self._skipped.append(f"{g['name']} ({path})")
            return

        detail = g["name"]
        if g["renamed_from"]:
            detail = f"{g['renamed_from']} → {g['name']}"
        if g["count"] > 1:
            detail += f" (기록 {g['count']}건)"
        if path:
            detail += f" · {path}" + ("" if sure else " (추정 경로)")
        if product:
            # 이 파서의 대상은 Claude Desktop 이다. 다른 제품 흔적은 버리지 않되
            # 무엇인지 밝혀 둔다.
            detail += f" [{product}]"
        self.emit(Record(
            kind=g["kind"], source=self.name, key=g["name"],
            value={
                "name": g["name"],
                "detail": detail,
                "renamed_from": g["renamed_from"],
                "reason": reason_text(g["reasons"]),
                "reason_flags": g["reasons"],
                "file_ref": g["file_ref"],
                "parent_ref": g["parent_ref"],
                "path": path,
                "product": product or "Claude Desktop",
                "package_removed": bool(
                    PACKAGE_RE.match(g["name"] or "")
                    and (g["kind"] == "usn_delete" or "deleted/" in (path or "").lower())),
                "record_count": g["count"],
                "last_seen_utc": g["last_ts"],
            },
            ts_utc=g["first_ts"], time_source=TimeSource.USNJRNL.value, ref=ref))


    def _ref_paths(self) -> dict:
        """참조 번호 → 경로. MFT 색인을 한 번만 뒤집어 둔다."""
        table = getattr(self, "_ref_table", None)
        if table is None:
            table = {}
            backend = getattr(self.volume_root, "backend", None) if self.volume_root else None
            by_path = getattr(backend, "by_path", None) if backend else None
            if by_path:
                for path, ref in by_path.items():
                    table.setdefault(ref, path)
            self._ref_table = table
        return table

    def _path_of(self, file_ref: int, parent_ref: int, name: str) -> tuple[str, bool]:
        """
        (경로, 확정 여부).

        기준은 부모 폴더다. 지워진 파일은 자기 MFT 레코드가 다른 파일에 재사용되므로
        파일 자신의 참조 번호를 믿으면 엉뚱한 경로가 나온다. 실제로 그랬다 —
        제거된 Claude 패키지가 다른 앱 폴더 안에 있는 것처럼 보였다.

        부모가 살아 있는 폴더이면 확정으로 본다. 볼륨 루트이거나 폴더가 아니면
        판단을 포기한다. 파일 자신의 참조는 이름이 일치할 때만 교차 확인에 쓴다.
        """
        table = self._ref_paths()
        low = (name or "").lower()

        own = table.get(file_ref) if file_ref else None
        if own and own != "." and own.rsplit("/", 1)[-1].lower() == low:
            return own, True

        parent = table.get(parent_ref) if parent_ref else None
        if not parent or parent == "." or parent.count("/") < 1:
            return "", False
        # 레코드의 디렉터리 플래그는 믿지 않는다. 지워진 폴더의 레코드가 다른
        # 파일에 재사용되면 플래그가 파일로 바뀌어 있다 — 실제 이미지가 그랬다.
        # 색인에 그 경로가 있다는 사실만으로 충분하다.
        return f"{parent}/{name}", True


class RecycleBinSource(Source):
    """`$Recycle.Bin` — 휴지통으로 보낸 파일의 원래 경로와 삭제 시각."""

    name = "recyclebin"
    scope = "volume"
    display = "휴지통"

    def locate(self) -> list:
        if self.volume_root is None:
            return []
        rb = self.volume_root / "$Recycle.Bin"
        if not rb.is_dir():
            return []
        out = []
        for sid_dir in rb.iterdir():
            if not sid_dir.is_dir():
                continue
            for f in sid_dir.iterdir():
                if f.name.lower().startswith("$i"):
                    out.append(f)
        return out

    @staticmethod
    def _parse_i(raw: bytes) -> dict[str, Any] | None:
        if len(raw) < 24:
            return None
        version = struct.unpack_from("<Q", raw, 0)[0]
        size = struct.unpack_from("<Q", raw, 8)[0]
        ft = struct.unpack_from("<Q", raw, 16)[0]
        if version == 1:                      # 이름이 520바이트 고정
            name = raw[24:24 + 520].decode("utf-16-le", "replace").split("\x00")[0]
        elif version == 2:
            nlen = struct.unpack_from("<I", raw, 24)[0]
            name = raw[28:28 + nlen * 2].decode("utf-16-le", "replace").split("\x00")[0]
        else:
            return None
        return {"original_path": name, "size": size, "deleted_filetime": ft}

    def read(self) -> list[Record]:
        files = self.locate()
        if not files:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name,
                          "$Recycle.Bin 에 삭제 기록($I)이 없다")
            return []

        kept = 0
        for f in files:
            raw = self.safe_bytes(f)
            if raw is None:
                continue
            info = self._parse_i(raw)
            if not info:
                self.errs.add("warning", "ARTIFACT_CORRUPT", "parse", self.name,
                              f"$I 형식을 해석하지 못했다: {f.name}", str(f))
                continue
            sid = f.parent.name
            when = from_filetime(info["deleted_filetime"])
            self.emit(Record(
                kind="recycle_entry", source=self.name, key=f.name,
                value={"original_path": info["original_path"], "size": info["size"],
                       "sid": sid,
                       "claude_related": "claude" in info["original_path"].lower()},
                ts_utc=to_utc_iso(when) if when else None,
                time_source=TimeSource.FILENAME.value,
                ref=ArtifactRef.from_file(f, Storage.FILESYSTEM.value),
            ))
            kept += 1

        self.errs.add("info", "RECYCLE_PARSED", "parse", self.name,
                      f"휴지통 삭제 기록 {kept}건")
        return self.records
