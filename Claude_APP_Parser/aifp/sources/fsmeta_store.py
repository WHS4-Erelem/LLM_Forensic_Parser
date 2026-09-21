"""
파일시스템 메타·앱 로그 리더.

두 가지를 한다.

1) **앱 로그**(main.log 등) — 앱이 직접 찍은 시각이라 신뢰도가 높다.
   기동·버전·조직 UUID·계정 전환이 줄글로 남는다.

2) **파일 메타데이터** — lockfile·Prefetch·캐시 파일의 시각.
   여기서 반드시 해야 하는 일이 있다:
   Chromium은 종료할 때 밀린 쓰기를 한 번에 flush한다.
   그래서 파일 시각이 전부 '앱을 끈 시각'으로 수렴한다.
   이걸 모르고 타임라인에 쓰면 결론이 통째로 틀린다 → 수렴을 감지해 경고를 붙인다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..provenance import ArtifactRef, Storage
from ..timeutil import (TimeConfidence, TimeSource, detect_flush_convergence,
                        from_iso, to_utc_iso)
from .base import Record, Source

# main.log 줄머리의 시각 — 형식이 버전마다 달라 여러 패턴을 시도한다
LOG_TS_PATTERNS = (
    re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\]?"),
    re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    re.compile(r"^\[(\d{2}:\d{2}:\d{2}\.\d+)\]"),
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:\.\d+)?)\b")

# 줄머리 시각에 시간대 표시가 붙어 있는지 — 문자열로 판단한다.
# 파싱된 값만 보면 알 수 없다. 시간대가 없는 값도 UTC로 읽히기 때문이다.
RAW_TZ_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def is_naive_stamp(raw: str) -> bool:
    return not RAW_TZ_RE.search((raw or "").strip())


# 로그에 식별자가 어떤 이름으로 적히는지. 첫 UUID를 계정으로 단정하면
# "accountId=null, orgId=…" 같은 줄에서 조직 UUID를 계정으로 잘못 싣게 된다.
ACCOUNT_LABEL_RE = re.compile(
    r"(?:account[_ ]?id|account[_ ]?uuid|accountid)\s*[:=]\s*[\"']?"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
ORG_LABEL_RE = re.compile(
    r"(?:org[_ ]?id|org[_ ]?uuid|organization[_ ]?id|organizations?/)\s*[:=]?\s*[\"']?"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)
# [account] Login-state transition (… uuid: <none> → <uuid>)
ACCOUNT_TRANSITION_RE = re.compile(
    r"uuid:\s*[^\s]+\s*(?:->|→)\s*"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.I)


# Login-state transition (loggedOut: true → false, uuid: <none> → <uuid>)
TRANSITION_RE = re.compile(
    r"login-state transition\s*\(loggedout:\s*(true|false)\s*(?:->|→)\s*(true|false)"
    r"[^)]*?uuid:\s*(<none>|[0-9a-f-]{36})\s*(?:->|→)\s*(<none>|[0-9a-f-]{36})",
    re.I)


def login_transition(line: str) -> tuple[str, dict] | None:
    """
    (종류, 값). 로그인 상태가 어떻게 바뀌었는지 읽는다.

    계정이 A에서 B로 바뀌면 로그인도 로그아웃도 아닌 '계정 전환'이다.
    이것을 구분하지 못하면 한 PC를 여러 계정이 썼다는 사실을 놓친다.
    """
    m = TRANSITION_RE.search(line)
    if not m:
        return None
    now_out, before, after = m.group(2).lower(), m.group(3), m.group(4)
    none = "<none>"
    # 로그아웃이 먼저다. 계정이 바뀌면서 로그아웃 상태가 됐다면 그것은 전환이 아니라
    # 로그아웃이다 — 순서를 뒤집으면 없는 전환이 생긴다.
    if now_out == "true":
        return "log_logout", {"account_uuid": before if before != none else None}
    if before != none and after != none and before != after:
        return "log_account_switch", {"from_account_uuid": before,
                                      "account_uuid": after}
    if after != none:
        return "log_login", {"account_uuid": after}
    return None


def labeled_ids(line: str) -> dict:
    """줄에서 이름표가 붙은 식별자만 뽑는다. 이름표가 없으면 아무것도 돌려주지 않는다."""
    out: dict[str, str] = {}
    m = ACCOUNT_LABEL_RE.search(line) or ACCOUNT_TRANSITION_RE.search(line)
    if m:
        out["account_uuid"] = m.group(1)
    m = ORG_LABEL_RE.search(line)
    if m:
        out["org_uuid"] = m.group(1)
    return out


def shift_local(dt, offset_seconds: int, naive: bool = True):
    """현지시각으로 적힌 값을 UTC로 옮긴다. 오프셋이 0이면 그대로 둔다."""
    if dt is None or not offset_seconds or not naive:
        return dt
    from datetime import timedelta
    return dt - timedelta(seconds=offset_seconds)


# 관심 있는 로그 키워드 → 의미
LOG_KEYWORDS = (
    ("appVersion", "앱 버전"),
    ("version", "버전 정보"),
    ("login", "로그인 관련"),
    ("logout", "로그아웃 관련"),
    ("organization", "조직 식별자"),
    ("account", "계정 관련"),
    ("quit", "종료"),
    ("ready", "기동 완료"),
    ("error", "오류"),
)


# 로그 한 줄에서 읽어낼 사실. (찾을 말, 레코드 종류, 사람이 읽을 이름)
LOG_FACTS = (
    (("logged in", "login succeeded", "sign-in complete", "[account] logged in"),
     "log_login_state", "로그인 상태"),
    (("logout", "signed out", "sign-out"), "log_logout", "로그아웃"),
    (("starting app", "app ready", "app started"), "log_start", "앱 기동"),
    (("beforequit", "before-quit", "will-quit", "shutting down", "shutdown",
      "onquitcleanup", "app quit", "quit requested", "going down"),
     "log_quit", "앱 종료"),
    (("conversation", "chat id", "new chat"), "log_conversation", "대화"),
)

# 한 동작이 여러 줄에 걸쳐 찍히는 종류와, 같은 동작으로 볼 시간 폭(초)
BURST_KINDS = ("log_quit", "log_start", "log_logout", "log_login")
BURST_WINDOW = 120

# 모델 이름은 로그에 그대로 찍힌다
MODEL_RE = re.compile(r"\b(claude[-\w.]*?(?:opus|sonnet|haiku)[-\w.]*)\b", re.I)


class AppLogSource(Source):
    name = "applog"
    scope = "user"
    display = "앱 로그"

    def locate(self) -> list:
        """패키지 밖에 있어 앱을 지워도 남는 로그. 증거 안의 사용자 프로필 기준으로 찾는다."""
        candidates = []
        if self.user_root is not None:
            candidates.append(self.user_root / "AppData/Local/Claude/logs")
            candidates.append(self.user_root / "AppData/Local/Temp")   # 설치 로그
        candidates.append(self.root / "logs")
        if self.volume_root is not None:
            # 서비스 로그는 사용자 프로필이 아니라 ProgramData 에 쌓인다
            candidates.append(self.volume_root / "ProgramData/Claude/logs")
        out = []
        seen: set[str] = set()
        for d in candidates:
            try:
                if not d.is_dir():
                    continue
                for p in sorted(d.glob("*.log")):
                    key = str(p).lower()
                    if d.name.lower() == "temp" and "claude" not in p.name.lower():
                        continue
                    # 앱 루트가 곧 로그 폴더의 부모인 경우 후보가 겹친다
                    if p.is_file() and key not in seen:
                        seen.add(key)
                        out.append(p)
            except Exception:
                continue
        return out

    @staticmethod
    def _naive_offset(path, text: str) -> tuple[int, str]:
        """
        (초 단위 오프셋, 설명). 로그 줄이 현지시각이면 그 PC의 UTC 오프셋을 돌려준다.

        Z가 붙은 줄만 있으면 오프셋은 0이다. 시간대 표시가 없는 줄이면 파일의
        수정시각(UTC)과 마지막 줄의 시각을 견줘 15분 단위로 반올림한다.
        추정이므로 근거를 함께 남긴다.
        """
        last = None
        naive = False
        for line in text.splitlines():
            for pat in LOG_TS_PATTERNS:
                m = pat.match(line.rstrip())
                if not m:
                    continue
                raw = m.group(1)
                if len(raw) < 10:              # 시:분:초만 있는 형식은 판단 불가
                    break
                dt = from_iso(raw)
                if dt is None:
                    break
                if is_naive_stamp(raw):
                    naive = True
                last = dt
                break
        if last is None or not naive:
            return 0, ""
        try:
            mtime = from_iso(path.stat().modified_utc or "")
        except Exception:
            mtime = None
        if mtime is None:
            return 0, ""
        delta = (last - mtime).total_seconds()
        if abs(delta) > 14 * 3600:
            return 0, ""
        off = int(round(delta / 900.0) * 900)
        if off == 0:
            return 0, ""
        sign = "+" if off > 0 else "-"
        return off, (f"로그 시각이 현지시각으로 적혀 있다 — 파일 수정시각과 견줘 "
                     f"UTC{sign}{abs(off) // 3600:02d}:{abs(off) % 3600 // 60:02d} 로 보고 환산했다")

    def read(self) -> list[Record]:
        files = self.locate()
        if not files:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name, "앱 로그 폴더 없음")
            return []

        version_seen: str | None = None
        budget = 600                     # 로그 전체에서 뽑을 최대 이벤트 수
        for f in files:
            data = self.safe_bytes(f)
            if data is None:
                continue
            self.manifest.add_file(f)
            ref_base = ArtifactRef.from_file(f, Storage.APPLOG)
            text = data.decode("utf-8", "replace")
            tz_off, tz_note = self._naive_offset(f, text)
            if tz_note:
                self.errs.add("info", "APPLOG_LOCALTIME", "parse", self.name,
                              f"{f.name}: {tz_note}", str(f))

            offset = 0
            emitted = 0
            for line in text.splitlines(keepends=True):
                raw_line = line.rstrip("\r\n")
                line_off = offset
                offset += len(line.encode("utf-8", "replace"))
                if not raw_line.strip():
                    continue

                ts = None
                for pat in LOG_TS_PATTERNS:
                    m = pat.match(raw_line)
                    if m:
                        ts = shift_local(from_iso(m.group(1)), tz_off,
                                         is_naive_stamp(m.group(1)))
                        break

                low = raw_line.lower()
                tags = [desc for kw, desc in LOG_KEYWORDS if kw.lower() in low]
                if not tags and ts is None:
                    continue
                if emitted >= 60 or budget <= 0:   # 파일당·전체 상한
                    break

                if version_seen is None:
                    vm = VERSION_RE.search(raw_line)
                    if vm and ("version" in low):
                        version_seen = vm.group(1)

                self.emit(Record(
                    kind="appevent", source=self.name, key=f.name,
                    value={"line": raw_line[:500], "tags": tags,
                           "uuids": list(dict.fromkeys(UUID_RE.findall(raw_line)))[:3]},
                    ts_utc=to_utc_iso(ts),
                    time_source=TimeSource.APPLOG.value if ts else None,
                    ref=ArtifactRef(path=str(f), storage=Storage.APPLOG.value,
                                    offset=line_off, sha256=ref_base.sha256,
                                    locator=f"line@{line_off}"),
                ))
                emitted += 1
                budget -= 1

        self._read_facts(files)

        if version_seen:
            self.emit(Record(kind="client_version", source=self.name,
                             key="appVersion", value={"version": version_seen},
                             ref=ArtifactRef(path=str(files[0]), storage=Storage.APPLOG.value)))
        self.errs.add("info", "APPLOG_SCAN", "parse", self.name,
                      f"로그 {len(files)}개에서 이벤트 {len(self.records)}건 추출")
        return self.records

    # ── 로그에서 사실 뽑기 ─────────────────────────────────────────────
    def _read_facts(self, files: list) -> None:
        """
        줄을 그대로 싣는 것과 별개로, 줄 안에 적힌 사실을 종류별 레코드로 만든다.

        앱 로그는 앱이 직접 찍은 기록이라 시각을 믿을 수 있고, 패키지 밖에 있어
        앱을 지워도 남는다. 계정 식별자와 로그인·종료 시각은 여기서만 나오는
        경우가 많다 — 사용자 데이터 폴더가 지워진 디스크가 그렇다.
        """
        found: dict[str, int] = {}
        capped: set[str] = set()          # 상한에 걸린 종류
        seen: set[tuple] = set()          # (종류, 시각, 줄) — 반복 기록을 한 번만

        # 상태 전이가 찍힌 시각을 로그 전체에서 먼저 모은다. 한 동작을 여러
        # 모듈이 서로 다른 파일에 적으므로 파일 하나만 봐서는 알 수 없다.
        transition_at: set = set()
        for f in files:
            data = self.safe_bytes(f)
            if data is None:
                continue
            probe_text = data.decode("utf-8", "replace")
            probe_off, _ = self._naive_offset(f, probe_text)
            for probe in probe_text.splitlines():
                if not login_transition(probe):
                    continue
                for pat in LOG_TS_PATTERNS:
                    m = pat.match(probe.rstrip())
                    if m:
                        transition_at.add(to_utc_iso(shift_local(
                            from_iso(m.group(1)), probe_off,
                            is_naive_stamp(m.group(1)))))
                        break

        for f in files:
            data = self.safe_bytes(f)
            if data is None:
                continue
            text = data.decode("utf-8", "replace")
            tz_off, _ = self._naive_offset(f, text)
            ref_base = ArtifactRef.from_file(f, Storage.APPLOG)
            offset = 0
            per_kind: dict[str, int] = {}

            for line in text.splitlines(keepends=True):
                raw = line.rstrip("\r\n")
                line_off = offset
                offset += len(line.encode("utf-8", "replace"))
                if not raw.strip():
                    continue
                low = raw.lower()

                ts = None
                for pat in LOG_TS_PATTERNS:
                    m = pat.match(raw)
                    if m:
                        ts = shift_local(from_iso(m.group(1)), tz_off,
                                         is_naive_stamp(m.group(1)))
                        break

                def ref_for() -> ArtifactRef:
                    return ArtifactRef(path=str(f), storage=Storage.APPLOG.value,
                                       offset=line_off, sha256=ref_base.sha256,
                                       locator=f"line@{line_off}")

                uuids = list(dict.fromkeys(UUID_RE.findall(raw)))

                # 로그인 상태 전이 — 방향과 계정 변화를 함께 읽는다
                tr = login_transition(raw)
                if tr:
                    handled_line = True
                    kind, extra = tr
                    mark = (kind, to_utc_iso(ts))
                    if per_kind.get(kind, 0) >= 20:
                        capped.add(kind)
                    if mark not in seen and per_kind.get(kind, 0) < 20:
                        seen.add(mark)
                        value = {"line": raw[:300]}
                        value.update({k: v for k, v in extra.items() if v})
                        self.emit(Record(kind=kind, source=self.name, key=f.name,
                                         value=value, ts_utc=to_utc_iso(ts),
                                         time_source=(TimeSource.APPLOG.value
                                                      if ts else None),
                                         ref=ref_for()))
                        per_kind[kind] = per_kind.get(kind, 0) + 1
                        found[kind] = found.get(kind, 0) + 1
                        if kind in BURST_KINDS and ts is not None:
                            # 뒤따라오는 같은 동작의 줄들을 묶어 두기 위해
                            # 시간 창 표시도 함께 남긴다
                            seen.add((kind, int(ts.timestamp()) // BURST_WINDOW))
                    continue        # 전이 줄은 여기서 끝 — 같은 줄을 두 번 싣지 않는다

                # 계정·조직 식별자 — 이름표가 붙은 값만 싣는다.
                # 같은 식별자는 처음 본 줄 하나만 싣는다. 여러 건을 묶으면 표에
                # 찍히는 시각과 근거 줄이 서로 다른 줄을 가리키게 된다.
                for field, kind in (("account_uuid", "log_account"),
                                    ("org_uuid", "log_org")):
                    got = labeled_ids(raw).get(field)
                    if not got:
                        continue
                    mark = (kind, got)
                    if per_kind.get(kind, 0) >= 20:
                        capped.add(kind)
                        continue
                    if mark in seen:
                        continue
                    seen.add(mark)
                    self.emit(Record(kind=kind, source=self.name, key=f.name,
                                     value={"line": raw[:300], field: got},
                                     ts_utc=to_utc_iso(ts),
                                     time_source=(TimeSource.APPLOG.value
                                                  if ts else None),
                                     ref=ref_for()))
                    per_kind[kind] = per_kind.get(kind, 0) + 1
                    found[kind] = found.get(kind, 0) + 1

                # 로그인·로그아웃·기동·종료·대화
                for words, kind, label in LOG_FACTS:
                    if not any(w in low for w in words):
                        continue
                    if (kind in ("log_login", "log_logout")
                            and to_utc_iso(ts) in transition_at):
                        break           # 그 시각은 전이 줄이 근거다
                    if kind in BURST_KINDS and any(
                            w in low for w in ("failed", "failure", "error",
                                               "timed out", "timeout")):
                        # 실패를 알리는 줄은 그 행위가 일어났다는 근거가 아니다.
                        # 사용자 행위로 올리면 없던 로그아웃이 생긴다.
                        break
                    if per_kind.get(kind, 0) >= 20:
                        capped.add(kind)
                        break
                    # 종료·로그아웃 한 동작은 수십 줄에 걸쳐 수십 초 동안 찍힌다.
                    # 줄마다 한 행을 만들면 표가 같은 사실로 도배된다.
                    # 같은 동작으로 볼 시간 폭(2분) 안이면 한 건으로 묶는다.
                    if kind in BURST_KINDS and ts is not None:
                        bucket = int(ts.timestamp()) // BURST_WINDOW
                        mark = (kind, bucket)
                        prev = (kind, bucket - 1)
                        if mark in seen or prev in seen:
                            break
                    else:
                        mark = (kind, to_utc_iso(ts), raw[:120])
                        if mark in seen:
                            break
                    seen.add(mark)
                    value = {"line": raw[:300], "what": label}
                    if uuids:
                        value["uuids"] = uuids[:3]
                        if kind == "log_conversation":
                            value["conversation_uuid"] = uuids[0]
                    self.emit(Record(kind=kind, source=self.name, key=f.name,
                                     value=value, ts_utc=to_utc_iso(ts),
                                     time_source=TimeSource.APPLOG.value if ts else None,
                                     ref=ref_for()))
                    per_kind[kind] = per_kind.get(kind, 0) + 1
                    found[kind] = found.get(kind, 0) + 1
                    break

                # 사용한 모델
                mm = MODEL_RE.search(raw)
                mark = ("log_model", mm.group(1) if mm else "", "")
                if mm and per_kind.get("log_model", 0) >= 20:
                    capped.add("log_model")
                if mm and per_kind.get("log_model", 0) < 20 and mark not in seen:
                    seen.add(mark)
                    self.emit(Record(kind="log_model", source=self.name, key=f.name,
                                     value={"model": mm.group(1), "line": raw[:300]},
                                     ts_utc=to_utc_iso(ts),
                                     time_source=TimeSource.APPLOG.value if ts else None,
                                     ref=ref_for()))
                    per_kind["log_model"] = per_kind.get("log_model", 0) + 1
                    found["log_model"] = found.get("log_model", 0) + 1

        if capped:
            # 상한에 걸려 버린 것이 있으면 반드시 알린다. 말없이 자르면
            # 조사관은 로그에 그만큼밖에 없었다고 오해한다.
            self.errs.add("warning", "APPLOG_CAPPED", "parse", self.name,
                          "로그에서 뽑은 사실이 파일당 상한(20건)에 걸렸다 — "
                          + ", ".join(sorted(capped))
                          + ". 원본 로그를 직접 확인할 것")
        if found:
            detail = ", ".join(f"{k} {v}건" for k, v in sorted(found.items()))
            self.errs.add("info", "APPLOG_FACTS", "parse", self.name,
                          f"로그에서 사실 추출 — {detail}")


class FsMetaSource(Source):
    """
    파일 메타데이터 + 실행 흔적.
    본문이 하나도 없어도 '언제 무엇이 생기고 지워졌는지'는 여기서 나온다.
    """
    name = "fsmeta"
    display = "파일시스템 메타"

    WATCH = (
        ("lockfile", "실행 중 표시 — 생성/삭제가 실행/종료와 1:1 대응"),
        ("config.json", "정상 종료 직전 재작성"),
        ("window-state.json", "정상 종료 시 갱신"),
        ("Local State", "프로파일 상태"),
        ("Preferences", "환경설정"),
    )

    def locate(self) -> list[Path]:
        out = [self.root / n for n, _ in self.WATCH if (self.root / n).exists()]
        cache = self.root / "Cache" / "Cache_Data"
        if cache.is_dir():
            out.extend(sorted(cache.glob("f_*"))[:400])
        if self.volume_root is not None:
            pf = self.volume_root / "Windows/Prefetch"
            try:
                if pf.is_dir():
                    out.extend(sorted(pf.glob("CLAUDE*.pf")))
            except Exception as exc:
                self.errs.from_exception(exc, "collect", self.name, str(pf))
        return out

    def read(self) -> list[Record]:
        paths = self.locate()
        if not paths:
            self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name, "대상 파일 없음")
            return []

        notes = dict(self.WATCH)
        cache_mtimes: list[datetime] = []

        for p in paths:
            try:
                st = p.stat()
            except (OSError, PermissionError) as exc:
                self.errs.from_exception(exc, "collect", self.name, str(p))
                continue

            mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
            ctime = datetime.fromtimestamp(st.st_ctime, timezone.utc)
            if p.name.startswith("f_"):
                cache_mtimes.append(mtime)

            if p.name.lower().endswith(".pf"):
                # 프리패치는 윈도가 직접 남기는 실행 기록이다. 수집만 하고
                # 판정하지 않으면 실행 시각이라는 1차 증거를 버리는 셈이다.
                self.emit(Record(
                    kind="prefetch_run", source=self.name, key=p.name,
                    value={"program": p.name.split("-")[0],
                           "prefetch": p.name,
                           "last_run_utc": to_utc_iso(mtime)},
                    ts_utc=to_utc_iso(mtime),
                    time_source=TimeSource.MFT.value,
                    ref=ArtifactRef.from_file(p, Storage.FILESYSTEM)))

            self.emit(Record(
                kind="fileinfo", source=self.name, key=p.name,
                value={"size": st.st_size,
                       "mtime_utc": to_utc_iso(mtime),
                       "ctime_utc": to_utc_iso(ctime),
                       "note": notes.get(p.name)},
                ts_utc=to_utc_iso(mtime),
                time_source=TimeSource.MFT.value,
                ref=ArtifactRef(path=str(p), storage=Storage.FILESYSTEM.value,
                                size=st.st_size,
                                note=notes.get(p.name)),
            ))

        # ── flush 수렴 판정 ────────────────────────────────────────────
        if detect_flush_convergence(cache_mtimes):
            span = max(cache_mtimes) - min(cache_mtimes)
            self.errs.add("warning", "MFT_FLUSH_CONVERGENCE", "parse", self.name,
                          f"캐시 파일 {len(cache_mtimes)}개의 수정 시각이 {span.total_seconds():.1f}초 안에 "
                          f"몰려 있다 — 앱 종료 시 일괄 flush로 보이므로 이 시각을 '대화 시각'으로 쓰면 안 된다")
            self.emit(Record(
                kind="time_warning", source=self.name, key="flush_convergence",
                value={"files": len(cache_mtimes),
                       "span_seconds": span.total_seconds(),
                       "converged_at": to_utc_iso(max(cache_mtimes))},
                ts_utc=to_utc_iso(max(cache_mtimes)),
                time_source=TimeSource.MFT.value,
                ref=ArtifactRef(path=str(self.root / "Cache" / "Cache_Data"),
                                storage=Storage.FILESYSTEM.value,
                                note="MFT 시각 수렴 — 신뢰도 하향 근거"),
            ))

        self._check_app_removed()
        self.errs.add("info", "FSMETA_SCAN", "parse", self.name,
                      f"파일 메타 {len(self.records)}건 수집")
        return self.records

    def _check_app_removed(self) -> None:
        """
        앱 루트 하위가 전부 삭제 엔트리면 **앱이 제거된 상태**다.

        제거해도 MFT 엔트리는 남기 때문에 '무엇이 있었는지'는 복원된다.
        본문이 살아 있는지는 클러스터 재할당 여부에 달렸고, 그 차이를 결과에 적는다.
        """
        backend = getattr(self.root, "backend", None)
        by_path = getattr(backend, "by_path", None)
        entries = getattr(backend, "entries", None)
        if not by_path or not entries:
            return
        base = self.root.rel.lower()
        if not base:
            return
        under = [entries[r] for p, r in by_path.items()
                 if p.startswith(base) and r in entries]
        if not under:
            return
        live = sum(1 for e in under if e.in_use)
        deleted = len(under) - live

        # 제거해도 빈 폴더가 남는 경우가 흔하다. '전부 삭제'만 보면 그런 제거를 놓친다.
        # 파일 엔트리 기준으로 얼마나 지워졌는지를 보고 확정과 정황을 나눈다.
        files = [e for e in under if not getattr(e, "is_dir", False)]
        file_deleted = sum(1 for e in files if not e.in_use)
        ratio = (file_deleted / len(files)) if files else 0.0

        if live == 0:
            level, note = "확정", "앱 루트 하위 엔트리가 전부 삭제 표시"
        elif files and ratio >= 0.9:
            level, note = ("정황",
                           f"앱 루트의 파일 {len(files)}건 중 {file_deleted}건"
                           f"({ratio:.0%})이 삭제 표시 — 폴더만 남은 제거로 보인다")
        else:
            return

        self.emit(Record(
            kind="app_removed", source=self.name, key="app_root",
            value={"entries_total": len(under), "entries_live": live,
                   "files_total": len(files), "files_deleted": file_deleted,
                   "deleted_ratio": round(ratio, 3), "level": level,
                   "note": f"{note} — 애플리케이션 제거 {level}"},
            ref=ArtifactRef(path=str(self.root), storage=Storage.FILESYSTEM.value,
                            recovered=True,
                            note=f"$MFT 삭제 엔트리 {deleted}건에서 구조 복원"),
        ))
        self.errs.add("info", "APP_REMOVED", "parse", self.name,
                      f"{note} — 제거된 앱을 $MFT에서 복원해 분석한다 ({level})")
