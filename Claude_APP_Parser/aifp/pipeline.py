"""
파이프라인 오케스트레이션.

증거 열기 → 대상 탐지 → 수집 → 파싱 → 정규화 → 행위 매핑 → 교차 검증 → 출력 → 무결성 검증

세 원칙이 전 구간에 걸려 있다.

  **무결성** 입력은 디스크 이미지다. 마운트하지 않고 읽기 전용으로만 연다.
            분석 전후 이미지 해시를 비교해 원본 불변을 증명한다.
  **가용성** 하나가 실패해도 나머지는 계속 간다. 실패 사실을 결과에 남긴다.
  **기밀성** 산출물의 민감정보는 기본적으로 가린다.
"""

from __future__ import annotations

import hashlib as _hashlib
import shutil
import uuid as _uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .actions import ActionMapper, RuleSet, correlate
from .checkpoint import Checkpoint, CheckpointStore
from .errors import ErrorCollector
from .evidence import Evidence, VPath, open_evidence
from .provenance import Manifest
from .report import Reporter
from .schema import ParseResult
from .sources import Record, resolve as resolve_sources
from .timeutil import to_utc_iso

TOOL_VERSION = "aifp 1.9.0"


def normalize_app_root(spec) -> dict:
    """
    규칙 파일의 target.app_root 는 두 가지로 쓸 수 있다.

        "AppData/Roaming/Claude"                     — 경로 하나
        {"relative": ..., "alternatives": [...]}      — 설치 형태가 여럿일 때

    앞의 형태로 써도 죽지 않도록 뒤의 형태로 맞춰 준다.
    """
    if isinstance(spec, str):
        return {"relative": spec}
    if isinstance(spec, list):
        return {"relative": list(spec)}
    return spec or {}


def app_root_candidates(spec: dict) -> list[str]:
    """
    규칙 파일이 말하는 앱 루트 후보 경로를 순서대로 돌려준다.

    설치 형태마다 사용자 데이터 위치가 다르다(MSIX 패키지 컨테이너 / 일반 설치의
    %APPDATA%). `relative` 는 문자열도 목록도 되고, `alternatives` 로 더 얹을 수 있다.
    코드가 아니라 규칙 파일만 고쳐서 새 설치 형태를 지원하게 하기 위함이다.
    """
    rels: list[str] = []
    rel = spec.get("relative", "")
    if isinstance(rel, str):
        rels.append(rel)
    elif isinstance(rel, list):
        rels.extend(rel)
    rels.extend(spec.get("alternatives", []) or [])

    out: list[str] = []
    for r in rels:
        r = str(r or "").strip("/")
        if r and r not in out:
            out.append(r)
    return out


def locate_app_roots(root: VPath, spec: dict,
                     by_path: object = None) -> list[tuple[VPath, str]]:
    """
    증거 안에서 앱 루트를 전부 찾는다. (앱 루트, 매칭된 상대경로) 목록.

    이미지마다 사용자 계정 수도, 설치 형태도, 사용자 폴더 위치도 다르다.
    네 단계로 좁혀 가며 어떤 이미지든 스스로 찾게 한다. 아무것도 기록하지 않는
    순수 탐색이라 볼륨을 고르기 위한 사전 탐지에도 그대로 쓴다.
    """
    spec = normalize_app_root(spec)
    marker_files = spec.get("marker_files", []) or []
    marker_dirs = spec.get("marker_dirs", []) or []
    package_dir = (spec.get("package_dir") or "").lower()
    tail = (spec.get("tail") or "").lower()
    rels = app_root_candidates(spec)
    found: list[tuple[VPath, str]] = []

    # 1) 이미 앱 루트를 직접 가리킨 경우
    if (any((root / f).exists() for f in marker_files)
            or any((root / d).is_dir() for d in marker_dirs)):
        return [(root, "")]

    # 2) 사용자 프로필 루트를 가리킨 경우 — 한 사용자가 두 형태를 다 쓸 수 있다
    for rel in rels:
        direct = root.joinpath(*rel.split("/"))
        if direct.is_dir():
            found.append((direct, rel))
    if found:
        return found

    # 3) 볼륨 루트 — 사용자 계정마다, 설치 형태마다 하나씩
    users = root / "Users"
    if rels and users.is_dir():
        for u in users.iterdir():
            if not u.is_dir():
                continue
            for rel in rels:
                cand = u.joinpath(*rel.split("/"))
                if cand.is_dir():
                    found.append((cand, rel))

    if found:
        return found

    # 4) 경로 색인 전체 탐색 (사용자 폴더가 표준 위치에 없을 때)
    if by_path:
        seen: set[str] = set()
        for p in by_path:
            low = p.lower()
            for rel in rels:
                if low.endswith(rel.lower()) and p not in seen:
                    seen.add(p)
                    found.append((VPath(root.backend, p), rel))
                    break
            else:
                # 패키지 이름만 아는 경우의 보조 경로 (MSIX 등)
                if (package_dir and tail and p not in seen
                        and package_dir in low and low.endswith(tail)):
                    seen.add(p)
                    found.append((VPath(root.backend, p), rels[0] if rels else ""))

    return found


def find_app_roots(evidence: Evidence, target: dict,
                   errs: ErrorCollector) -> list[tuple[VPath, str]]:
    """
    증거 안에서 분석 대상 앱 루트를 전부 찾고, 못 찾으면 그 사실을 기록한다.
    경로 규칙은 코드가 아니라 **규칙 파일의 target.app_root**에서 온다.
    """
    spec = target.get("app_root", {})
    found = locate_app_roots(evidence.root, spec,
                             getattr(evidence.backend, "by_path", None))
    if not found:
        errs.add("info", "TARGET_NOT_FOUND", "collect", "root",
                 f"증거에서 {target.get('display', '대상')} 앱 루트를 찾지 못했다 — "
                 f"미설치이거나 다른 볼륨에 있을 수 있다")
    return found


def user_root_of(app_root: VPath, rel: str) -> VPath | None:
    """앱 루트에서 사용자 프로필 루트를 거슬러 올라간다."""
    p = app_root
    for _ in range(len(rel.split("/")) if rel else 0):
        p = p.parent
    return p if p.rel else None


def _root_key(app_root: VPath, rel: str) -> str:
    """로그·체크포인트·작업 폴더에서 이 앱 루트를 부르는 이름."""
    u = user_root_of(app_root, rel)
    return u.name if u and u.name else "user"


def _short_id(app_root: VPath) -> str:
    return _hashlib.sha1(str(app_root).encode("utf-8", "replace")).hexdigest()[:6]


def volume_root_of(app_root: VPath) -> VPath:
    return VPath(app_root.backend, "")


class Pipeline:
    def __init__(self, source: Path, rules_path: Path, *,
                 out_dir: Path | None = None,
                 case_id: str | None = None, tz: str = "UTC",
                 mode: str = "auto", volume_index: int | None = None,
                 workdir: Path | None = None, keep_work: bool = False,
                 unmask: bool = False, resume: bool = False,
                 extended_fs: bool = False,
                 verbose: bool = False) -> None:
        self.source = Path(source)
        self.rules_path = Path(rules_path)
        self.case_id = case_id or f"CASE-{datetime.now(timezone.utc):%Y%m%d}-{str(_uuid.uuid4())[:8]}"
        self.tz = tz
        self.mode = mode
        self.volume_index = volume_index
        self.out_dir = Path(out_dir) if out_dir else None
        self.workdir = workdir
        self.keep_work = keep_work
        self.unmask = unmask
        self.resume = resume
        self.extended_fs = extended_fs
        self.verbose = verbose
        self.errs = ErrorCollector(verbose=verbose)
        self.started_utc = to_utc_iso(datetime.now(timezone.utc))
        self.manifest = Manifest()

    def run(self) -> Reporter:
        ruleset = RuleSet(self.rules_path)
        if self.verbose:
            print(f"  규칙 {len(ruleset.rules)}개 로드 ({ruleset.version})")

        # ── 증거 열기 (읽기 전용, 마운트 없음) ──────────────────────────
        # 볼륨이 여럿인 이미지에서 대상이 어느 볼륨에 있는지는 미리 알 수 없다.
        # 볼륨을 열어 보고 대상이 있는 쪽을 고르도록 탐지 함수를 넘긴다.
        root_spec = ruleset.target.get("app_root", {})
        evidence = open_evidence(
            self.source, self.errs, mode=self.mode,
            volume_index=self.volume_index,
            probe=lambda backend: bool(locate_app_roots(
                VPath(backend, ""), root_spec, getattr(backend, "by_path", None))),
            probe_label=str(ruleset.target.get("display", "대상")))

        result = ParseResult(
            case_id=self.case_id,
            target_root="(미탐지)",
            tool_version=TOOL_VERSION,
            rule_version=ruleset.version,
        )

        # ── 재개 준비 ───────────────────────────────────────────────────
        # --resume 을 주지 않았으면 만들지 않는다. 산출물 폴더에는
        # CSV 두 개만 남아야 한다.
        store = CheckpointStore(self.out_dir) if (self.out_dir and self.resume) else None
        cur_cp = Checkpoint(
            case_id=self.case_id, tool_version=TOOL_VERSION,
            rule_version=ruleset.version, evidence_source=str(self.source),
            evidence_size=(evidence.container.size if evidence.container else 0),
            evidence_digest=(evidence.container.sources[0].sha256_open
                             if evidence.container and evidence.container.sources else ""),
        )
        records: list[Record] = []
        done_sources: list[str] = []
        if self.resume and store:
            prev, prev_records = store.load()
            if prev is None:
                self.errs.add("info", "RESUME_NONE", "collect", "pipeline",
                              "이어갈 체크포인트가 없다 — 처음부터 분석한다")
            else:
                ok, why = prev.matches(cur_cp)
                if ok:
                    records = list(prev_records)
                    done_sources = list(prev.done_sources)
                    self.case_id = prev.case_id
                    result.case_id = prev.case_id
                    cur_cp.case_id = prev.case_id
                    self.errs.add("info", "RESUME_OK", "collect", "pipeline",
                                  f"체크포인트에서 이어간다 — 완료된 리더 "
                                  f"{', '.join(done_sources)} · 레코드 {len(records)}건")
                else:
                    self.errs.add("warning", "RESUME_MISMATCH", "collect", "pipeline",
                                  f"체크포인트를 쓸 수 없다({why}) — 처음부터 분석한다")

        checked_paths: list[str] = []
        app_roots = find_app_roots(evidence, ruleset.target, self.errs)
        source_names = list(ruleset.target.get("sources", []))
        if self.extended_fs:
            source_names += list(ruleset.target.get("sources_extended", []))
        source_classes = resolve_sources(ruleset.service_key, source_names)
        if not source_classes:
            self.errs.add("warning", "NO_SOURCES", "parse", "pipeline",
                          f"규칙 파일이 지정한 리더를 찾지 못했다 "
                          f"(service_key={ruleset.service_key})")
        if app_roots:
            result.target_root = str(app_roots[0][0])
            if len(app_roots) > 1:
                self.errs.add("info", "MULTI_USER", "collect", "root",
                              f"사용자 프로필 {len(app_roots)}개에서 앱 루트 발견 — 전부 분석한다")
            layouts = sorted({rel for _, rel in app_roots if rel})
            if len(layouts) > 1:
                self.errs.add("info", "MULTI_LAYOUT", "collect", "root",
                              f"설치 형태 {len(layouts)}종을 함께 분석한다 — "
                              f"{' / '.join(layouts)}")

        # 작업 사본에는 증거 원문이 그대로 들어간다.
        # 작업 디렉터리에 흘리지 않고 **사건 폴더 안**에 두고, 끝나면 지운다.
        work = self.workdir or ((self.out_dir or Path.cwd()) / "_work")
        try:
            # 한 사용자에게 설치 형태가 둘 이상일 수 있다. 체크포인트 태그와 작업
            # 사본 폴더가 겹치면 뒤엣것이 앞엣것을 지워 버리므로 루트마다 구분한다.
            base_names = Counter(_root_key(r, rl) for r, rl in app_roots)

            seen_user_roots = []
            for app_root, app_rel in app_roots:
                if self.verbose:
                    print(f"  대상 루트: {app_root}")
                u_root = user_root_of(app_root, app_rel)
                if u_root is not None and str(u_root) not in [str(x) for x in seen_user_roots]:
                    seen_user_roots.append(u_root)
                v_root = volume_root_of(app_root)
                base = _root_key(app_root, app_rel)
                key = base if base_names[base] == 1 else f"{base}-{_short_id(app_root)}"
                sub_work = work / key

                for cls in source_classes:
                    # 볼륨·사용자 단위 리더를 앱 루트마다 돌리면 같은 일을 두 번 한다.
                    # 실제 이미지에서 40만 건짜리 변경 저널을 두 번 파싱하고 있었다.
                    scope = getattr(cls, "scope", "app")
                    scope_key = {"volume": str(v_root), "user": str(u_root)}.get(
                        scope, key)
                    tag = f"{scope_key}:{cls.name}"
                    if tag in done_sources:
                        if self.verbose:
                            print(f"  [{cls.name}] 건너뜀 (체크포인트에 완료됨)")
                        continue
                    src = cls(app_root, self.errs, self.manifest,
                              evidence=evidence, user_root=u_root,
                              volume_root=v_root, workdir=sub_work)
                    if self.verbose:
                        print(f"  [{src.name}] 읽는 중…")
                    with self.errs.guard("parse", src.name):
                        checked_paths.extend(str(p) for p in src.locate())
                    got = src.run()
                    records.extend(got)
                    done_sources.append(tag)
                    if store:
                        cur_cp.done_sources = done_sources
                        store.save(cur_cp, records)      # 리더 하나 끝날 때마다 저장
                    if self.verbose:
                        print(f"  [{src.name}] 레코드 {len(got)}건")

            if app_roots:
                # 감사 기록에는 실제로 분석한 루트가 전부 남아야 한다.
                # 한 사용자가 두 곳(로그 폴더와 데이터 폴더)을 쓰는 설치 형태가 있다.
                self.errs.add("info", "ROOTS_ANALYZED", "parse", "pipeline",
                              f"분석한 앱 루트 {len(app_roots)}곳 — "
                              + " · ".join(str(r) for r, _ in app_roots))
            self.errs.add("info", "PARSE_DONE", "parse", "pipeline",
                          f"전체 레코드 {len(records)}건 수집")

            # 데스크톱 쪽에서 대화를 하나도 못 건졌을 때만 본다.
            # "대화 없음"이라는 결론이 맞는지 한 번 더 확인하는 절차다.
            if not any(r.kind in ("message", "conversation") for r in records):
                from .sources.cache_store import scan_browser_conversations
                for u_root in seen_user_roots:
                    with self.errs.guard("parse", "cache"):
                        scan_browser_conversations(u_root, self.errs)

            # ── 행위 매핑 + 교차 검증 ───────────────────────────────────
            mapper = ActionMapper(ruleset, self.errs)
            events, negatives = mapper.map_all(records, checked_paths)
            events = correlate(events)
            for ev in events:
                result.add(ev)
        finally:
            # ── 무결성 검증 (분석 후 해시 재산출) ───────────────────────
            integrity = evidence.verify_and_close()
            self._dispose_work(work)

        if store:
            store.clear()          # 정상 종료 — 체크포인트 정리

        return Reporter(result, self.manifest, self.errs, negatives, self.tz,
                        records=records, started_utc=self.started_utc,
                        integrity=integrity, unmask=self.unmask)

    # ── 작업 사본 처리 ──────────────────────────────────────────────────
    def _dispose_work(self, work: Path) -> None:
        """
        작업 사본에는 증거 원문이 그대로 들어 있다.
        기본은 **덮어쓰고 삭제**한다. 파일명만 지우면 내용이 디스크에 남는다.
        """
        if not work.exists():
            return
        if self.keep_work:
            try:
                (work / "READ_ME_경고.txt").write_text(
                    "이 폴더에는 증거에서 추출한 원문 사본이 마스킹 없이 들어 있다.\n"
                    "사건 폴더 밖으로 내보내지 말고, 분석이 끝나면 삭제할 것.\n",
                    encoding="utf-8")
            except OSError:
                pass
            self.errs.add("warning", "WORKDIR_KEPT", "collect", "pipeline",
                          f"작업 사본을 보존했다 — 원문이 마스킹 없이 남아 있다: {work}")
            return

        wiped = failed = 0
        for p in sorted(work.rglob("*"), reverse=True):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
                with p.open("r+b") as f:       # 내용을 0으로 덮고 지운다
                    f.write(b"\x00" * min(size, 1 << 20))
                    f.flush()
                p.unlink()
                wiped += 1
            except OSError:
                failed += 1
        shutil.rmtree(work, ignore_errors=True)
        self.errs.add("info", "WORKDIR_WIPED", "collect", "pipeline",
                      f"작업 사본 안전 삭제 — {wiped}개 파일 덮어쓰기 후 제거"
                      + (f", {failed}개 실패" if failed else ""))
