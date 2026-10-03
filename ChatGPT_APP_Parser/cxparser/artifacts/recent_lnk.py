"""%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk — 윈도 최근 항목. Codex 가 파일을 저장하면 바로가기가 생긴다.

조사(2026-09-23, 평서문 표본):
  'Codex 이미지 2026년 9월 15일 오후 01_40_12.lnk' (13:40:19) → 바탕화면의 같은 이름 .png  : 정답 생성 이미지 다운로드 13:40:24 (5초 차)
  '간단한_학습_계획서.lnk' (13:38:14)                 → 바탕화면 .docx, 같은 초에 생성        : 정답 문서 다운로드 13:38:21 (7초 차)
  업로드한 파일(pdf)은 바로가기를 만들지 않았다 → 바로가기는 '저장' 흔적으로 본다.
조사(2026-09-28, 삭제 제외 raw 표본):
  '2019] 알기사 필기1(191224-수정)(4).lnk' (05:45:36) → Downloads 에 **확장자 없이** 저장된 2.4MB 파일, 첫 8바이트 %PDF-1.7 : 정답 문서 다운로드 05:45:35
  → 확장자만 보면 놓친다. 대상 파일 머리 바이트로 종류를 판별한다. 이름 뒤 '(4)' 는 윈도가 중복 저장에 붙인 번호.
규칙
  대상 파일명이 'Codex 이미지 …' 면 E06-02 생성 이미지 다운로드 (확인) — 앱 고유 명명.
  그 밖에는 대상 파일이 바로가기와 같은 시각(±15초)에 새로 생겼을 때만 저장 후보(추정):
    문서(확장자 또는 머리 바이트가 PDF·Office·텍스트) → E05-05 문서 다운로드 / 이미지·미확인 → E05-06 파일 다운로드.
  기존 문서를 열어서 생긴 바로가기(대상 생성 시각이 훨씬 이전)는 관찰(NA-00).
  어느 앱이 저장했는지는 바로가기에 없어, derive 에서 앱 실행 구간·Codex 대화의 파일명 언급으로 판정을 조정한다.
"""

import re
from datetime import datetime, timezone

from .. import events, model

DOC_EXT = {".docx", ".doc", ".pdf", ".txt", ".md", ".xlsx", ".xls", ".csv", ".pptx", ".hwp", ".hwpx", ".rtf"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\x00\"<>|*?\r\n]{3,300}")
IMAGE_PREFIX = "codex 이미지"
NEW_FILE_WINDOW_SEC = 15
_MAGIC = (  # (머리 바이트, 종류)
    (b"%PDF", "document"), (b"PK\x03\x04", "document"), (b"\xd0\xcf\x11\xe0", "document"), (b"{\\rtf", "document"),
    (b"\x89PNG", "image"), (b"\xff\xd8\xff", "image"), (b"GIF8", "image"), (b"RIFF", "image"), (b"BM", "image"),
)


def target_path(blob):
    """LinkInfo 의 LocalBasePath(ANSI) / 유니코드 경로 / 문자열 데이터 어디에 있든 드라이브 경로를 찾아 가장 긴 것을 택한다."""
    cands = set()
    for enc, offs in (("utf-16le", (0, 1)), ("mbcs", (0,)), ("cp949", (0,)), ("utf-8", (0,))):
        for off in offs:
            try:
                cands.update(_PATH_RE.findall(blob[off:].decode(enc, "ignore")))
            except LookupError:
                continue
    cands = [c.rstrip("\\ ") for c in cands if len(c.rsplit("\\", 1)[-1]) > 0]
    return max(cands, key=len) if cands else None


def _open_target(vfile, win_path):
    fs = getattr(vfile, "_fs", None)
    if fs is None or not win_path or len(win_path) < 3:
        return None
    try:
        return fs.open(win_path[2:].replace("\\", "/"))
    except Exception:  # noqa: BLE001
        return None


def _target_info(vfile, win_path):
    """대상 파일의 (MFT 생성 시각 ISO, 크기, 머리 바이트로 판별한 종류). 이미지(TSK)면 직접 열고,
    폴더 입력이면 호스트 도구가 넘긴 메타데이터(_host_metadata.json)를 쓴다. 둘 다 없으면 (None, None, None)."""
    f = _open_target(vfile, win_path)
    if f is None:
        host_stat = getattr(vfile._source, "host_stat", None)
        m = host_stat(win_path[2:]) if host_stat and win_path and len(win_path) > 2 else None
        if not m:
            return None, None, None
        head = bytes.fromhex(m.get("head_hex") or "")
        return ((m.get("times") or {}).get("created"), m.get("size"),
                next((k for magic, k in _MAGIC if head.startswith(magic)), "unknown" if head else None))
    meta = f.info.meta
    created = datetime.fromtimestamp(meta.crtime, tz=timezone.utc).isoformat().replace("+00:00", "Z") if meta.crtime else None
    kind = None
    try:
        head = f.read_random(0, min(8, meta.size)) if meta.size else b""
        kind = next((k for magic, k in _MAGIC if head.startswith(magic)), "unknown" if head else None)
    except Exception:  # noqa: BLE001
        pass
    return created, meta.size, kind


def _secs(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def parse(vfile, image_desc, rb, max_excerpt=500):
    name = vfile.path.rsplit("/", 1)[-1]
    target = target_path(vfile.read())
    base = (target or name[:-4]).rsplit("\\", 1)[-1]
    ext = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base and len(base.rsplit(".", 1)[-1]) <= 5 else ""
    created = vfile.si_times.get("created")
    ts = model.timestamp(utc=created, meaning="바로가기(.lnk) 파일의 MFT 생성 시각 = 저장 직후", source=model.TS_SOURCE_MFT,
                         null_reason=None if created else "바로가기 파일의 생성 시각을 읽지 못함")
    common = {"artifact": "recent_lnk", "lnk": name, "file_name": base, "file_path": target}
    if base.lower().startswith(IMAGE_PREFIX) or name.lower().startswith(IMAGE_PREFIX):
        return [model.Record(
            rb.next_id(), "E06-02", events.name("E06-02"), ts,
            model.user_action(action="생성 이미지 저장", confidence=model.CONF_CONFIRMED,
                              rationale="최근 항목 바로가기의 대상이 'Codex 이미지 <날짜>' — 앱이 생성 이미지를 저장할 때 붙이는 이름"),
            model.evidence(image_desc, vfile, locator="lnk_target=%s" % (target or "-")), status="ok", details=common)]
    if target is None or target.lower().startswith(("http", "ms-")) or ext in (".lnk", ".exe", ".url"):
        return []                                                  # 폴더·URL·프로그램 바로가기는 저장 흔적이 아니다
    tgt_created, tgt_size, kind = _target_info(vfile, target)
    if tgt_created is None and ext not in DOC_EXT | IMAGE_EXT:
        return []                                                  # 대상을 못 열고 확장자도 단서가 없으면 판단할 근거가 없다
    if tgt_created and created and abs(_secs(tgt_created) - _secs(created)) > NEW_FILE_WINDOW_SEC:
        return [model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"), ts,
            model.user_action(observed="최근 항목: %s (대상 파일은 %s 에 이미 존재)" % (base, tgt_created[:19]),
                              rationale="바로가기보다 훨씬 전에 만들어진 파일을 연 흔적 — 저장(다운로드)이 아님"),
            model.evidence(image_desc, vfile, locator="lnk_target=%s" % target), status="ok",
            details={**common, "target_created_utc": tgt_created, "candidate_event": None})]
    is_doc = ext in DOC_EXT or kind == "document"
    is_img = ext in IMAGE_EXT or kind == "image"
    eid = "E05-05" if is_doc else "E05-06"
    how = ("확장자 %s" % ext) if ext else ("머리 바이트로 %s 판별" % ({"document": "문서(PDF/Office)", "image": "이미지"}.get(kind, "종류 미확인")) if kind else "확장자 없음, 대상 미확인")
    note = ("대상 파일이 바로가기와 같은 시각에 새로 생김 (생성 %s, %s)" % (tgt_created[:19], how)) if tgt_created else "대상 파일의 생성 시각은 확인하지 못함 (%s)" % how
    return [model.Record(
        rb.next_id(), eid, events.name(eid), ts,
        model.user_action(action="문서 저장(새 파일)" if is_doc else ("이미지 저장(새 파일)" if is_img else "파일 저장(새 파일)"), confidence=model.CONF_INFERRED,
                          rationale=("최근 항목 바로가기 + %s — Codex 가 파일을 내려 저장한 흔적으로 추정. "
                                     "어느 앱이 저장했는지는 바로가기에 없어 앱 실행 구간·대화 언급과 대조한다 (derive)") % note),
        model.evidence(image_desc, vfile, locator="lnk_target=%s" % target), status="ok", notes=[note],
        details={**common, "target_created_utc": tgt_created, "target_size": tgt_size, "target_kind": kind or ext or None})]


if __name__ == "__main__":  # python -m cxparser.artifacts.recent_lnk — 경로 추출 자체 검사
    blob = b"\x4c\x00\x00\x00" + "C:\\Users\\a\\Desktop\\x.docx".encode("cp949") + b"\x00\x00" + "C:\\Users\\a\\Desktop\\간단한_학습_계획서.docx".encode("utf-16le") + b"\x00\x00"
    assert target_path(blob) == "C:\\Users\\a\\Desktop\\간단한_학습_계획서.docx", target_path(blob)
    assert target_path("C:\\Users\\a\\Downloads\\2019] 알기사 필기1(191224-수정)(4)".encode("utf-16le")) == "C:\\Users\\a\\Downloads\\2019] 알기사 필기1(191224-수정)(4)"
    assert target_path(b"no path here") is None
    print("recent_lnk self-check ok")
