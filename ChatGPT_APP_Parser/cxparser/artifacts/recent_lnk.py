"""%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk — 윈도 최근 항목. Codex 가 파일을 저장하면 바로가기가 생긴다.

조사(2026-09-23, 평서문 표본):
  'Codex 이미지 2026년 9월 15일 오후 01_40_12.lnk' (13:40:19) → 바탕화면의 같은 이름 .png  : 정답 생성 이미지 다운로드 13:40:24 (5초 차)
  '간단한_학습_계획서.lnk' (13:38:14)                 → 바탕화면 .docx, 같은 초에 생성        : 정답 문서 다운로드 13:38:21 (7초 차)
  업로드한 파일(pdf)은 바로가기를 만들지 않았다 → 바로가기는 '저장' 흔적으로 본다.
규칙
  대상 파일명이 'Codex 이미지 …' 면 E06-02 생성 이미지 다운로드 (확인) — 앱 고유 명명.
  대상이 문서 확장자면 E05-05 문서 다운로드 후보 (추정). 대상 파일이 바로가기와 같은 시각(±15초)에 새로 생겼을 때만.
  기존 문서를 열어서 생긴 바로가기(대상 생성 시각이 훨씬 이전)는 관찰(NA-00). 앱 실행 구간 밖의 후보는 derive 에서 미확정으로 내린다.
"""

import re
from datetime import datetime, timezone

from .. import events, model

DOC_EXT = {".docx", ".doc", ".pdf", ".txt", ".md", ".xlsx", ".xls", ".csv", ".pptx", ".hwp", ".hwpx", ".rtf"}
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\x00\"<>|*?\r\n]{3,300}")
IMAGE_PREFIX = "codex 이미지"
NEW_FILE_WINDOW_SEC = 15


def target_path(blob):
    """LinkInfo 의 LocalBasePath(ANSI) / 유니코드 경로 / 문자열 데이터 어디에 있든 드라이브 경로를 찾아 가장 긴 것을 택한다."""
    cands = set()
    for enc, offs in (("utf-16le", (0, 1)), ("mbcs", (0,)), ("cp949", (0,)), ("utf-8", (0,))):
        for off in offs:
            try:
                cands.update(_PATH_RE.findall(blob[off:].decode(enc, "ignore")))
            except LookupError:
                continue
    cands = [c.rstrip("\\ ") for c in cands if "." in c.rsplit("\\", 1)[-1]]
    return max(cands, key=len) if cands else None


def _target_created(vfile, win_path):
    """대상 파일의 MFT 생성 시각(ISO). 이미지(TSK)일 때만 가능. 못 열면 None."""
    fs = getattr(vfile, "_fs", None)
    if fs is None or not win_path or len(win_path) < 3:
        return None
    try:
        f = fs.open(win_path[2:].replace("\\", "/"))
        ct = f.info.meta.crtime
        return datetime.fromtimestamp(ct, tz=timezone.utc).isoformat().replace("+00:00", "Z") if ct else None
    except Exception:  # noqa: BLE001
        return None


def _secs(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def parse(vfile, image_desc, rb, max_excerpt=500):
    name = vfile.path.rsplit("/", 1)[-1]
    target = target_path(vfile.read())
    base = (target or name[:-4]).rsplit("\\", 1)[-1]
    ext = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""
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
    if ext not in DOC_EXT:
        return []
    tgt_created = _target_created(vfile, target)
    if tgt_created and created and abs(_secs(tgt_created) - _secs(created)) > NEW_FILE_WINDOW_SEC:
        return [model.Record(
            rb.next_id(), "NA-00", events.name("NA-00"), ts,
            model.user_action(observed="최근 항목: %s (대상 파일은 %s 에 이미 존재)" % (base, tgt_created[:19]),
                              rationale="바로가기보다 훨씬 전에 만들어진 문서를 연 흔적 — 저장(다운로드)이 아님"),
            model.evidence(image_desc, vfile, locator="lnk_target=%s" % target), status="ok",
            details={**common, "target_created_utc": tgt_created, "candidate_event": None})]
    note = ("대상 파일이 바로가기와 같은 시각에 새로 생김 (생성 %s)" % tgt_created[:19]) if tgt_created else "대상 파일의 생성 시각은 확인하지 못함"
    return [model.Record(
        rb.next_id(), "E05-05", events.name("E05-05"), ts,
        model.user_action(action="문서 저장(새 파일)", confidence=model.CONF_INFERRED,
                          rationale=("최근 항목 바로가기 + %s — Codex 가 문서를 내려 저장한 흔적으로 추정. "
                                     "어느 앱이 저장했는지는 바로가기에 없어 앱 실행 구간과 대조한다 (derive)") % note),
        model.evidence(image_desc, vfile, locator="lnk_target=%s" % (target or "-")), status="ok", notes=[note],
        details={**common, "target_created_utc": tgt_created})]


if __name__ == "__main__":  # python -m cxparser.artifacts.recent_lnk — 경로 추출 자체 검사
    blob = b"\x4c\x00\x00\x00" + "C:\\Users\\a\\Desktop\\x.docx".encode("cp949") + b"\x00\x00" + "C:\\Users\\a\\Desktop\\간단한_학습_계획서.docx".encode("utf-16le") + b"\x00\x00"
    assert target_path(blob) == "C:\\Users\\a\\Desktop\\간단한_학습_계획서.docx", target_path(blob)
    assert target_path(b"no path here") is None
    print("recent_lnk self-check ok")
