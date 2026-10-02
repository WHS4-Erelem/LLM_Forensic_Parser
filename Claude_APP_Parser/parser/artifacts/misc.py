"""캐시 · 설정 파일 · 프리패치.

캐시에는 대화 본문 엔드포인트(/chat_conversations/<uuid>)가 더 이상 남지 않는다.
지금 앱은 cowork 세션으로 동작하고 본문은 IndexedDB 로 간다. 다만 분석 비콘
URL 에 페이지 제목(t=)과 세션(u=)이 실려 있어 어떤 대화가 언제 열렸는지 알 수 있다.

응답 본문은 대부분 zstd 로 눌려 있다. 압축을 풀지 않으면 그 안을 볼 수 없어서,
평문만 훑으면 "캐시에 아무것도 없다" 는 잘못된 결론이 난다. 압축을 풀면
공유 스냅샷 목록이 나온다. 공유 링크를 언제 만들었는지는 여기에만 남는다.
"""

import io
import json
import re
from urllib.parse import parse_qs, unquote, urlparse

try:
    import zstandard
except ImportError:                     # 없으면 평문만 훑는다
    zstandard = None

from .. import events, model
from ..util import excerpt, parse_any_time

# 분석 비콘 — .../images/<n>.gif?…&t=<제목>&u=<페이지주소>&ua=…
# u= 는 URL 인코딩된 페이지 주소라 길다. 짧게 끊으면 cowork 세션 ID 를 놓친다.
BEACON = re.compile(r"s-cdn\.anthropic\.com/images/[^\"'\s\x00]{0,1200}")
COWORK_ID = re.compile(r"/cowork/(cse_[0-9A-Za-z]{10,40})")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# 프리패치 — 실행 횟수·마지막 실행 시각은 압축 해제가 필요해 파일 시각만 쓴다
PF_NAME = re.compile(r"^(?P<exe>[^-]+)-(?P<hash>[0-9A-F]{8})\.pf$", re.I)


ZSTD_MAGIC = bytes.fromhex("28b52ffd")
ZSTD_MAX = 8 * 1024 * 1024          # 프레임 하나에서 풀어 낼 최대 크기


def zstd_frames(data):
    """블록 안의 zstd 프레임을 모두 푼다. 잘린 프레임은 건질 수 있는 만큼만."""
    if zstandard is None:
        return
    dctx = zstandard.ZstdDecompressor()
    pos = 0
    while True:
        i = data.find(ZSTD_MAGIC, pos)
        if i < 0:
            return
        pos = i + 4
        try:
            yield dctx.decompressobj().decompress(data[i:])
            continue
        except Exception:
            pass
        try:                            # 응답이 중간에서 잘린 경우
            yield dctx.stream_reader(io.BytesIO(data[i:])).read(ZSTD_MAX)
        except Exception:
            continue


def _snapshot_records(blob, vfile, image, rb, max_excerpt):
    """공유 스냅샷 목록 — 공유 링크를 만든 시각이 여기에만 남는다."""
    try:
        obj = json.loads(blob.decode("utf-8", "replace"))
    except Exception:
        return []
    items = obj if isinstance(obj, list) else [obj]
    out = []
    for it in items:
        if not isinstance(it, dict) or not it.get("snapshot_name"):
            continue
        created = it.get("created_at")
        utc, fmt, note = parse_any_time(created)
        vis = it.get("visibility")
        out.append(model.Record(
            rb.next_id(), "E07-02", events.name("E07-02"),
            model.timestamp(utc=utc, original=created, fmt=fmt,
                            meaning="공유 스냅샷 생성 시각",
                            source=model.TS_SOURCE_CONTENT,
                            null_reason=None if utc else (note or "시각 해석 실패")),
            model.user_action("공유 링크 생성", model.CONF_CONFIRMED,
                              rationale="캐시에 남은 공유 스냅샷 목록에 생성 시각과 "
                                        "공개 범위(%s)가 기록됨" % vis),
            model.evidence(image, vfile, locator="zstd frame · share snapshot",
                           excerpt=excerpt(str(it.get("snapshot_name")), max_excerpt)),
            notes=["zstd_decompressed"],
            details={"artifact": "cache_block", "item_type": "share_snapshot",
                     "title": str(it.get("snapshot_name")),
                     "conversation_uuid": str(it.get("conversation_uuid") or ""),
                     "visibility": vis,
                     "snapshot_uuid": str(it.get("uuid") or "")}))
    return out


def parse_cache(vfile, image, rb, max_excerpt=500):
    """캐시 블록파일 — 평문 비콘 URL 과 zstd 로 눌린 응답 본문을 함께 훑는다."""
    data = vfile.read()
    text = data.decode("latin1", "replace")
    out, seen = [], set()
    if ZSTD_MAGIC in data:
        for blob in zstd_frames(data):
            if blob and b"snapshot_name" in blob:
                out.extend(_snapshot_records(blob, vfile, image, rb, max_excerpt))
    for m in BEACON.finditer(text):
        url = unquote(m.group(0))
        try:
            qs = parse_qs(urlparse("http://" + url).query)
        except ValueError:
            continue
        title = (qs.get("t") or [""])[0].strip()
        page = (qs.get("u") or [""])[0]
        cm = COWORK_ID.search(page)
        if not cm or not title:
            continue
        cid = "cowork:" + cm.group(1)
        if (cid, title) in seen:
            continue
        seen.add((cid, title))
        eid, act = _beacon_event(title, page)
        out.append(model.Record(
            rb.next_id(), eid, events.name(eid),
            model.timestamp(null_reason="비콘 URL 에 시각이 없음"),
            model.user_action(act, model.CONF_INFERRED,
                              rationale="분석 비콘에 대화 페이지 제목이 기록됨 — "
                                        "제목은 앱이 잘라 보내므로 원문 일부다"),
            model.evidence(image, vfile, locator="beacon", excerpt=excerpt(url, max_excerpt)),
            details={"artifact": "cache_block", "conversation_uuid": cid,
                     "title": title, "item_type": "beacon"}))
    return out


# 대화 제목이 곧 첫 프롬프트라, 제목에 남은 마커로 어떤 행위였는지 가른다.
_BY_MARKER = {
    "E0301": ("E03-01", "새로운 대화 생성"),
    "E0401": ("E04-01", "사용자 프롬프트 입력/전송"),
    "E0501": ("E05-01", "이미지 업로드"),
    "E0503": ("E05-03", "문서 업로드"),
    "E0601": ("E06-01", "이미지 생성 요청"),
    "E0701": ("E07-01", "대화 데이터 Export"),
    "E0702": ("E07-02", "공유 링크 생성"),
    "E0901": ("E09-01", "모델 변경"),
    "E1001": ("E10-01", "임시 채팅 사용"),
}
_MARKER_RE = re.compile(r"MRK_(E\d{4})")


def _beacon_event(title, page):
    """제목에 남은 마커로 행위를 가른다. 없으면 대화가 열린 사실만 본다."""
    m = _MARKER_RE.search(title)
    if m:
        hit = _BY_MARKER.get(m.group(1))
        if hit:
            return hit
    if "공유" in title or "/share" in page:
        return "E07-02", "공유 링크 생성"
    return "E03-01", "새로운 대화 생성"


def parse_config(vfile, image, rb, max_excerpt=500):
    """config.json 등 — 계정·조직 UUID, 정상 종료 근거."""
    raw = vfile.read()
    mtime = (vfile.si_times or {}).get("modified")
    name = vfile.path.rsplit("/", 1)[-1]
    det = {"artifact": "config", "key": name}
    try:
        obj = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        obj = None
    text = raw.decode("utf-8", "replace")
    ids = UUID.findall(text)
    if ids:
        det["account_uuid"] = ids[0]
        if len(ids) > 1:
            det["org_uuid"] = ids[1]
    out = []
    if isinstance(obj, dict):
        for k in ("model", "selectedModel", "lastModel"):
            if isinstance(obj.get(k), str):
                det["model"] = obj[k]
                break
    # config.json 은 종료 직전 다시 쓰인다 — 정상 종료의 직접 근거
    if name == "config.json":
        out.append(model.Record(
            rb.next_id(), "E08-02", events.name("E08-02"),
            model.timestamp(utc=mtime, original=mtime, meaning="설정 파일 재작성 시각",
                            source=model.TS_SOURCE_MFT,
                            null_reason=None if mtime else "파일 시각 없음"),
            model.user_action("정상 종료", model.CONF_INFERRED,
                              rationale="종료 직전 config.json 재작성"),
            model.evidence(image, vfile, locator="file"),
            details=dict(det, item_type="config_rewrite")))
    if ids:
        # 팀 매핑 규칙(2026-09-23, Claude Desktop 합의): 계정·조직 식별자가
        # 남아 있다는 것은 그 계정으로 로그인한 상태였다는 증거다. 새 행위명을
        # 만들지 않고 '로그인' 으로 올리며, 직접 증거가 아니라 정황이므로
        # 확신도는 의심으로 둔다. 식별자 자체는 Behavior_details 에 적는다.
        who = "계정 %s" % ids[0]
        if len(ids) > 1:
            who += " / 조직 %s" % ids[1]
        out.append(model.Record(
            rb.next_id(), "E01-01", events.name("E01-01"),
            model.timestamp(utc=mtime, original=mtime,
                            meaning="설정 파일 수정 시각",
                            source=model.TS_SOURCE_MFT,
                            null_reason=None if mtime else "파일 시각 없음"),
            model.user_action("로그인", model.CONF_INFERRED,
                              rationale="설정 파일에 계정·조직 식별자가 남아 있음 "
                                        "— 그 계정으로 로그인한 상태였다는 정황. "
                                        "인증 시각 자체는 아니다"),
            model.evidence(image, vfile, locator="file",
                           excerpt=excerpt(who, max_excerpt)),
            details=dict(det, item_type="identifiers", identifiers=who)))
    return out


def parse_prefetch(vfile, image, rb, max_excerpt=500):
    """프리패치 — 실행 사실. 설치 관리자면 설치로 본다."""
    name = vfile.path.rsplit("/", 1)[-1]
    m = PF_NAME.match(name)
    exe = (m.group("exe") if m else name).upper()
    mtime = (vfile.si_times or {}).get("modified")
    setup = "SETUP" in exe
    eid = "E02-01" if setup else "E08-01"
    return [model.Record(
        rb.next_id(), eid, events.name(eid),
        model.timestamp(utc=mtime, original=mtime, meaning="프리패치 파일 수정 시각",
                        source=model.TS_SOURCE_MFT,
                        tz_note="마지막 실행 시각은 파일 내부에 있으나 압축 해제 필요",
                        null_reason=None if mtime else "파일 시각 없음"),
        model.user_action("애플리케이션 설치" if setup else "애플리케이션 실행",
                          model.CONF_INFERRED, rationale="윈도 프리패치에 실행 기록"),
        model.evidence(image, vfile, locator="prefetch"),
        details={"artifact": "prefetch", "file_name": name, "item_type": exe})]
