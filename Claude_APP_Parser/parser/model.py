"""정규화 레코드 모델.

프로젝트 필수 3항목:
  1) timestamp  — 근거에서 확인한 시각 (원본값·의미 보존)
  2) user_action — 증거가 뒷받침하는 사용자 행위 (특정 불가 시 '미확정')
  3) evidence   — 재확인 가능한 원본 위치 (이미지 식별자, 내부 경로, 행번호/DB키/MFT#)
세 항목은 항상 포함하되, 알 수 없는 값은 null + 사유로 표기한다.
"""

SCHEMA_VERSION = "1.0"

# 시각의 출처 (파일 수정시각을 메시지 전송시각으로 대체하지 않기 위해 명시)
TS_SOURCE_CONTENT = "artifact_content"   # 아티팩트 내부에 기록된 시각
TS_SOURCE_FILENAME = "artifact_filename"  # 파일명에 포함된 시각
TS_SOURCE_MFT = "ntfs_mft"               # 파일시스템 메타데이터 시각
TS_SOURCE_NONE = "none"

CONF_CONFIRMED = "확인"     # 아티팩트 내용이 행위를 직접 증명
CONF_INFERRED = "추정"      # 정황 증거 기반
CONF_UNKNOWN = "미확정"     # 행위 특정 불가

ACTION_UNKNOWN = "미확정"


def timestamp(utc=None, original=None, fmt=None, meaning=None,
              source=TS_SOURCE_NONE, tz_note=None, null_reason=None):
    if utc is None and null_reason is None:
        null_reason = "근거에서 해석 가능한 시각을 찾지 못함"
    return {
        "utc": utc,
        "original_value": original,
        "original_format": fmt,
        "meaning": meaning,
        "source": source,
        "timezone_note": tz_note,
        "null_reason": null_reason,
    }


def user_action(action=ACTION_UNKNOWN, confidence=CONF_UNKNOWN, rationale=None,
                observed=None):
    """observed: 행위를 특정할 수 없을 때 관찰된 Artifact 내용."""
    return {
        "action": action,
        "confidence": confidence,
        "rationale": rationale,
        "observed_artifact": observed,
    }


def evidence(image, vfile, locator=None, excerpt=None, artifact_sha256=None,
             extra=None):
    ev = {
        "image": image,             # {image_id, image_type, file_name, ...}
        "location": vfile.location() if vfile is not None else None,
        "locator": locator,         # 'line=12' / 'json_pointer=/a/b/0' / 'db_key=...'
        "artifact_sha256": artifact_sha256,
        "excerpt": excerpt,
    }
    if extra:
        ev.update(extra)
    return ev


class Record(dict):
    """출력 레코드 1건."""

    def __init__(self, record_id, event_id, event_name, ts, action, ev,
                 status="ok", errors=None, notes=None, details=None):
        super().__init__()
        self["schema_version"] = SCHEMA_VERSION
        self["record_id"] = record_id
        self["event"] = {"event_id": event_id, "event_name": event_name,
                         "catalog": "사용자 행위 분류표"}
        self["timestamp"] = ts
        self["user_action"] = action
        self["evidence"] = ev
        self["parse"] = {
            "status": status,                  # ok | partial | error
            "errors": errors or [],
            "notes": notes or [],
        }
        self["details"] = details or {}


class RecordBuilder:
    def __init__(self, prefix="R"):
        self._n = 0
        self._prefix = prefix

    def next_id(self):
        self._n += 1
        return "%s%06d" % (self._prefix, self._n)
