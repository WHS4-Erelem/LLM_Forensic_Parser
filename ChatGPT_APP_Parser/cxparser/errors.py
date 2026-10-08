"""파서 전역 예외/오류 분류.

프로젝트 요구: 이미지 열기 실패, 세그먼트 누락, 미지원 형식, Artifact 미발견,
손상/부분 파싱을 서로 구분하고, 실패를 빈 결과나 성공으로 숨기지 않는다.
"""


class CxError(Exception):
    """모든 파서 오류의 기반. code 로 분류한다."""

    code = "CX_ERROR"

    def __init__(self, message, **context):
        super().__init__(message)
        self.message = message
        self.context = context

    def to_dict(self):
        return {"code": self.code, "message": self.message, "context": self.context}


class ImageOpenError(CxError):
    """이미지 파일을 열 수 없음 (경로 없음, 권한, 헤더 손상)."""
    code = "IMAGE_OPEN_FAILED"


class MissingSegmentError(CxError):
    """분할 이미지(E01/E02.../.dd.001...)의 세그먼트 누락."""
    code = "SEGMENT_MISSING"


class UnsupportedFormatError(CxError):
    """지원하지 않는 이미지/파일시스템 형식."""
    code = "UNSUPPORTED_FORMAT"


class VolumeLockedError(CxError):
    """BitLocker 볼륨을 풀지 못함 (키 없음·키 틀림·dissect.fve 없음). 빈 결과로 숨기지 않는다."""
    code = "VOLUME_LOCKED"


class FilesystemError(CxError):
    """파일시스템 구조 판독 실패."""
    code = "FILESYSTEM_ERROR"


class ArtifactNotFoundError(CxError):
    """대상 아티팩트를 이미지에서 찾지 못함 (빈 결과와 구분)."""
    code = "ARTIFACT_NOT_FOUND"


class CorruptArtifactError(CxError):
    """아티팩트가 손상되어 전체 파싱 불가 (부분 파싱은 record 단위 status 로 표시)."""
    code = "ARTIFACT_CORRUPT"
