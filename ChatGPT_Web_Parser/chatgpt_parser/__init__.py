"""
ChatGPT Web Artifact Parser — 팀 통합용 공개 API.

Disk Image(E01 / DD·RAW) 또는 분석용 폴더에서 ChatGPT Web(Chrome) 흔적을 찾아
"Timestamp + 사용자 행위" 와 "복구된 대화 내용" 을 돌려준다.

최소 사용법
    from chatgpt_parser import analyze_chatgpt_web, write_final_outputs

    result = analyze_chatgpt_web(r"D:\\CASE\\POST", input_type="dir")   # 파일을 쓰지 않는다
    for event in result.events:
        print(event.timestamp_kst, event.action, event.action_status)
    write_final_outputs(result, r"D:\\CASE\\out")                        # timeline.csv + recovered_conversations.csv

내부 Reader·Rule·Cache carving 구현은 하위 모듈에 있고, 여기서는 통합에 필요한 것만 공개한다.
인자·반환 필드는 README 의 "Python 통합" 절에 있다.
"""
from .constants import PARSER_NAME, PARSER_VERSION, SERVICE
from .image import ImageOpenError, open_image_source
from .models import (
    ArtifactRecord,
    Coverage,
    Event,
    EvidenceItem,
    InputInfo,
    ParseResult,
    RecoveredConversation,
    RecoveredMessage,
)
from .output.csv_writer import CSV_DEBUG_FILES, CSV_FINAL_FILES, write_result_csv
from .output.debug import write_result_json
from .output.final_csv import CSV_RECOVERED_CONVERSATION_COLUMNS, CSV_TIMELINE_COLUMNS
from .parser import analyze_chatgpt_web, detect, extract, run, write_final_outputs
from .source import DirectorySource, Source

__all__ = [
    "analyze_chatgpt_web",
    "write_final_outputs",
    "run",
    "extract",
    "detect",
    "ParseResult",
    "Coverage",
    "ArtifactRecord",
    "EvidenceItem",
    "Event",
    "RecoveredConversation",
    "RecoveredMessage",
    "InputInfo",
    "Source",
    "DirectorySource",
    "open_image_source",
    "ImageOpenError",
    "write_result_json",
    "write_result_csv",
    "CSV_TIMELINE_COLUMNS",
    "CSV_RECOVERED_CONVERSATION_COLUMNS",
    "CSV_FINAL_FILES",
    "CSV_DEBUG_FILES",
    "PARSER_NAME",
    "PARSER_VERSION",
    "SERVICE",
]
