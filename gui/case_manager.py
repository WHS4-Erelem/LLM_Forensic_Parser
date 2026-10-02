"""사건 정보(case_info.json) 저장·읽기.

사건 정보는 Parser 결과에 쓰지 않는다. 결과 폴더 안에 별도 파일로만 둔다
(통합 Runner 가 만든 timeline.csv / unified.db / integration_report.json 은 건드리지 않는다).
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

CASE_JSON = "case_info.json"


@dataclass
class CaseInfo:
    case_name: str = ""
    case_number: str = ""
    examiner: str = ""
    notes: str = ""
    created_at: str = ""

    def with_timestamp(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        return self

    def is_empty(self):
        return not any((self.case_name, self.case_number, self.examiner, self.notes))

    def save(self, result_dir):
        """결과 폴더에 case_info.json 을 쓴다 (기존 산출물은 수정하지 않는다). 반환: 쓴 경로."""
        os.makedirs(result_dir, exist_ok=True)
        path = os.path.join(result_dir, CASE_JSON)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self.with_timestamp()), fh, ensure_ascii=False, indent=2)
        return path

    @classmethod
    def load(cls, result_dir):
        path = os.path.join(result_dir, CASE_JSON)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return None
        return cls(**{k: str(data.get(k, "")) for k in
                      ("case_name", "case_number", "examiner", "notes", "created_at")})
