"""claude_desktop_config.json — 수집·민감값 비노출·로그인 중복 방지 검증."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser import locate  # noqa: E402
from parser.artifacts import misc  # noqa: E402
from parser.model import RecordBuilder  # noqa: E402

ACCOUNT = "45c84a1c-a548-4b27-816a-baf90e8ab113"
ARG_UUID = "99999999-8888-4777-8666-555555555555"
TOKEN = "ghp_SECRETSECRETSECRET1234567890"
PATH = "/Users/u/AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude/claude_desktop_config.json"


class FakeFile:
    def __init__(self, data):
        self.data, self.path, self.size, self.allocated = data, PATH, len(data), True
        self.mft_record, self.si_times, self.fn_times = 7, {"modified": "2026-10-02T03:22:11Z"}, {}

    def read(self):
        return self.data

    def location(self):
        return {"path": self.path}


def parse(obj_or_bytes):
    data = obj_or_bytes if isinstance(obj_or_bytes, bytes) else json.dumps(obj_or_bytes).encode()
    return misc.parse_config(FakeFile(data), {"image_id": "t"}, RecordBuilder())


SAMPLE = {
    "mcpServers": {
        "github": {"command": "C:\\Program Files\\nodejs\\npx.cmd",
                   "args": ["-y", "@modelcontextprotocol/server-github", "--org", ARG_UUID],
                   "env": {"GITHUB_TOKEN": TOKEN}},
        "files": {"command": "uvx", "args": ["mcp-server-files", "C:\\secret\\folder"]},
    },
    "preferences": {"remoteToolsDeviceName": "LAB-PC",
                    "coworkModelAutoFallbackByAccount": {ACCOUNT: True}},
    "coworkUserFilesPath": "C:\\Users\\u\\Documents\\cowork",
}


class DesktopConfig(unittest.TestCase):
    def test_collected_by_locate(self):
        self.assertEqual(locate.classify(PATH)[0], "config")

    def test_observation_only_names_no_secrets(self):
        recs = parse(SAMPLE)
        self.assertEqual([r["event"]["event_id"] for r in recs], ["NA-00"])   # 로그인 행을 따로 만들지 않는다
        det = recs[0]["details"]
        self.assertEqual(det["mcp_servers"], ["files", "github"])
        self.assertEqual(det["mcp_server_commands"], {"github": "npx.cmd", "files": "uvx"})
        self.assertEqual(det["account_uuids"], [ACCOUNT])                     # 정해진 자리에서만
        dump = json.dumps(recs, ensure_ascii=False)
        for secret in (TOKEN, ARG_UUID, "secret\\\\folder", "Documents\\\\cowork", "Program Files"):
            self.assertNotIn(secret, dump)

    def test_no_shutdown_or_login_rules_from_config_json(self):
        """config.json 전용 규칙(정상 종료·식별자 로그인)이 이 파일에 적용되지 않는다."""
        recs = parse({"mcpServers": {}, "note": ARG_UUID})
        self.assertEqual([r["event"]["event_id"] for r in recs], ["NA-00"])
        self.assertEqual(recs[0]["details"]["account_uuids"], [])

    def test_broken_json_is_partial_not_crash(self):
        (r,) = parse(b"{not json")
        self.assertEqual((r["event"]["event_id"], r["parse"]["status"]), ("NA-00", "partial"))


if __name__ == "__main__":
    unittest.main()
