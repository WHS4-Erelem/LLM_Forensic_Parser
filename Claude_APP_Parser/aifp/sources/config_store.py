"""
설정·상태 파일 리더.

config.json 은 이 트랙에서 계정 귀속의 핵심이다.
  - lastKnownAccountUuid / 조직 UUID 가 평문으로 들어 있다
  - **정상 종료 0.5초 전에 원자적으로 다시 쓰인다** → 종료 시각의 근거가 된다
    (강제 종료면 이 재작성이 일어나지 않는다 = E08-02 vs E08-03 판별)

plan-usage-history.json 의 samples 배열은 약 5분 간격 사용 기록이라
대화 본문이 없어도 **언제 앱을 쓰고 있었는지** 타임라인을 만들 수 있다.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..provenance import ArtifactRef, Storage
from ..timeutil import TimeSource, from_iso, from_unix, to_utc_iso
from .base import Record, Source

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _walk(obj: Any, path: str = "$"):
    """JSON 전체를 (경로, 키, 값)으로 훑는다. 어디서 나온 값인지 남기기 위함."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            yield p, k, v
            yield from _walk(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]"
            yield from _walk(v, p)


class ConfigSource(Source):
    name = "config"
    display = "설정·상태 파일"

    FILES = (
        ("config.json", "config"),
        ("ant-did", "device_id"),
        ("ant-device-registry.json", "device_registry"),
        ("window-state.json", "window_state"),
        ("plan-usage-history.json", "plan_usage"),
    )

    def locate(self) -> list[Path]:
        return [self.root / n for n, _ in self.FILES if (self.root / n).exists()]

    def read(self) -> list[Record]:
        found = 0
        for name, kind in self.FILES:
            p = self.root / name
            if not p.exists():
                self.errs.add("info", "TARGET_NOT_FOUND", "parse", self.name,
                              f"{name} 없음", str(p))
                continue
            data = self.safe_bytes(p)
            if data is None:
                continue
            self.manifest.add_file(p)
            found += 1
            with self.errs.guard("parse", self.name, str(p)):
                getattr(self, f"_read_{kind}", self._read_generic)(p, data)

        self.errs.add("info", "CONFIG_SCAN", "parse", self.name, f"설정 파일 {found}개 파싱")
        return self.records

    # ── 개별 파일 ───────────────────────────────────────────────────────
    def _read_config(self, path: Path, data: bytes) -> None:
        ref = ArtifactRef.from_file(path, Storage.CONFIGFILE)
        try:
            obj = json.loads(data.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            self.errs.add("warning", "ARTIFACT_CORRUPT", "parse", self.name,
                          f"config.json 파싱 실패: {exc}", str(path))
            return

        account = org = None
        first_launch = None
        interesting: dict[str, Any] = {}

        for jpath, key, val in _walk(obj):
            lk = key.lower()
            if isinstance(val, str):
                if "accountuuid" in lk.replace("_", ""):
                    account = val
                    interesting[jpath] = val
                elif "organization" in lk or "orguuid" in lk.replace("_", ""):
                    if UUID_RE.fullmatch(val):
                        org = val
                        interesting[jpath] = val
                elif "token" in lk:
                    interesting[jpath] = f"<{len(val)}자 토큰 — 마스킹>"
                elif UUID_RE.fullmatch(val) and len(interesting) < 40:
                    interesting[jpath] = val
            elif isinstance(val, (int, float)) and "launch" in lk:
                first_launch = from_unix(val)
                interesting[jpath] = val

        # 파일 자체의 수정 시각 = 마지막 정상 종료 시각의 근거
        mtime = None
        try:
            mtime = to_utc_iso(
                __import__("datetime").datetime.fromtimestamp(
                    path.stat().st_mtime, __import__("datetime").timezone.utc))
        except OSError:
            pass

        self.emit(Record(
            kind="account", source=self.name, key="config.json",
            value={"account_uuid": account, "org_uuid": org,
                   "first_launch_at": to_utc_iso(first_launch),
                   "fields": interesting},
            ts_utc=mtime,
            time_source=TimeSource.CONFIG.value,
            ref=ref,
            meta={"note": "정상 종료 직전 원자적 재작성 — 이 시각은 종료 시각의 근거"},
        ))

    def _read_device_id(self, path: Path, data: bytes) -> None:
        self.emit(Record(
            kind="device_id", source=self.name, key="ant-did",
            value={"device_id": data.decode("utf-8", "replace").strip(), "size": len(data)},
            ref=ArtifactRef.from_file(path, Storage.CONFIGFILE, note="기기 UUID"),
        ))

    def _read_device_registry(self, path: Path, data: bytes) -> None:
        ref = ArtifactRef.from_file(path, Storage.CONFIGFILE)
        try:
            obj = json.loads(data.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return
        uuids = list(dict.fromkeys(UUID_RE.findall(json.dumps(obj))))
        self.emit(Record(kind="device_registry", source=self.name,
                         key="ant-device-registry.json",
                         value={"uuids": uuids, "entries": len(obj) if hasattr(obj, "__len__") else 0},
                         ref=ref))

    def _read_window_state(self, path: Path, data: bytes) -> None:
        ref = ArtifactRef.from_file(path, Storage.CONFIGFILE,
                                    note="정상 종료 시 갱신 · 강제 종료 시 미갱신")
        mtime = to_utc_iso(
            __import__("datetime").datetime.fromtimestamp(
                path.stat().st_mtime, __import__("datetime").timezone.utc))
        try:
            obj = json.loads(data.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            obj = {}
        self.emit(Record(kind="window_state", source=self.name, key="window-state.json",
                         value=obj, ts_utc=mtime,
                         time_source=TimeSource.CONFIG.value, ref=ref))

    def _read_plan_usage(self, path: Path, data: bytes) -> None:
        """samples 배열 → 사용 구간 타임라인."""
        ref = ArtifactRef.from_file(path, Storage.CONFIGFILE)
        try:
            obj = json.loads(data.decode("utf-8", "replace"))
        except json.JSONDecodeError as exc:
            self.errs.add("warning", "ARTIFACT_CORRUPT", "parse", self.name,
                          f"plan-usage-history.json 파싱 실패: {exc}", str(path))
            return

        samples = obj.get("samples") if isinstance(obj, dict) else obj
        if not isinstance(samples, list):
            return

        emitted = 0
        for i, s in enumerate(samples):
            if not isinstance(s, dict):
                continue
            ts = None
            # 실제 형식: {"t": 1786758227382, "org": "<uuid>", "u": {...}}
            # 'ts'보다 't'를 먼저 보지 않으면 413건이 통째로 누락된다.
            for k in ("t", "timestamp", "time", "at", "created_at", "ts"):
                if k in s:
                    v = s[k]
                    ts = from_iso(v) if isinstance(v, str) else from_unix(v)
                    break
            if ts is None:
                continue
            flat = {k: v for k, v in s.items() if not isinstance(v, (dict, list))}
            if isinstance(s.get("u"), dict):
                flat["usage"] = s["u"]
            if s.get("org"):
                flat["org_uuid"] = s["org"]
            self.emit(Record(
                kind="usage_sample", source=self.name, key="plan-usage-history.json",
                value=flat,
                ts_utc=to_utc_iso(ts),
                time_source=TimeSource.APPLOG.value,
                ref=ArtifactRef(path=str(path), storage=Storage.CONFIGFILE.value,
                                locator=f"$.samples[{i}]", sha256=ref.sha256),
            ))
            emitted += 1
        self.errs.add("info", "USAGE_SAMPLES", "parse", self.name,
                      f"사용 기록 샘플 {emitted}건 — 약 5분 간격 활동 타임라인")

    def _read_generic(self, path: Path, data: bytes) -> None:
        self.emit(Record(kind="fileinfo", source=self.name, key=path.name,
                         value={"size": len(data)},
                         ref=ArtifactRef.from_file(path, Storage.CONFIGFILE)))
