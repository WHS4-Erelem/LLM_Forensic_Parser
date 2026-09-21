"""
저장소 리더 레지스트리.

리더는 **서비스 네임스페이스**로 등록한다 — `claude-desktop.cache` 처럼.
서로 다른 서비스가 같은 이름의 리더(`cache`, `config` 등)를 가져도 충돌하지 않는다.

규칙 파일의 `target.sources`에 짧은 이름만 적으면
파이프라인이 `<service_key>.<name>`으로 찾아 쓴다. 규칙 파일 안에서는
그 서비스의 리더만 보이므로 짧은 이름으로 충분하다.

새 서비스를 붙이는 방법
  1. sources/<service>_*.py 에 Source 하위 클래스를 만든다
  2. 여기 register()로 등록한다
  3. rules/<service>.json 에 target.sources 로 나열한다
  코어 코드는 건드리지 않는다.
"""

from __future__ import annotations

from typing import Type

from .base import Record, Source

REGISTRY: dict[str, Type[Source]] = {}


def register(service_key: str, cls: Type[Source]) -> Type[Source]:
    REGISTRY[f"{service_key}.{cls.name}"] = cls
    return cls


def resolve(service_key: str, names: list[str]) -> list[Type[Source]]:
    """규칙 파일이 나열한 리더 이름을 클래스로 바꾼다. 모르는 이름은 건너뛴다."""
    out: list[Type[Source]] = []
    for n in names:
        cls = REGISTRY.get(f"{service_key}.{n}")
        if cls is not None:
            out.append(cls)
    return out


def available(service_key: str) -> list[str]:
    pre = f"{service_key}."
    return sorted(k[len(pre):] for k in REGISTRY if k.startswith(pre))


def _bootstrap() -> None:
    """기본 제공 리더 등록. import 시 한 번 실행된다."""
    from .cache_store import CacheSource
    from .config_store import ConfigSource
    from .fsextra_store import RecycleBinSource, UsnJrnlSource
    from .fsmeta_store import AppLogSource, FsMetaSource
    from .leveldb_store import BlobSource, IndexedDbSource, LocalStorageSource

    for cls in (CacheSource, IndexedDbSource, LocalStorageSource, BlobSource,
                ConfigSource, AppLogSource, FsMetaSource,
                UsnJrnlSource, RecycleBinSource):
        register("claude-desktop", cls)


_bootstrap()

__all__ = ["Record", "Source", "REGISTRY", "register", "resolve", "available"]
