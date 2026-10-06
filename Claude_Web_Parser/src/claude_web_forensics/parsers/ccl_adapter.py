"""Single place that absorbs ccl_chromium_reader version differences."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from ..model.entities import (STATE_HISTORICAL_OR_DELETED, STATE_LIVE, STATE_UNKNOWN,)
from ..util.common import get_attr_any, safe_str

CCL_COMMIT = "ef840de30221c4d65bc96d2f4d9057e9ef2f526d"
CCL_VERSION = "0.3.18"

_IMPORT_ERROR: str | None = None

try:
    from ccl_chromium_reader import (
        ccl_chromium_cache, ccl_chromium_indexeddb, ccl_chromium_localstorage, ccl_chromium_snss2,
    )
except Exception as exc:
    ccl_chromium_cache = None
    ccl_chromium_indexeddb = None
    ccl_chromium_localstorage = None
    ccl_chromium_snss2 = None
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

def import_error() -> str | None:
    return _IMPORT_ERROR

def ccl_provenance() -> dict[str, str]:
    return {"package": "ccl_chromium_reader", "version": CCL_VERSION, "commit": CCL_COMMIT}

def open_cache(cache_dir: Path) -> Any:
    if ccl_chromium_cache is None:
        raise RuntimeError(f"ccl_chromium_reader unavailable: {_IMPORT_ERROR}")
    cache_type = ccl_chromium_cache.guess_cache_class(cache_dir)
    if cache_type is None:
        raise RuntimeError(f"unrecognised Chromium cache layout at {cache_dir}")
    cache = cache_type(cache_dir)
    if hasattr(cache, "__enter__"):
        cache.__enter__()
    return cache

def close_cache(cache: Any) -> None:
    if cache is None:
        return
    try:
        cache.__exit__(None, None, None)
    except Exception:
        try:
            cache.close()
        except Exception:
            pass

def cache_keys(cache: Any) -> list[str]:
    try:
        return [safe_str(k) for k in cache.keys()]
    except Exception:
        return []

def header_pairs(meta: Any) -> list[tuple[str, str]]:
    attrs = get_attr_any(meta, "http_header_attributes", default=[]) or []
    out: list[tuple[str, str]] = []
    for item in attrs:
        try:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                name, value = item[0], item[1]
            elif isinstance(item, dict):
                name = item.get("name") or item.get("key")
                value = item.get("value")
            else:
                continue
            if name is not None and value is not None:
                out.append((safe_str(name).strip().lower(), safe_str(value).strip()))
        except Exception:
            continue
    return out

def header_value(meta: Any, name: str) -> str | None:
    target = name.casefold()
    values = [v for k, v in header_pairs(meta) if k == target]
    return ", ".join(values) if values else None

def _cache_list(cache: Any, method: str, key: str) -> list[Any]:
    try:
        return list(getattr(cache, method)(key))
    except Exception:
        return []

def cache_metadata(cache: Any, key: str) -> list[Any]:
    return _cache_list(cache, "get_metadata", key)

def cache_bodies(cache: Any, key: str) -> list[bytes]:
    return _cache_list(cache, "get_cachefile", key)

def cache_locations(cache: Any, key: str) -> tuple[list[Any], list[Any]]:
    return (_cache_list(cache, "get_location_for_metadata", key),
            _cache_list(cache, "get_location_for_cachefile", key))

def get_attr_any_meta(meta: Any, *names: str) -> Any:
    if meta is None:
        return None
    return get_attr_any(meta, *names, default=None)

def _file_name(value: Any) -> str:
    text = safe_str(value or "").strip()
    if not text or text == "None":
        return ""
    return text.replace("\\", "/").rsplit("/", 1)[-1]

def location_str(location: Any) -> str:
    if location is None:
        return ""
    source = get_attr_any(location, "source_file", "file_name", default="")
    offset = get_attr_any(location, "offset", default=None)
    if source or offset is not None:
        return f"{safe_str(source)}@{offset}"
    return safe_str(location)

@dataclass
class IdbRecord:
    database_name: str
    object_store: str
    origin: str
    key: Any
    key_text: str
    value: Any
    ldb_seq_no: int | None
    state: str
    external_value_path: str
    record_location: str

    origin_file: str = ""

    @property
    def locator(self) -> str:
        parts = [f"db={self.database_name}", f"store={self.object_store}"]
        if self.ldb_seq_no is not None:
            parts.append(f"seq={self.ldb_seq_no}")
        if self.record_location:
            parts.append(f"loc={self.record_location}")
        return ";".join(parts)

# A non-live version may be old or deleted; it does not prove deletion.
def _record_state(record: Any) -> str:
    value = get_attr_any(record, "is_live", default=None)
    if value is True:
        return STATE_LIVE
    if value is False:
        return STATE_HISTORICAL_OR_DELETED
    return STATE_UNKNOWN

def idb_key_text(key: Any) -> str:
    value = get_attr_any(key, "value", default=None)
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if value is not None:
        return safe_str(value)
    return safe_str(key)

def open_indexeddb(leveldb_dir: Path, blob_dir: Path | None) -> Any:
    if ccl_chromium_indexeddb is None:
        raise RuntimeError(f"ccl_chromium_reader unavailable: {_IMPORT_ERROR}")
    if blob_dir is not None and blob_dir.exists():
        try:
            return ccl_chromium_indexeddb.WrappedIndexDB(leveldb_dir, blob_dir)
        except TypeError:
            pass
    return ccl_chromium_indexeddb.WrappedIndexDB(leveldb_dir)

def iter_indexeddb_records(
    wrapper: Any, on_bad_record: Callable[[Any, bytes], None] | None = None,
    on_store_error: Callable[[str, Exception], None] | None = None,
) -> Iterator[IdbRecord]:
    for database_id in wrapper.database_ids:
        db_no = get_attr_any(database_id, "dbid_no", "db_id", default=None)
        try:
            database = wrapper[db_no] if db_no is not None else wrapper[database_id]
        except Exception as exc:
            if on_store_error:
                on_store_error(safe_str(database_id), exc)
            continue

        db_name = safe_str(get_attr_any(database, "name", "database_name", default=""))
        origin = safe_str(get_attr_any(database, "origin", "database_origin", default=""))

        for store_name in list(get_attr_any(database, "object_store_names", default=[]) or []):
            try:
                if hasattr(database, "get_object_store_by_name"):
                    store = database.get_object_store_by_name(store_name)
                else:
                    store = database[store_name]
                iterator = store.iterate_records(errors_to_stdout=False, bad_deserializer_data_handler=on_bad_record,)
                for record in iterator:
                    key = get_attr_any(record, "key", "user_key", default=None)
                    yield IdbRecord(
                        database_name=db_name, object_store=safe_str(store_name), origin=origin, key=key,
                        key_text=idb_key_text(key), value=get_attr_any(record, "value", default=None),
                        ldb_seq_no=get_attr_any(record, "ldb_seq_no", default=None),
                        state=_record_state(record), external_value_path=safe_str(get_attr_any(record,
                            "external_value_path", default="") or ""),
                        record_location=safe_str(get_attr_any(record, "record_location", default="") or ""),
                        origin_file=_file_name(get_attr_any(record, "origin_file", default="")),
                    )
            except Exception as exc:
                if on_store_error:
                    on_store_error(f"{db_name}/{store_name}", exc)
                continue

def close_indexeddb(wrapper: Any) -> None:
    if wrapper is not None and hasattr(wrapper, "close"):
        try:
            wrapper.close()
        except Exception:
            pass

@dataclass
class LocalStorageRecord:
    storage_key: str
    script_key: str
    value: Any
    seq: int | None

    origin_file: str = ""

    @property
    def locator(self) -> str:
        parts = [f"storage_key={self.storage_key}", f"key={self.script_key}"]
        if self.seq is not None:
            parts.append(f"seq={self.seq}")
        return ";".join(parts)

def iter_local_storage(
    leveldb_dir: Path, on_error: Callable[[str, Exception], None] | None = None,
) -> Iterator[LocalStorageRecord]:
    if ccl_chromium_localstorage is None:
        raise RuntimeError(f"ccl_chromium_reader unavailable: {_IMPORT_ERROR}")
    try:
        store = ccl_chromium_localstorage.LocalStoreDb(leveldb_dir)
    except Exception:
        # CCL reads every file while opening, so one damaged .log/.ldb loses the whole store. Rebuild it beside the
        # staged copy from the files that read cleanly on their own and report the rest.
        leveldb = ccl_chromium_localstorage.ccl_leveldb
        readable = leveldb_dir.with_name(leveldb_dir.name + "_readable")
        shutil.rmtree(readable, ignore_errors=True)
        readable.mkdir()
        for file in sorted(p for p in leveldb_dir.iterdir() if p.is_file()):
            reader = {".log": leveldb.LogFile, ".ldb": leveldb.LdbFile, ".sst": leveldb.LdbFile}.get(file.suffix.lower())
            try:
                if reader:
                    data = reader(file)
                    try:
                        for _ in data:
                            pass
                    finally:
                        data.close()
            except Exception as exc:
                if on_error:
                    on_error(f"{file.name} skipped (unreadable)", exc)
                continue
            shutil.copy2(file, readable / file.name)
        store = ccl_chromium_localstorage.LocalStoreDb(readable)
    try:
        for storage_key in store.iter_storage_keys():
            try:
                for record in store.iter_records_for_storage_key(storage_key):
                    seq = get_attr_any(
                        record, "leveldb_seq_number", "leveldb_sequence_number", "sequence_number",
                        default=None,
                    )
                    yield LocalStorageRecord(
                        storage_key=safe_str(storage_key),
                        script_key=safe_str(get_attr_any(record, "script_key", "key", default="")),
                        value=get_attr_any(record, "value", default=None), seq=seq,
                            origin_file=_file_name(get_attr_any(record, "file", "origin_file", default="")),
                    )
            except Exception as exc:
                if on_error:
                    on_error(safe_str(storage_key), exc)
                continue
    finally:
        try:
            store.close()
        except Exception:
            pass

@dataclass
class SnssCommand:
    file_name: str
    ordinal: int
    is_navigation: bool
    index: Any = None
    timestamp: Any = None
    title: str = ""
    url: str = ""
    original_request_url: str = ""
    referrer_url: str = ""

    @property
    def locator(self) -> str:
        return f"file={self.file_name};ordinal={self.ordinal}"

def iter_snss_commands(
    path: Path, on_error: Callable[[str, Exception], None] | None = None,
) -> Iterator[SnssCommand]:
    if ccl_chromium_snss2 is None:
        raise RuntimeError(f"ccl_chromium_reader unavailable: {_IMPORT_ERROR}")
    file_type = (
        ccl_chromium_snss2.SnssFileType.Session
        if path.name.startswith("Session_")
        else ccl_chromium_snss2.SnssFileType.Tab
    )
    try:
        with path.open("rb") as fh:
            snss = ccl_chromium_snss2.SnssFile(file_type, fh)
            ordinal = 0
            for command in snss.iter_session_commands():
                ordinal += 1
                is_nav = isinstance(command, ccl_chromium_snss2.NavigationEntry)
                if is_nav:
                    yield SnssCommand(
                        file_name=path.name, ordinal=ordinal, is_navigation=True,
                        index=get_attr_any(command, "index", default=None),
                        timestamp=get_attr_any(command, "timestamp", default=None),
                        title=safe_str(get_attr_any(command, "title", default="") or ""),
                        url=safe_str(get_attr_any(command, "url", default="") or ""),
                        original_request_url=safe_str(get_attr_any(command, "original_request_url", default="") or ""),
                        referrer_url=safe_str(get_attr_any(command, "referrer_url", default="") or ""),
                    )
                else:
                    yield SnssCommand(file_name=path.name, ordinal=ordinal, is_navigation=False,)
    except Exception as exc:
        if on_error:
            on_error(path.name, exc)
