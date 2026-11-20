"""JSON文件持久化层：所有领域服务共享的本地存储能力。

提供原子写入、分区目录管理和数据版本号支持。
每个领域服务通过其MODULE名称自动获得独立的JSON文件存储。
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class JsonStore:
    """线程安全的多分区JSON文件存储。

    每个分区(key)存储为一个独立的JSON文件。
    使用原子写（先写临时文件，再rename）避免写入中断导致数据损坏。
    """

    def __init__(self, base_dir: str | None = None) -> None:
        if base_dir is None:
            base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data_store")
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._caches: dict[str, dict[str, Any]] = {}

    def _file_path(self, key: str) -> Path:
        """获取分区对应的JSON文件路径。"""
        safe_key = key.replace("/", "_").replace("\\", "_")
        partition_dir = safe_key.rsplit("_", 1)[0] if "_" in safe_key else "default"
        partition_path = self._base_dir / partition_dir
        partition_path.mkdir(parents=True, exist_ok=True)
        return partition_path / f"{safe_key}.json"

    def _read_raw(self, key: str) -> dict[str, Any]:
        """从磁盘读取分区的原始数据。"""
        path = self._file_path(key)
        if not path.exists():
            return {"_meta": {"key": key, "version": 0, "updated_at": None}, "records": []}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"_meta": {"key": key, "version": 0, "updated_at": None}, "records": []}

    def _write_raw(self, key: str, data: dict[str, Any]) -> None:
        """原子写入分区数据到磁盘。"""
        path = self._file_path(key)
        tmp_path = path.with_suffix(".tmp")
        json_text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(json_text)
        tmp_path.replace(path)

    def get_all(self, key: str) -> list[dict[str, Any]]:
        """获取分区所有记录。"""
        with self._lock:
            data = self._read_raw(key)
            return list(data.get("records", []))

    def get_by_id(self, key: str, record_id: int) -> dict[str, Any] | None:
        """按ID获取单条记录。"""
        records = self.get_all(key)
        for record in records:
            if record.get("id") == record_id:
                return dict(record)
        return None

    def insert(self, key: str, record: dict[str, Any]) -> dict[str, Any]:
        """插入一条新记录，自动分配ID和时间戳。"""
        with self._lock:
            data = self._read_raw(key)
            records = data.get("records", [])
            max_id = max((int(r.get("id", 0)) for r in records), default=0)
            record["id"] = max_id + 1
            record["created_at"] = datetime.now(timezone.utc).isoformat()
            record["updated_at"] = record["created_at"]
            records.append(record)
            data["_meta"]["version"] = data["_meta"].get("version", 0) + 1
            data["_meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._write_raw(key, data)
            return dict(record)

    def update(self, key: str, record_id: int, updates: dict[str, Any]) -> dict[str, Any] | None:
        """更新一条记录。"""
        with self._lock:
            data = self._read_raw(key)
            records = data.get("records", [])
            for i, record in enumerate(records):
                if record.get("id") == record_id:
                    records[i].update(updates)
                    records[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    data["_meta"]["version"] = data["_meta"].get("version", 0) + 1
                    data["_meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    self._write_raw(key, data)
                    return dict(records[i])
            return None

    def delete(self, key: str, record_id: int) -> bool:
        """删除一条记录。"""
        with self._lock:
            data = self._read_raw(key)
            records = data.get("records", [])
            for i, record in enumerate(records):
                if record.get("id") == record_id:
                    records.pop(i)
                    data["_meta"]["version"] = data["_meta"].get("version", 0) + 1
                    data["_meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    self._write_raw(key, data)
                    return True
            return False

    def find_one(self, key: str, predicate) -> dict[str, Any] | None:
        """按谓词查找单条记录，返回副本；未命中返回 None。"""
        for record in self.get_all(key):
            if predicate(record):
                return dict(record)
        return None

    def insert_if_absent(self, key: str, predicate, record: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """原子条件插入：锁内先按谓词检查，已存在则返回既有记录。

        返回 (记录, 是否新插入)。用于并发场景下保证同一业务键
        （如检查指纹、告警指纹）只落一份数据。
        """
        with self._lock:
            data = self._read_raw(key)
            records = data.get("records", [])
            for existing in records:
                if predicate(existing):
                    return dict(existing), False
            max_id = max((int(r.get("id", 0)) for r in records), default=0)
            record["id"] = max_id + 1
            record["created_at"] = datetime.now(timezone.utc).isoformat()
            record["updated_at"] = record["created_at"]
            records.append(record)
            data["_meta"]["version"] = data["_meta"].get("version", 0) + 1
            data["_meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._write_raw(key, data)
            return dict(record), True

    def update_if(self, key: str, record_id: int, predicate, updates: dict[str, Any]) -> dict[str, Any] | None:
        """条件更新（compare-and-set）：仅当谓词对当前记录成立时才写入。

        与 update 的区别在于谓词校验和写入在同一把存储锁内完成，
        供并发确认场景做幂等保护，避免两个请求重复确认同一条结论。
        条件不成立时返回 None，调用方可据此重新读取最新记录。
        """
        with self._lock:
            data = self._read_raw(key)
            records = data.get("records", [])
            for i, record in enumerate(records):
                if record.get("id") == record_id:
                    if not predicate(record):
                        return None
                    records[i].update(updates)
                    records[i]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    data["_meta"]["version"] = data["_meta"].get("version", 0) + 1
                    data["_meta"]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    self._write_raw(key, data)
                    return dict(records[i])
            return None

    def query(self, key: str, filters: dict[str, Any] | None = None,
              keyword: str | None = None, search_fields: list[str] | None = None,
              page: int = 1, size: int = 20) -> tuple[list[dict[str, Any]], int]:
        """分页查询记录，支持多字段过滤和关键词搜索。"""
        records = self.get_all(key)
        if filters:
            for field, value in filters.items():
                if value is not None and str(value).strip():
                    records = [
                        r for r in records
                        if str(value).casefold() in str(r.get(field, "")).casefold()
                    ]
        if keyword and search_fields:
            filtered = []
            kw = keyword.casefold()
            for record in records:
                for field in search_fields:
                    if kw in str(record.get(field, "")).casefold():
                        filtered.append(record)
                        break
            records = filtered
        total = len(records)
        start = (page - 1) * size
        return records[start:start + size], total

    def aggregate(self, key: str, group_by: str) -> dict[str, int]:
        """按字段分组统计计数。"""
        records = self.get_all(key)
        result: dict[str, int] = {}
        for record in records:
            val = str(record.get(group_by, "未知"))
            result[val] = result.get(val, 0) + 1
        return result

    def get_version(self, key: str) -> int:
        """获取分区的数据版本号。"""
        data = self._read_raw(key)
        return data.get("_meta", {}).get("version", 0)

    def bulk_insert(self, key: str, records: list[dict[str, Any]]) -> int:
        """批量插入记录，返回插入数量。"""
        count = 0
        for record in records:
            self.insert(key, record)
            count += 1
        return count

    def truncate(self, key: str) -> None:
        """清空分区数据。"""
        with self._lock:
            path = self._file_path(key)
            if path.exists():
                path.unlink()

    def list_keys(self) -> list[str]:
        """列出所有分区键。"""
        keys: list[str] = []
        for root, dirs, files in os.walk(self._base_dir):
            for f in files:
                if f.endswith(".json") and not f.endswith(".tmp"):
                    keys.append(f.replace(".json", ""))
        return sorted(keys)

    def stats(self) -> dict[str, Any]:
        """获取存储层统计信息。"""
        keys = self.list_keys()
        total_records = 0
        per_key = {}
        for key in keys:
            count = len(self.get_all(key))
            per_key[key] = count
            total_records += count
        return {
            "total_keys": len(keys),
            "total_records": total_records,
            "per_key": per_key,
            "base_dir": str(self._base_dir),
        }


# 全局单例
json_store = JsonStore()