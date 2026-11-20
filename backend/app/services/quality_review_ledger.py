"""质量复核台账领域服务：归档告警对应的质量检查结论。

集成监控每发布一条质量阻断告警，就把该告警所依据的已确认检查凭证
同步到复核台账，形成只追加（append-only）的复核记录。值班员可据此
核对告警引用的检查编号、结论、阻断率分母与凭证指纹。

台账使用 json_store 持久化，服务重启后记录仍然可查；写入按
fingerprint 幂等，重复同步同一检查不会产生多份台账记录。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.persistence import json_store
from app.services.base import BaseModuleService

# 复核台账独立分区键（不占用前端业务模块位，不出现在资源路由中）
LEDGER_KEY = "quality_review_ledger"


class QualityReviewLedgerService(BaseModuleService):
    MODULE = LEDGER_KEY
    ENTITY = "质量复核记录"
    OPERATION_TERM = "复核"

    def __init__(self) -> None:
        super().__init__()

    def sync_alert(self, alert: dict[str, Any], voucher: dict[str, Any]) -> dict[str, Any]:
        """将告警及其依据的检查凭证同步到复核台账（幂等）。

        同一条告警（按 fingerprint 判定）重复同步时直接返回既有台账记录，
        保证一次阻断告警在台账中只有一份有效复核记录。
        """
        fingerprint = alert.get("fingerprint") or self.build_fingerprint(
            alert.get("type", ""), str(alert.get("check_id", "")),
            str(alert.get("cycle_id", "")),
        )
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "台账编号": f"REVIEW-{voucher.get('检查编号', alert.get('check_id', ''))}",
            "监控周期": alert.get("cycle_id", voucher.get("cycle_id", "")),
            "告警类型": alert.get("type", ""),
            "告警级别": alert.get("level", ""),
            "检查编号": voucher.get("检查编号", ""),
            "检查ID": voucher.get("id", alert.get("check_id")),
            "检查结论": voucher.get("outcome", ""),
            "阻断": bool(voucher.get("blocked", False)),
            "规则命中数": voucher.get("failed", 0),
            "检查项总数": voucher.get("checks", 0),
            "凭证指纹": voucher.get("credential_fingerprint", ""),
            "规则摘要": voucher.get("rule_digest", ""),
            "数据来源": voucher.get("source_module", ""),
            "确认时间": voucher.get("confirmed_at", ""),
            "发布时间": alert.get("published_at", now),
            "复核状态": "待复核",
            "fingerprint": fingerprint,
            "status": "待复核",
            "pending": True,
            "abnormal": True,
            "synced_at": now,
        }
        saved, inserted = json_store.insert_if_absent(
            LEDGER_KEY,
            predicate=lambda r: r.get("fingerprint") == fingerprint,
            record=entry,
        )
        if not inserted:
            saved["_duplicate_sync"] = True
        return saved

    def list_entries_for_cycle(self, cycle_id: str | None = None) -> list[dict[str, Any]]:
        """查询复核台账，可按监控周期过滤。"""
        rows = json_store.get_all(LEDGER_KEY)
        if cycle_id:
            rows = [r for r in rows if str(r.get("监控周期", "")) == str(cycle_id)]
        return sorted(rows, key=lambda r: r.get("synced_at", ""), reverse=True)

    def get_by_check_id(self, check_id: int) -> dict[str, Any] | None:
        """按检查ID定位对应的复核记录。"""
        return json_store.find_one(
            LEDGER_KEY, lambda r: r.get("检查ID") == check_id
        )

    @staticmethod
    def build_fingerprint(alert_type: str, check_id: str, cycle_id: str) -> str:
        import hashlib
        raw = f"{alert_type}|{check_id}|{cycle_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def ledger_stats(self) -> dict[str, Any]:
        """台账统计。"""
        rows = json_store.get_all(LEDGER_KEY)
        return {
            "total": len(rows),
            "pending_review": sum(1 for r in rows if r.get("复核状态") == "待复核"),
            "blocking_reviews": sum(1 for r in rows if r.get("阻断")),
        }
